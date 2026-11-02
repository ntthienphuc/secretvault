"""Authenticated HTTP API. Private cryptographic operations run in the client."""

from __future__ import annotations

import json
import ipaddress
import os
import socket
import mimetypes
import re
import secrets
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from . import VERSION
from .security import (
    ApiError,
    CHUNK_SIZE,
    MAX_FILE_SIZE,
    check_password,
    new_password,
    require,
    unb64,
    valid_id,
    validate_bundle,
    validate_public,
    verify,
)
from .store import Store, canonical, digest, now, uid


class VaultHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = os.name != "nt"

    def server_bind(self):
        if os.name == "nt":
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def __init__(
        self,
        address,
        store: Store,
        public_dir,
        secure=False,
        behind_proxy=False,
        allowed_networks=(),
        lan_host_id=None,
    ):
        super().__init__(address, Handler)
        self.store = store
        self.public_dir = public_dir.resolve()
        self.secure = secure
        self.behind_proxy = behind_proxy
        self.allowed_networks = tuple(
            ipaddress.ip_network(value) for value in allowed_networks
        )
        self.lan_host_id = lan_host_id
        self.auth_attempts = {}
        self.attempt_lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    server_version = "SecretVault/" + VERSION

    def log_message(self, format_string, *args):
        if "bootstrap" not in self.path and "health" not in self.path:
            print(self.log_date_time_string(), format_string % args, flush=True)

    @property
    def store(self):
        return self.server.store

    def headers_common(self, content_type):
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        )

    def send_bytes(self, data, content_type="application/octet-stream", status=200):
        self.send_response(status)
        self.headers_common(content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def json(self, data, status=200):
        self.send_bytes(
            json.dumps(data, ensure_ascii=False).encode("utf-8"),
            "application/json; charset=utf-8",
            status,
        )

    def read_bytes(self, limit=2 * 1024 * 1024):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ApiError("Độ dài request không hợp lệ")
        require(0 <= length <= limit, "Request vượt giới hạn", 413)
        return self.rfile.read(length)

    def read_json(self):
        require(
            self.headers.get("Content-Type", "").startswith("application/json"),
            "Yêu cầu application/json",
            415,
        )
        value = json.loads(self.read_bytes().decode("utf-8"))
        require(isinstance(value, dict), "JSON phải là object")
        return value

    def check_origin(self):
        if self.server.allowed_networks:
            peer = ipaddress.ip_address(self.client_address[0])
            require(
                any(peer in network for network in self.server.allowed_networks),
                "Host nay chi cho phep ket noi tu mang LAN da chon",
                403,
            )
        # Reject cross-site browser requests and DNS rebinding on local instances.
        host = self.headers.get("Host", "")
        origin = self.headers.get("Origin")
        if origin:
            require(urlparse(origin).netloc == host, "Origin bị từ chối", 403)
        if self.path.startswith("/api/"):
            require(
                self.headers.get("Sec-Fetch-Site") != "cross-site",
                "Cross-site request bị từ chối",
                403,
            )
        if not self.server.secure and not self.server.behind_proxy:
            hostname = host.rsplit(":", 1)[0]
            require(
                hostname in ("localhost", "127.0.0.1", "[::1]"),
                "Dùng địa chỉ localhost",
                403,
            )
        if self.server.behind_proxy:
            require(
                self.client_address[0] in ("127.0.0.1", "::1"),
                "Proxy phải ở loopback",
                403,
            )
            require(
                self.headers.get("X-Forwarded-Proto") == "https",
                "Host từ xa cần HTTPS",
                403,
            )

    def current_user(self):
        auth = self.headers.get("Authorization", "")
        require(auth.startswith("Bearer "), "Vui lòng đăng nhập", 401)
        session = self.store.one(
            "SELECT * FROM sessions WHERE token_hash=? AND expires>?",
            (digest(auth[7:].encode()), now()),
        )
        require(session is not None, "Phiên đăng nhập đã hết hạn", 401)
        self.store.execute(
            "UPDATE sessions SET last_seen=? WHERE token_hash=?",
            (now(), session["token_hash"]),
        )
        return self.store.user(session["user_id"])

    def do_GET(self):
        self.dispatch("GET")

    def do_POST(self):
        self.dispatch("POST")

    def do_DELETE(self):
        self.dispatch("DELETE")

    def dispatch(self, method):
        try:
            self.check_origin()
            parsed = urlparse(self.path)
            path = parsed.path
            query = parse_qs(parsed.query)
            if path == "/api/health" and method == "GET":
                health = {
                    "ok": True,
                    "app": "SecretVault",
                    "version": VERSION,
                    "maxFileSize": MAX_FILE_SIZE,
                    "chunkSize": CHUNK_SIZE,
                }
                if self.server.lan_host_id:
                    health["lanHostId"] = self.server.lan_host_id
                self.json(health)
                return
            if path in ("/api/register", "/api/login") and method == "POST":
                self.authenticate(path, self.read_json())
                return
            if not path.startswith("/api/"):
                require(method == "GET", "Method không hợp lệ", 405)
                self.static(path)
                return
            user = self.current_user()
            if path == "/api/logout" and method == "POST":
                self.store.execute(
                    "DELETE FROM sessions WHERE token_hash=?",
                    (digest(self.headers["Authorization"][7:].encode()),),
                )
                self.json({"ok": True})
            elif path == "/api/bootstrap" and method == "GET":
                self.bootstrap(user)
            elif path == "/api/directory" and method == "GET":
                peer = self.store.one(
                    "SELECT * FROM users WHERE email=?",
                    (query.get("email", [""])[0].strip().lower(),),
                )
                require(peer is not None, "Không tìm thấy tài khoản", 404)
                self.json(self.store.public_user(peer))
            elif path == "/api/contacts" and method == "POST":
                self.pin_contact(user, self.read_json())
            elif path == "/api/files" and method == "POST":
                self.begin_file(user, self.read_json())
            elif re.fullmatch(r"/api/files/f_[0-9a-f]{32}/chunks/\d+", path):
                parts = path.split("/")
                self.file_chunk(user, parts[3], int(parts[5]), method)
            elif (
                re.fullmatch(r"/api/files/f_[0-9a-f]{32}/commit", path)
                and method == "POST"
            ):
                self.commit_file(user, path.split("/")[3], self.read_json())
            elif (
                re.fullmatch(r"/api/files/f_[0-9a-f]{32}", path) and method == "DELETE"
            ):
                row = self.owner_file(user, path.split("/")[3])
                self.store.execute(
                    "UPDATE files SET deleted=1 WHERE id=?", (row["id"],)
                )
                self.store.activity(user["id"], "Đã chuyển tệp vào thùng rác")
                self.json({"ok": True})
            elif path == "/api/shares" and method == "POST":
                self.share(user, self.read_json())
            elif (
                re.fullmatch(r"/api/shares/s_[0-9a-f]{32}", path) and method == "DELETE"
            ):
                row = self.store.one(
                    "SELECT * FROM shares WHERE id=? AND sender_id=?",
                    (path.split("/")[3], user["id"]),
                )
                require(row is not None, "Không có quyền thu hồi", 403)
                self.store.execute(
                    "UPDATE shares SET revoked=1 WHERE id=?", (row["id"],)
                )
                self.json({"ok": True})
            elif path == "/api/live" and method == "POST":
                self.live_offer(user, self.read_json())
            elif (
                re.fullmatch(
                    r"/api/live/l_[0-9a-f]{32}/(accept|chunk|finish|ack|reject)", path
                )
                and method == "POST"
            ):
                self.live_update(
                    user, path.split("/")[3], path.split("/")[4], self.read_json()
                )
            elif (
                re.fullmatch(r"/api/live/l_[0-9a-f]{32}/chunks/\d+", path)
                and method == "GET"
            ):
                row = self.live_row(user, path.split("/")[3])
                require(
                    row["recipient_id"] == user["id"]
                    and row["state"] in ("sent", "complete"),
                    "Payload chưa sẵn sàng",
                    403,
                )
                chunk = self.store.one(
                    "SELECT payload FROM live_chunks WHERE live_id=? AND idx=?",
                    (row["id"], int(path.split("/")[5])),
                )
                require(chunk is not None, "Không tìm thấy chunk", 404)
                self.json(json.loads(chunk["payload"]))
            else:
                raise ApiError("Không tìm thấy API", 404)
        except ApiError as error:
            self.json({"error": str(error)}, error.status)
        except (ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
            self.json(
                {"error": "Dữ liệu yêu cầu không hợp lệ: " + str(error)[:160]}, 400
            )
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass
        except Exception:
            import traceback

            traceback.print_exc()
            self.json({"error": "Máy chủ gặp lỗi; kiểm tra nhật ký"}, 500)

    def static(self, path):
        filename = unquote(path).lstrip("/") or "index.html"
        candidate = (self.server.public_dir / filename).resolve()
        require(
            candidate.is_relative_to(self.server.public_dir) and candidate.is_file(),
            "Không tìm thấy tài nguyên",
            404,
        )
        mime = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        if candidate.suffix == ".js":
            mime = "text/javascript; charset=utf-8"
        self.send_bytes(candidate.read_bytes(), mime)

    def throttle(self, email):
        key = (self.client_address[0], email)
        with self.server.attempt_lock:
            attempts = self.server.auth_attempts.setdefault(key, [])
            attempts[:] = [
                timestamp for timestamp in attempts if timestamp > time.time() - 300
            ]
            require(
                len(attempts) < 12, "Quá nhiều lần thử. Chờ 5 phút rồi thử lại", 429
            )
            attempts.append(time.time())

    def authenticate(self, path, body):
        email = str(body.get("email", "")).strip().lower()
        credential = str(body.get("authProof", ""))
        require(
            re.fullmatch(r"[^\s@]{1,80}@[^\s@]{1,120}\.[^\s@]{1,30}", email),
            "Email không hợp lệ",
        )
        require(
            bool(re.fullmatch(r"[0-9a-f]{64}", credential)),
            "Thiếu thông tin xác thực dẫn xuất hợp lệ",
        )
        self.throttle(email)
        if path == "/api/register":
            name = str(body.get("name", "")).strip()
            require(1 <= len(name) <= 80, "Tên cần từ 1 đến 80 ký tự")
            public = body.get("public")
            bundle = body.get("bundle")
            validate_public(public)
            validate_bundle(bundle)
            proof = {"purpose": "register-v2", "email": email, "public": public}
            verify(public, proof, body.get("proof", ""))
            salt, hashed = new_password(credential)
            try:
                self.store.execute(
                    "INSERT INTO users VALUES(?,?,?,?,?,?,?,?)",
                    (
                        uid("u"),
                        email,
                        name,
                        salt,
                        hashed,
                        canonical(public).decode(),
                        canonical(bundle).decode(),
                        now(),
                    ),
                )
            except sqlite3.IntegrityError:
                raise ApiError("Email này đã có tài khoản", 409)
        row = self.store.one("SELECT * FROM users WHERE email=?", (email,))
        require(
            row is not None and check_password(credential, row),
            "Email hoặc mật khẩu không đúng",
            401,
        )
        token = secrets.token_urlsafe(40)
        self.store.execute(
            "INSERT INTO sessions VALUES(?,?,?,?)",
            (digest(token.encode()), row["id"], now() + 12 * 3600000, now()),
        )
        self.json(
            {
                "token": token,
                "user": self.store.public_user(row),
                "bundle": json.loads(row["bundle_json"]),
            }
        )

    def bootstrap(self, user):
        self.store.prune()
        files = self.store.all(
            """
            SELECT DISTINCT f.* FROM files f LEFT JOIN shares s ON s.file_id=f.id AND s.revoked=0
            WHERE f.ready=1 AND f.deleted=0 AND (f.owner_id=? OR s.recipient_id=?) ORDER BY f.created DESC
        """,
            (user["id"], user["id"]),
        )
        contacts = self.store.all(
            "SELECT * FROM contacts WHERE owner_id=?", (user["id"],)
        )
        shares = self.store.all(
            "SELECT * FROM shares WHERE sender_id=? OR recipient_id=? ORDER BY created DESC",
            (user["id"], user["id"]),
        )
        live = self.store.all(
            "SELECT * FROM live WHERE (sender_id=? OR recipient_id=?) AND created>? ORDER BY created DESC LIMIT 20",
            (user["id"], user["id"], now() - 86400000),
        )
        peer_ids = {user["id"]}
        peer_ids.update(row["owner_id"] for row in files)
        peer_ids.update(row["peer_id"] for row in contacts)
        for row in shares:
            peer_ids.update((row["sender_id"], row["recipient_id"]))
        for row in live:
            peer_ids.update((row["sender_id"], row["recipient_id"]))
        users = [
            self.store.public_user(self.store.user(peer_id))
            for peer_id in sorted(peer_ids)
        ]
        sessions = []
        for row in live:
            sessions.append(
                {
                    "id": row["id"],
                    "senderId": row["sender_id"],
                    "recipientId": row["recipient_id"],
                    "offer": json.loads(row["offer"]),
                    "offerSignature": row["offer_sig"],
                    "acceptance": json.loads(row["acceptance"])
                    if row["acceptance"]
                    else None,
                    "acceptSignature": row["accept_sig"],
                    "state": row["state"],
                    "expires": row["expires"],
                    "completion": json.loads(row["completion"])
                    if row["completion"]
                    else None,
                }
            )
        activity = [
            dict(row)
            for row in self.store.all(
                "SELECT * FROM activity WHERE user_id=? ORDER BY created DESC LIMIT 12",
                (user["id"],),
            )
        ]
        self.json(
            {
                "user": self.store.public_user(user),
                "users": users,
                "files": [self.store.file_json(row, user["id"]) for row in files],
                "shares": [self.store.share_json(row) for row in shares],
                "contacts": [dict(row) for row in contacts],
                "live": sessions,
                "activity": activity,
            }
        )

    def pin_contact(self, user, body):
        peer = self.store.user(body.get("peerId", ""))
        require(
            peer is not None and peer["id"] != user["id"], "Người nhận không hợp lệ"
        )
        public = json.loads(peer["public_json"])
        require(
            body.get("fingerprint") == public["fingerprint"],
            "Fingerprint đã thay đổi. Xác minh lại",
            409,
        )
        existing = self.store.one(
            "SELECT * FROM contacts WHERE owner_id=? AND peer_id=?",
            (user["id"], peer["id"]),
        )
        require(
            not existing or existing["fingerprint"] == body["fingerprint"],
            "Khóa đã ghim thay đổi; không tự ghi đè",
            409,
        )
        self.store.execute(
            "INSERT OR IGNORE INTO contacts VALUES(?,?,?,?)",
            (user["id"], peer["id"], body["fingerprint"], now()),
        )
        self.json({"ok": True})

    def owner_file(self, user, file_id):
        row = self.store.file(file_id)
        require(
            row is not None and row["owner_id"] == user["id"],
            "Không có quyền quản lý tệp",
            403,
        )
        return row

    def begin_file(self, user, body):
        file_id = body.get("id")
        require(valid_id(file_id) and file_id.startswith("f_"), "File ID không hợp lệ")
        require(
            not self.store.one("SELECT id FROM files WHERE id=?", (file_id,)),
            "File ID đã tồn tại",
            409,
        )
        count = self.store.one(
            "SELECT COUNT(*) n FROM files WHERE owner_id=? AND deleted=0", (user["id"],)
        )["n"]
        require(count < 1000, "Đã đạt giới hạn 1.000 tệp")
        self.store.execute(
            "INSERT INTO files VALUES(?,?,?,?,?,?,0,0,?)",
            (file_id, user["id"], "{}", "", "{}", "", now()),
        )
        self.json({"id": file_id}, 201)

    def file_chunk(self, user, file_id, index, method):
        require(0 <= index <= MAX_FILE_SIZE // CHUNK_SIZE, "Chỉ số chunk vượt giới hạn")
        if method == "POST":
            row = self.owner_file(user, file_id)
            require(not row["ready"], "Tệp đã hoàn tất, không được sửa chunk", 409)
            data = self.read_bytes(CHUNK_SIZE + 16)
            require(16 <= len(data) <= CHUNK_SIZE + 16, "Chunk AES-GCM không hợp lệ")
            self.store.chunk_path(file_id, index).write_bytes(data)
            self.store.execute(
                "INSERT OR REPLACE INTO chunks VALUES(?,?,?,?)",
                (file_id, index, digest(data), len(data)),
            )
            self.json({"hash": digest(data)})
        elif method == "GET":
            require(
                self.store.can_read(file_id, user["id"]), "Không có quyền tải tệp", 403
            )
            chunk = self.store.one(
                "SELECT * FROM chunks WHERE file_id=? AND idx=?", (file_id, index)
            )
            require(chunk is not None, "Chunk không tồn tại", 404)
            self.send_bytes(self.store.chunk_path(file_id, index).read_bytes())
        else:
            raise ApiError("Method không hợp lệ", 405)

    def commit_file(self, user, file_id, body):
        row = self.owner_file(user, file_id)
        require(not row["ready"], "Tệp đã được hoàn tất", 409)
        manifest = body["manifest"]
        require(
            manifest["id"] == file_id and manifest["ownerId"] == user["id"],
            "Sai chủ tệp",
        )
        require(
            manifest.get("version") == 2
            and manifest.get("algorithm") == "AES-256-GCM-chunked",
            "Sai giao thức",
        )
        size = manifest["size"]
        require(type(size) is int and 0 <= size <= MAX_FILE_SIZE, "Tệp tối đa 256 MiB")
        require(
            1 <= len(manifest["name"]) <= 240 and len(manifest.get("mime", "")) <= 160,
            "Tên hoặc MIME không hợp lệ",
        )
        expected_count = max(1, (size + CHUNK_SIZE - 1) // CHUNK_SIZE)
        chunks = manifest["chunks"]
        require(len(chunks) == expected_count, "Thiếu chunk")
        stored = self.store.all(
            "SELECT * FROM chunks WHERE file_id=? ORDER BY idx", (file_id,)
        )
        require(len(stored) == expected_count, "Chưa tải lên đủ chunk")
        for index, (meta, actual) in enumerate(zip(chunks, stored)):
            plain_size = min(CHUNK_SIZE, max(0, size - index * CHUNK_SIZE))
            require(
                meta["index"] == index
                and actual["idx"] == index
                and meta["hash"] == actual["hash"],
                "Hash chunk không khớp",
            )
            require(
                meta["plainSize"] == plain_size and actual["size"] == plain_size + 16,
                "Độ dài chunk không khớp",
            )
            require(len(unb64(meta["iv"])) == 12, "IV không hợp lệ")
        require(
            len({meta["iv"] for meta in chunks}) == len(chunks), "IV bị tái sử dụng"
        )
        verify(json.loads(user["public_json"]), manifest, body["signature"])
        require(
            len(unb64(body["ownerWrap"]["data"])) == 48
            and len(unb64(body["ownerWrap"]["iv"])) == 12,
            "Owner key wrap không hợp lệ",
        )
        self.store.execute(
            "UPDATE files SET manifest=?,signature=?,owner_wrap=?,manifest_hash=?,ready=1 WHERE id=?",
            (
                canonical(manifest).decode(),
                body["signature"],
                canonical(body["ownerWrap"]).decode(),
                digest(canonical(manifest)),
                file_id,
            ),
        )
        self.store.activity(user["id"], "Đã mã hóa và lưu " + manifest["name"])
        self.json({"ok": True})

    def share(self, user, body):
        payload = body["payload"]
        row = self.owner_file(user, payload["fileId"])
        require(row["ready"], "Tệp chưa hoàn tất")
        recipient = self.store.user(payload["recipientId"])
        require(
            recipient is not None and recipient["id"] != user["id"], "Sai người nhận"
        )
        contact = self.store.one(
            "SELECT * FROM contacts WHERE owner_id=? AND peer_id=?",
            (user["id"], recipient["id"]),
        )
        require(contact is not None, "Hãy ghim khóa người nhận trước", 403)
        require(
            payload["senderId"] == user["id"]
            and payload["manifestHash"] == row["manifest_hash"]
            and payload["purpose"] == "offline-v2",
            "Sai ngữ cảnh chia sẻ",
        )
        require(
            payload["recipientFingerprint"] == contact["fingerprint"],
            "Fingerprint người nhận không khớp",
        )
        envelope = payload["envelope"]
        require(
            envelope["scheme"] == "ElGamal-Hybrid-HKDF-SHA256"
            and envelope["group"] == "RFC3526-MODP3072",
            "Sai ElGamal envelope",
        )
        require(
            re.fullmatch(r"[a-f0-9]{768}", envelope["c1"])
            and len(unb64(envelope["salt"])) == 32
            and len(unb64(envelope["iv"])) == 12
            and len(unb64(envelope["data"])) == 48,
            "Envelope không hợp lệ",
        )
        verify(json.loads(user["public_json"]), payload, body["signature"])
        share_id = uid("s")
        try:
            self.store.execute(
                "INSERT INTO shares VALUES(?,?,?,?,?,?,0,?)",
                (
                    share_id,
                    row["id"],
                    user["id"],
                    recipient["id"],
                    canonical(payload).decode(),
                    body["signature"],
                    now(),
                ),
            )
        except sqlite3.IntegrityError:
            raise ApiError("Tệp đã được chia sẻ cho tài khoản này", 409)
        self.store.activity(user["id"], "Đã chia sẻ offline cho " + recipient["name"])
        self.store.activity(recipient["id"], "Có tệp offline mới từ " + user["name"])
        self.json({"id": share_id}, 201)

    def live_row(self, user, live_id):
        row = self.store.one("SELECT * FROM live WHERE id=?", (live_id,))
        require(
            row is not None and user["id"] in (row["sender_id"], row["recipient_id"]),
            "Không có quyền với phiên này",
            403,
        )
        require(row["expires"] > now(), "Phiên live đã hết hạn", 410)
        return row

    def live_offer(self, user, body):
        offer = body["payload"]
        require(
            valid_id(offer["id"]) and offer["id"].startswith("l_"), "Sai session ID"
        )
        require(
            offer["senderId"] == user["id"]
            and offer["purpose"] == "live-offer-v2"
            and offer["group"] == "RFC3526-MODP3072",
            "Sai danh tính gửi",
        )
        require(
            now() < offer["expires"] <= now() + 15 * 60000, "Phiên live tối đa 15 phút"
        )
        require(
            0 <= offer["size"] <= MAX_FILE_SIZE and 1 <= len(offer["name"]) <= 240,
            "Tệp live vượt giới hạn",
        )
        require(
            offer["total"] == max(1, (offer["size"] + CHUNK_SIZE - 1) // CHUNK_SIZE),
            "Sai số chunk",
        )
        require(re.fullmatch(r"[a-f0-9]{768}", offer["publicKey"]), "Sai DH public key")
        require(len(unb64(offer["nonce"])) == 32, "Sai nonce")
        peer = self.store.user(offer["recipientId"])
        require(peer is not None and peer["id"] != user["id"], "Sai người nhận")
        contact = self.store.one(
            "SELECT * FROM contacts WHERE owner_id=? AND peer_id=?",
            (user["id"], peer["id"]),
        )
        require(
            contact is not None
            and offer["recipientFingerprint"] == contact["fingerprint"],
            "Hãy ghim khóa người nhận",
            403,
        )
        verify(json.loads(user["public_json"]), offer, body["signature"])
        self.store.execute(
            "INSERT INTO live VALUES(?,?,?,?,?,NULL,NULL,'offered',?,?,NULL)",
            (
                offer["id"],
                user["id"],
                peer["id"],
                canonical(offer).decode(),
                body["signature"],
                now(),
                offer["expires"],
            ),
        )
        self.json({"id": offer["id"]}, 201)

    def live_update(self, user, live_id, action, body):
        row = self.live_row(user, live_id)
        sender = row["sender_id"] == user["id"]
        offer = json.loads(row["offer"])
        if action == "reject":
            require(
                not sender and row["state"] == "offered", "Không thể từ chối phiên", 409
            )
            self.store.execute(
                "UPDATE live SET state='rejected' WHERE id=?", (live_id,)
            )
        elif action == "accept":
            require(
                not sender and row["state"] == "offered",
                "Phiên không còn chờ nhận",
                409,
            )
            value = body["payload"]
            require(
                value["purpose"] == "live-accept-v2"
                and value["id"] == live_id
                and value["offerHash"] == digest(canonical(offer)),
                "Sai transcript DH",
            )
            require(
                value["recipientId"] == user["id"]
                and re.fullmatch(r"[a-f0-9]{768}", value["publicKey"])
                and len(unb64(value["nonce"])) == 32,
                "Sai khóa nhận",
            )
            verify(json.loads(user["public_json"]), value, body["signature"])
            self.store.execute(
                "UPDATE live SET state='accepted',acceptance=?,accept_sig=? WHERE id=?",
                (canonical(value).decode(), body["signature"], live_id),
            )
        elif action == "chunk":
            require(sender and row["state"] == "accepted", "Phiên chưa sẵn sàng", 409)
            index = body["index"]
            require(
                type(index) is int and 0 <= index < offer["total"], "Sai chỉ số chunk"
            )
            raw = unb64(body["data"])
            require(
                len(raw)
                == min(CHUNK_SIZE, max(0, offer["size"] - index * CHUNK_SIZE)) + 16,
                "Sai độ dài live chunk",
            )
            require(
                len(unb64(body["iv"])) == 12 and body["hash"] == digest(raw),
                "Live chunk không hợp lệ",
            )
            existing = self.store.one(
                "SELECT payload FROM live_chunks WHERE live_id=? AND idx=?",
                (live_id, index),
            )
            require(existing is None, "Không cho ghi đè chunk của phiên", 409)
            self.store.execute(
                "INSERT INTO live_chunks VALUES(?,?,?)",
                (live_id, index, canonical(body).decode()),
            )
        elif action == "finish":
            require(
                sender and row["state"] == "accepted", "Không thể hoàn tất phiên", 409
            )
            value = body["payload"]
            acceptance = json.loads(row["acceptance"])
            transcript = digest(canonical({"offer": offer, "acceptance": acceptance}))
            require(
                value["id"] == live_id
                and value["purpose"] == "live-finish-v2"
                and value["transcriptHash"] == transcript,
                "Sai transcript hoàn tất",
            )
            chunks = self.store.all(
                "SELECT payload FROM live_chunks WHERE live_id=? ORDER BY idx",
                (live_id,),
            )
            hashes = [json.loads(chunk["payload"])["hash"] for chunk in chunks]
            require(
                len(hashes) == offer["total"] and hashes == value["hashes"],
                "Chưa có đủ ciphertext",
            )
            verify(json.loads(user["public_json"]), value, body["signature"])
            self.store.execute(
                "UPDATE live SET state='sent',completion=? WHERE id=?",
                (canonical(body).decode(), live_id),
            )
        elif action == "ack":
            require(
                not sender and row["state"] == "sent", "Không thể xác nhận phiên", 409
            )
            self.store.execute(
                "UPDATE live SET state='complete' WHERE id=?", (live_id,)
            )
            self.store.activity(user["id"], "Đã giải mã phiên live " + offer["name"])
        else:
            raise ApiError("Sai thao tác live")
        self.json({"ok": True})
