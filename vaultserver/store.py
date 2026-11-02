"""SQLite metadata and opaque ciphertext storage. No private keys are decrypted here."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path


def now() -> int:
    return int(time.time() * 1000)


def uid(prefix: str) -> str:
    return prefix + "_" + secrets.token_hex(16)


def canonical(value) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class Store:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.blobs = self.root / "ciphertext"
        self.blobs.mkdir(exist_ok=True)
        self.database = self.root / "vault-v2.db"
        self.lock = threading.RLock()
        with self.db() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
                    salt TEXT NOT NULL, password_hash TEXT NOT NULL,
                    public_json TEXT NOT NULL, bundle_json TEXT NOT NULL, created INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id)
                );
                CREATE TABLE IF NOT EXISTS contacts (
                    owner_id TEXT NOT NULL, peer_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
                    created INTEGER NOT NULL, PRIMARY KEY(owner_id, peer_id)
                );
                CREATE TABLE IF NOT EXISTS files (
                    id TEXT PRIMARY KEY, owner_id TEXT NOT NULL,
                    manifest TEXT NOT NULL, signature TEXT NOT NULL, owner_wrap TEXT NOT NULL,
                    manifest_hash TEXT NOT NULL, ready INTEGER NOT NULL DEFAULT 0,
                    deleted INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS chunks (
                    file_id TEXT NOT NULL, idx INTEGER NOT NULL, hash TEXT NOT NULL,
                    size INTEGER NOT NULL, PRIMARY KEY(file_id, idx)
                );
                CREATE TABLE IF NOT EXISTS shares (
                    id TEXT PRIMARY KEY, file_id TEXT NOT NULL, sender_id TEXT NOT NULL,
                    recipient_id TEXT NOT NULL, payload TEXT NOT NULL, signature TEXT NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS active_share ON shares(file_id, recipient_id) WHERE revoked=0;
                CREATE TABLE IF NOT EXISTS live (
                    id TEXT PRIMARY KEY, sender_id TEXT NOT NULL, recipient_id TEXT NOT NULL,
                    offer TEXT NOT NULL, offer_sig TEXT NOT NULL, acceptance TEXT,
                    accept_sig TEXT, state TEXT NOT NULL, created INTEGER NOT NULL,
                    expires INTEGER NOT NULL, completion TEXT
                );
                CREATE TABLE IF NOT EXISTS live_chunks (
                    live_id TEXT NOT NULL, idx INTEGER NOT NULL, payload TEXT NOT NULL,
                    PRIMARY KEY(live_id, idx)
                );
                CREATE TABLE IF NOT EXISTS activity (
                    id TEXT PRIMARY KEY, user_id TEXT NOT NULL, message TEXT NOT NULL,
                    created INTEGER NOT NULL
                );
            """)

    @contextmanager
    def db(self):
        with self.lock:
            connection = sqlite3.connect(self.database, timeout=30)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            try:
                yield connection
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()

    def one(self, sql, parameters=()):
        with self.db() as db:
            return db.execute(sql, parameters).fetchone()

    def all(self, sql, parameters=()):
        with self.db() as db:
            return db.execute(sql, parameters).fetchall()

    def execute(self, sql, parameters=()):
        with self.db() as db:
            db.execute(sql, parameters)

    def activity(self, user_id, message):
        self.execute(
            "INSERT INTO activity VALUES(?,?,?,?)", (uid("a"), user_id, message, now())
        )

    def public_user(self, row):
        public = json.loads(row["public_json"])
        seen = self.one(
            "SELECT MAX(last_seen) AS seen FROM sessions WHERE user_id=? AND expires>?",
            (row["id"], now()),
        )
        return {
            "id": row["id"],
            "email": row["email"],
            "name": row["name"],
            "public": public,
            "online": bool(seen and seen["seen"] and seen["seen"] > now() - 20000),
        }

    def user(self, user_id):
        return self.one("SELECT * FROM users WHERE id=?", (user_id,))

    def file(self, file_id):
        return self.one("SELECT * FROM files WHERE id=? AND deleted=0", (file_id,))

    def can_read(self, file_id, user_id):
        row = self.file(file_id)
        if row is None or not row["ready"]:
            return False
        if row["owner_id"] == user_id:
            return True
        return bool(
            self.one(
                "SELECT id FROM shares WHERE file_id=? AND recipient_id=? AND revoked=0",
                (file_id, user_id),
            )
        )

    def file_json(self, row, user_id):
        output = {
            "id": row["id"],
            "ownerId": row["owner_id"],
            "manifest": json.loads(row["manifest"]),
            "signature": row["signature"],
            "manifestHash": row["manifest_hash"],
        }
        if row["owner_id"] == user_id:
            output["ownerWrap"] = json.loads(row["owner_wrap"])
        else:
            share = self.one(
                "SELECT * FROM shares WHERE file_id=? AND recipient_id=? AND revoked=0",
                (row["id"], user_id),
            )
            output["share"] = self.share_json(share)
        return output

    @staticmethod
    def share_json(row):
        return {
            "id": row["id"],
            "fileId": row["file_id"],
            "senderId": row["sender_id"],
            "recipientId": row["recipient_id"],
            "payload": json.loads(row["payload"]),
            "signature": row["signature"],
            "revoked": bool(row["revoked"]),
            "created": row["created"],
        }

    def chunk_path(self, file_id, index):
        # These values are validated route IDs and integers, never arbitrary paths.
        return self.blobs / (file_id + "-" + str(index) + ".bin")

    def prune(self):
        timestamp = now()
        with self.db() as db:
            db.execute("DELETE FROM sessions WHERE expires<?", (timestamp,))
            db.execute(
                "UPDATE live SET state='expired' WHERE expires<? AND state NOT IN ('complete','rejected','expired')",
                (timestamp,),
            )
            db.execute(
                "DELETE FROM live_chunks WHERE live_id IN (SELECT id FROM live WHERE expires<?)",
                (timestamp,),
            )

    def backup(self, destination: Path):
        import zipfile
        import tempfile

        with tempfile.TemporaryDirectory() as temporary:
            snapshot = Path(temporary) / "vault-v2.db"
            with self.db() as source:
                target = sqlite3.connect(snapshot)
                source.backup(target)
                target.close()
            with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.write(snapshot, "vault-v2.db")
                for blob in self.blobs.glob("*.bin"):
                    archive.write(blob, "ciphertext/" + blob.name)
