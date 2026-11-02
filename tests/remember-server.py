import hashlib, json, tempfile, threading, urllib.request, urllib.error, time
from pathlib import Path
from unittest.mock import patch
from cloudserver.store import CloudStore, V2_TABLES
from cloudserver.handler import CloudHandler
from vaultserver.server import VaultHTTPServer
from vaultserver.security import new_password
from vaultserver.store import now, canonical

checks = []
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    store = CloudStore(root / "run1", root / "persistent")
    salt, hashed = new_password("a" * 64)
    store.execute(
        "INSERT INTO users VALUES(?,?,?,?,?,?,?,?)",
        ("u_test", "user@example.test", "Test", salt, hashed, "{}", "{}", now()),
    )
    servers = []

    def serve(db):
        server = VaultHTTPServer(("127.0.0.1", 0), db, root, behind_proxy=True)
        server.RequestHandlerClass = CloudHandler
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return "http://127.0.0.1:" + str(server.server_port)

    base = serve(store)

    def req(path, body=None, token="", expected=200):
        headers = {"X-Forwarded-Proto": "https", "Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request(
            base + path,
            headers=headers,
            data=None if body is None else json.dumps(body).encode(),
        )
        try:
            response = urllib.request.urlopen(request, timeout=10)
        except urllib.error.HTTPError as e:
            response = e
        assert response.code == expected, (path, response.code)
        return json.loads(response.read())

    login = {"email": "user@example.test", "authProof": "a" * 64}
    remembered = req("/api/login", {**login, "remember": True})
    normal = req("/api/login", login)
    assert (
        remembered["remembered"]
        and 6 * 86400000 < remembered["expiresAt"] - now() <= 7 * 86400000
    )
    assert not normal["remembered"]
    row = store.one("SELECT * FROM remembered_sessions")
    assert row["token_hash"] == hashlib.sha256(remembered["token"].encode()).hexdigest()
    checks.append(
        "Explicit opt-in creates bounded seven-day hashed session; ordinary login does not"
    )
    req("/api/login", {**login, "remember": "true"}, expected=400)
    checks.append("Invalid remember flag is rejected")
    restarted = CloudStore(root / "run2", root / "persistent")
    base = serve(restarted)
    req("/api/bootstrap", token=remembered["token"])
    req("/api/bootstrap", token=normal["token"], expected=401)
    checks.append(
        "Remembered session survives fresh runtime; ordinary session does not"
    )
    with patch.object(restarted, "snapshot", side_effect=OSError("unavailable")):
        req("/api/bootstrap", token=remembered["token"])
    checks.append("Resume performs no durable remote write")
    req("/api/logout", {}, remembered["token"])
    req("/api/bootstrap", token=remembered["token"], expected=401)
    after = CloudStore(root / "run3", root / "persistent")
    base = serve(after)
    req("/api/bootstrap", token=remembered["token"], expected=401)
    checks.append("Logout revocation remains effective across restart")
    exp = req("/api/login", {**login, "remember": True})
    h = hashlib.sha256(exp["token"].encode()).hexdigest()
    with after.atomic():
        after.execute(
            "UPDATE remembered_sessions SET expires=? WHERE token_hash=?",
            (now() - 1, h),
        )
        after.execute("DELETE FROM sessions WHERE token_hash=?", (h,))
    req("/api/bootstrap", token=exp["token"], expected=401)
    checks.append("Expired remembered session fails closed")
    disabled = req("/api/login", {**login, "remember": True})
    after.execute("UPDATE accounts SET enabled=0 WHERE user_id='u_test'")
    req("/api/bootstrap", token=disabled["token"], expected=403)
    checks.append("Disabled account cannot resume")
    after.execute("UPDATE accounts SET enabled=1 WHERE user_id='u_test'")
    count = after.one("SELECT COUNT(*) n FROM remembered_sessions")["n"]
    with patch.object(after, "snapshot", side_effect=OSError("unavailable")):
        req("/api/login", {**login, "remember": True}, expected=503)
    assert after.one("SELECT COUNT(*) n FROM remembered_sessions")["n"] == count
    checks.append("Failed durable login rolls back remembered credential")
    payload = {
        "version": 2,
        "created": now(),
        "tables": {
            t: [dict(r) for r in after.all("SELECT * FROM " + t)] for t in V2_TABLES
        },
    }
    raw = canonical(payload)
    p = after.snapshots / (
        f"state-{time.time_ns() + 1000000000:020d}-v2-"
        + hashlib.sha256(raw).hexdigest()
        + ".json"
    )
    p.write_bytes(raw)
    migrated = CloudStore(root / "run4", root / "persistent")
    assert migrated.user("u_test")
    assert migrated.one("SELECT COUNT(*) n FROM remembered_sessions")["n"] == 0
    checks.append("Version two snapshot migrates without accounts or receipt loss")
    for server in servers:
        server.shutdown()
        server.server_close()
Path(".test-results").mkdir(exist_ok=True, parents=True)
Path(".test-results/remember-server.json").write_text(
    json.dumps({"passed": len(checks), "checks": checks}, indent=2), encoding="utf-8"
)
print(json.dumps({"passed": len(checks)}))
