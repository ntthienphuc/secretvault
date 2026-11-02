"""Liveness stays responsive during durable writes; auth changes commit atomically."""

import hashlib
import json
import os
import tempfile
import threading
import time
import urllib.request
from pathlib import Path
from unittest.mock import patch

from cloudserver.handler import CloudHandler
from cloudserver.store import CloudStore
from vaultserver.server import VaultHTTPServer
from vaultserver.store import now

checks = []
with tempfile.TemporaryDirectory() as p:
    root = Path(p)
    store = CloudStore(root / "runtime", root / "bucket")
    store.execute(
        "INSERT INTO users VALUES(?,?,?,?,?,?,?,?)",
        ("u_test", "user@example.test", "Test", "salt", "opaque", "{}", "{}", 1),
    )
    store.execute("INSERT INTO accounts VALUES(?,'user',1,?)", ("u_test", 104857600))
    store.execute(
        "INSERT INTO sessions VALUES(?,?,?,?)",
        (hashlib.sha256(b"qa-session").hexdigest(), "u_test", now() + 60000, now()),
    )
    try:
        with store.atomic():
            store.execute("UPDATE users SET name='Uncommitted' WHERE id='u_test'")
            store.execute("UPDATE accounts SET quota=1 WHERE user_id='u_test'")
            raise ValueError("abort whole operation")
    except ValueError:
        pass
    assert (
        store.user("u_test")["name"] == "Test"
        and store.settings("u_test")["quota"] == 104857600
    )
    checks.append("Multi-table operations roll back together")
    with patch.object(store, "snapshot", wraps=store.snapshot) as snapshot:
        with store.atomic():
            store.execute("UPDATE users SET name='Saved Test' WHERE id='u_test'")
            store.execute("UPDATE accounts SET quota=2000000 WHERE user_id='u_test'")
        assert snapshot.call_count == 1
    checks.append("A successful operation persists one combined snapshot")

    server = VaultHTTPServer(("127.0.0.1", 0), store, root, behind_proxy=True)
    server.RequestHandlerClass = CloudHandler
    serving = threading.Thread(target=server.serve_forever, daemon=True)
    serving.start()
    base = "http://127.0.0.1:" + str(server.server_port)

    def request(path, body=None, auth=False):
        headers = {"X-Forwarded-Proto": "https"}
        if auth:
            headers["Authorization"] = "Bearer qa-session"
        if body is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(
            base + path,
            data=json.dumps(body).encode() if body is not None else None,
            headers=headers,
        )
        try:
            response = urllib.request.urlopen(req, timeout=2)
        except urllib.error.HTTPError as error:
            response = error
        return response.code, json.loads(response.read())

    entered = threading.Event()
    release = threading.Event()
    original = store.snapshot

    def slow_snapshot(db):
        entered.set()
        assert release.wait(4)
        return original(db)

    def writer():
        with store.atomic():
            store.execute("UPDATE users SET name='Slow write' WHERE id='u_test'")

    with patch.object(store, "snapshot", side_effect=slow_snapshot):
        writing = threading.Thread(target=writer)
        writing.start()
        assert entered.wait(2)
        started = time.monotonic()
        status, health = request("/api/health")
        duration = time.monotonic() - started
        release.set()
        writing.join(3)
    assert status == 200 and health["ok"] and duration < 1
    checks.append(
        "Health probe remains responsive while storage snapshot holds the transaction lock"
    )

    os.environ["SV_ADMIN_CLAIM_HASH"] = hashlib.sha256(b"qa-owner-code").hexdigest()
    with patch.object(
        store, "snapshot", side_effect=OSError("simulated remote storage failure")
    ):
        status, body = request("/api/admin/claim", {"code": "qa-owner-code"}, True)
    assert (
        status == 503
        and store.settings("u_test")["role"] == "user"
        and store.setup_required
    )
    checks.append(
        "Failed durability returns 503 without granting admin or reporting success"
    )
    status, body = request("/api/admin/claim", {"code": "qa-owner-code"}, True)
    assert (
        status == 200
        and store.settings("u_test")["role"] == "admin"
        and not request("/api/health")[1]["setupRequired"]
    )
    checks.append(
        "Successful owner activation updates persisted role and cached setup status"
    )
    server.shutdown()
    server.server_close()
Path(".test-results/cloud-availability-results.json").write_text(
    json.dumps({"passed": len(checks), "checks": checks}, indent=2), encoding="utf8"
)
print(json.dumps({"passed": len(checks)}))
