"""Exercise crash recovery, snapshot corruption fallback, rollback and transient data."""

import json
import tempfile
import time
from pathlib import Path
from unittest.mock import patch
from cloudserver.store import CloudStore

checks = []
with tempfile.TemporaryDirectory() as directory:
    base = Path(directory)
    store = CloudStore(base / "run1", base / "bucket")
    store.execute(
        "INSERT INTO users VALUES(?,?,?,?,?,?,?,?)",
        ("u_test", "user@example.test", "Test", "salt", "opaque-hash", "{}", "{}", 1),
    )
    store.execute("INSERT INTO accounts VALUES(?,'admin',1,?)", ("u_test", 104857600))
    store.execute(
        "INSERT INTO sessions VALUES(?,?,?,?)",
        ("temporary", "u_test", 9999999999999, 1),
    )
    payload = b"opaque encrypted bytes"
    store.chunk_path("f_test", 0).write_bytes(payload)
    fresh = CloudStore(base / "run2", base / "bucket")
    assert fresh.user("u_test")["name"] == "Test"
    assert fresh.settings("u_test")["role"] == "admin"
    assert fresh.chunk_path("f_test", 0).read_bytes() == payload
    checks.append(
        "New local runtime restores users, admin role and persistent ciphertext"
    )
    assert fresh.one("SELECT COUNT(*) n FROM sessions")["n"] == 0
    checks.append("Bearer sessions do not survive restart")
    with patch.object(
        fresh, "snapshot", side_effect=OSError("simulated bucket unavailable")
    ):
        try:
            fresh.execute("UPDATE users SET name='Not saved' WHERE id='u_test'")
        except OSError:
            pass
        else:
            raise AssertionError("write failure ignored")
    assert fresh.user("u_test")["name"] == "Test"
    checks.append("Unavailable bucket rolls back metadata changes before success")
    bad = fresh.snapshots / (
        "state-"
        + str(time.time_ns() + 1000000000).zfill(20)
        + "-bad-"
        + "0" * 64
        + ".json"
    )
    bad.write_text("{truncated")
    recovered = CloudStore(base / "run3", base / "bucket")
    assert recovered.user("u_test")["name"] == "Test"
    checks.append("Corrupt newest snapshot falls back to an older verified snapshot")
    for path in recovered.snapshots.glob("*.json"):
        path.write_text("invalid")
    try:
        CloudStore(base / "run4", base / "bucket")
    except RuntimeError:
        pass
    else:
        raise AssertionError("corrupt store opened as empty")
    checks.append(
        "All-corrupt persistence fails closed instead of initializing an empty vault"
    )
Path(".test-results/cloud-persistence-results.json").write_text(
    json.dumps({"passed": len(checks), "checks": checks}, indent=2), encoding="utf8"
)
print(json.dumps({"passed": len(checks)}))
