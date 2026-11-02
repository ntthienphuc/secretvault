"""Backward migration and deferred blob deletion use isolated synthetic storage."""

import hashlib
import json
import tempfile
import time
from pathlib import Path
from unittest.mock import patch
from cloudserver.store import CloudStore, LEGACY_TABLES
from vaultserver.store import canonical

checks = []
with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    original = CloudStore(root / "runtime", root / "persist")
    original.execute(
        "INSERT INTO users VALUES(?,?,?,?,?,?,?,?)",
        (
            "u_test",
            "migration@example.test",
            "Migration",
            "salt",
            "opaque",
            "{}",
            "{}",
            1,
        ),
    )
    payload = {
        "version": 1,
        "created": 1,
        "tables": {
            table: [dict(r) for r in original.all("SELECT * FROM " + table)]
            for table in LEGACY_TABLES
        },
    }
    raw = canonical(payload)
    legacy = original.snapshots / (
        f"state-{time.time_ns() + 1000000000:020d}-legacy-"
        + hashlib.sha256(raw).hexdigest()
        + ".json"
    )
    legacy.write_bytes(raw)
    migrated = CloudStore(root / "runtime2", root / "persist")
    assert migrated.user("u_test")["name"] == "Migration"
    assert migrated.one("SELECT COUNT(*) n FROM notifications")["n"] == 0
    assert (
        json.loads(sorted(migrated.snapshots.glob("state-*.json"))[-1].read_text())[
            "version"
        ]
        == 3
    )
    checks.append("Version 1 production snapshots migrate without losing accounts")
    with migrated.atomic():
        migrated.execute(
            "INSERT INTO share_receipts VALUES(?,?,?,?)", ("s_test", 12, 34, "f_copy")
        )
        migrated.execute(
            "INSERT INTO copy_jobs VALUES(?,?,?)", ("f_copy", "s_test", "u_test")
        )
        migrated.execute(
            "INSERT INTO notifications VALUES(?,?,?,?,?,?,?,?)",
            (
                "n_test",
                "u_test",
                "s_test",
                "f_original",
                "saved",
                "Saved synthetic file",
                34,
                0,
            ),
        )
    restored = CloudStore(root / "runtime3", root / "persist")
    assert (
        restored.one("SELECT saved_file_id FROM share_receipts")["saved_file_id"]
        == "f_copy"
    )
    assert restored.one("SELECT share_id FROM copy_jobs")["share_id"] == "s_test"
    assert (
        restored.one("SELECT message FROM notifications")["message"]
        == "Saved synthetic file"
    )
    checks.append(
        "Receipts, independent-copy mapping and notifications survive a clean restart"
    )
    with patch.object(restored, "snapshot", side_effect=OSError("storage unavailable")):
        try:
            with restored.atomic():
                restored.execute("UPDATE share_receipts SET downloaded_at=999")
                restored.execute("UPDATE notifications SET read_at=999")
        except OSError:
            pass
        else:
            raise AssertionError("failed durable write was accepted")
    assert (
        restored.one("SELECT downloaded_at FROM share_receipts")["downloaded_at"] == 12
    )
    assert restored.one("SELECT read_at FROM notifications")["read_at"] == 0
    checks.append(
        "Receipt and notification updates roll back together if persistence fails"
    )
    restored.chunk_path("f_original", 0).write_bytes(b"ciphertext")
    restored.chunk_path("f_original", 1).write_bytes(b"orphan from interrupted upload")
    restored.chunk_path("f_copy", 0).write_bytes(b"independent ciphertext")
    restored.execute("INSERT INTO blob_garbage VALUES(?,?)", ("f_original", "[0]"))
    with patch.object(restored, "delete_blobs", side_effect=OSError("offline")):
        restored.collect_garbage()
    assert restored.one("SELECT file_id FROM blob_garbage")["file_id"] == "f_original"
    recovered = CloudStore(root / "runtime4", root / "persist")
    assert recovered.one("SELECT COUNT(*) n FROM blob_garbage")["n"] == 0
    assert not recovered.chunk_path("f_original", 0).exists()
    assert not recovered.chunk_path("f_original", 1).exists()
    assert recovered.chunk_path("f_copy", 0).read_bytes() == b"independent ciphertext"
    checks.append(
        "Deferred deletion retries after restart and removes orphan chunks only for that file"
    )
Path(".test-results/persistence.json").write_text(
    json.dumps({"passed": len(checks), "checks": checks}, indent=2), encoding="utf-8"
)
print(json.dumps({"passed": len(checks), "checks": checks}))
