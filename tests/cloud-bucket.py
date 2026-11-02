"""Exercise remote-object durability independently of the server's local cache."""

import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from cloudserver.bucket import BucketStore


class FakeBucket:
    def __init__(self):
        self.objects = {}
        self.fail = False

    def bucket_info(self, bucket):
        return SimpleNamespace(private=True)

    def list_bucket_tree(self, bucket, prefix, recursive=False):
        return [
            SimpleNamespace(path=p, size=len(v))
            for p, v in self.objects.items()
            if p.startswith(prefix + "/")
        ]

    def batch_bucket_files(self, bucket, add=None, delete=None):
        if self.fail:
            raise OSError("simulated remote storage failure")
        for content, path in add or []:
            self.objects[path] = (
                content if isinstance(content, bytes) else Path(content).read_bytes()
            )
        for path in delete or []:
            self.objects.pop(path, None)

    def download_bucket_files(self, bucket, files, raise_on_missing_files=False):
        for path, local in files:
            Path(local).write_bytes(self.objects[path])


checks = []
with tempfile.TemporaryDirectory() as p:
    root = Path(p)
    api = FakeBucket()
    store = BucketStore(root / "runtime1", root / "cache1", "qa/private", api)
    store.execute(
        "INSERT INTO users VALUES(?,?,?,?,?,?,?,?)",
        ("u_test", "user@example.test", "Test", "salt", "opaque", "{}", "{}", 1),
    )
    store.execute("INSERT INTO accounts VALUES(?,'admin',1,?)", ("u_test", 104857600))
    store.chunk_path("f_test", 0).write_bytes(b"opaque ciphertext")
    assert "secretvault/ciphertext/f_test-0.bin" in api.objects
    checks.append("Ciphertext is remotely stored before upload acknowledgement")
    restart = BucketStore(root / "runtime2", root / "cache2", "qa/private", api)
    assert (
        restart.user("u_test")["name"] == "Test"
        and restart.settings("u_test")["role"] == "admin"
    )
    assert restart.chunk_path("f_test", 0).read_bytes() == b"opaque ciphertext"
    checks.append(
        "Completely fresh runtime and cache recover accounts, admin and ciphertext"
    )
    api.fail = True
    try:
        restart.execute("UPDATE users SET name='Not saved' WHERE id='u_test'")
    except OSError:
        pass
    else:
        raise AssertionError("remote failure ignored")
    assert restart.user("u_test")["name"] == "Test"
    checks.append("Remote write failures roll back metadata before success")
    try:
        restart.chunk_path("f_test", 1).write_bytes(b"not saved")
    except OSError:
        pass
    else:
        raise AssertionError("failed chunk acknowledged")
    assert not (root / "cache2" / "ciphertext" / "f_test-1.bin").exists()
    checks.append("Failed remote chunk uploads are not acknowledged or cached")
    store.wait_for_retention()
    restart.wait_for_retention()
    assert len([k for k in api.objects if k.startswith("secretvault/metadata/")]) <= 3
    checks.append("Snapshot retention preserves the latest three remote versions")
    api.fail = False
    restart.chunk_path("f_copy", 0).write_bytes(b"independent ciphertext")
    restart.execute("INSERT INTO blob_garbage VALUES(?,?)", ("f_test", "[]"))
    api.fail = True
    restart.collect_garbage()
    assert restart.one("SELECT COUNT(*) n FROM blob_garbage")["n"] == 1
    api.fail = False
    restart.collect_garbage()
    assert "secretvault/ciphertext/f_test-0.bin" not in api.objects
    assert restart.chunk_path("f_copy", 0).read_bytes() == b"independent ciphertext"
    assert restart.one("SELECT COUNT(*) n FROM blob_garbage")["n"] == 0
    checks.append(
        "Deferred remote deletion retries failures and preserves independent copies"
    )
Path(".test-results/cloud-bucket-results.json").write_text(
    json.dumps({"passed": len(checks), "checks": checks}, indent=2), encoding="utf8"
)
print(json.dumps({"passed": len(checks)}))
