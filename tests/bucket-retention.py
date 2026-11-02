import json, tempfile, threading, time
from pathlib import Path
from types import SimpleNamespace
from cloudserver.bucket import BucketStore


class Bucket:
    def __init__(self):
        self.objects = {}
        self.entered = threading.Event()
        self.release = threading.Event()
        self.block = False
        self.fail = False
        self.lists = 0

    def bucket_info(self, *args):
        return SimpleNamespace(private=True)

    def list_bucket_tree(self, bucket, prefix, recursive=False):
        self.lists += 1
        return [
            SimpleNamespace(path=p, size=len(v))
            for p, v in list(self.objects.items())
            if p.startswith(prefix + "/")
        ]

    def batch_bucket_files(self, bucket, add=None, delete=None):
        if delete and self.block:
            self.entered.set()
            assert self.release.wait(5)
        if delete and self.fail:
            raise OSError("retention unavailable")
        for value, p in add or []:
            self.objects[p] = (
                value if isinstance(value, bytes) else Path(value).read_bytes()
            )
        for p in delete or []:
            self.objects.pop(p, None)

    def download_bucket_files(self, bucket, files, raise_on_missing_files=False):
        for p, dest in files:
            Path(dest).write_bytes(self.objects[p])


checks = []
with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    api = Bucket()
    s = BucketStore(root / "run", root / "cache", "qa", api)
    s.execute(
        "INSERT INTO users VALUES(?,?,?,?,?,?,?,?)",
        ("u_test", "user@example.test", "Test", "salt", "hash", "{}", "{}", 1),
    )
    s.execute("UPDATE users SET name='Second'")
    api.block = True
    started = time.monotonic()
    s.execute("UPDATE users SET name='Third'")
    elapsed = time.monotonic() - started
    assert api.entered.wait(2) and elapsed < 1
    assert s.user("u_test")["name"] == "Third"
    checks.append("Slow retention does not block a committed authenticated write")
    s.execute("UPDATE users SET name='Fourth'")
    assert api.lists == 1
    checks.append("Routine writes no longer list remote metadata")
    api.release.set()
    s.wait_for_retention()
    assert len(api.objects) == 3
    recovered = BucketStore(root / "run2", root / "cache2", "qa", api)
    recovered.wait_for_retention()
    assert recovered.user("u_test")["name"] == "Fourth"
    checks.append("Retention keeps newest three snapshots and fresh-runtime recovery")
    api.block = False
    api.fail = True
    recovered.execute("UPDATE users SET name='Fifth'")
    recovered.wait_for_retention()
    assert recovered.user("u_test")["name"] == "Fifth" and recovered._retention_pending
    api.fail = False
    recovered.trim_snapshots()
    recovered.wait_for_retention()
    assert len(api.objects) == 3 and not recovered._retention_pending
    checks.append("Failed cleanup retries without rolling back acknowledged data")
Path(".test-results/bucket-retention.json").write_text(
    json.dumps({"passed": len(checks), "checks": checks}, indent=2), encoding="utf-8"
)
print(json.dumps({"passed": len(checks)}))
