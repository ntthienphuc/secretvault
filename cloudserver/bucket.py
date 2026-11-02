"""Use a private Hugging Face Storage Bucket from a CPU host such as Render.

The bucket token is server-only, read from the host's secret environment. The web
client only receives a normal application session token, never this credential.
"""

from __future__ import annotations

import hashlib
import os
import threading
from pathlib import Path

from .store import CloudStore


class BucketBlob:
    def __init__(self, store, file_id, index):
        self.store = store
        self.local = store.blobs / (file_id + "-" + str(index) + ".bin")
        self.remote = "secretvault/ciphertext/" + self.local.name

    def write_bytes(self, data):
        # The persistent write must finish before the API can acknowledge a chunk.
        self.store.bucket_api.batch_bucket_files(
            self.store.bucket_id, add=[(bytes(data), self.remote)]
        )
        self.local.write_bytes(data)
        return len(data)

    def read_bytes(self):
        if not self.local.is_file():
            self.store.bucket_api.download_bucket_files(
                self.store.bucket_id,
                [(self.remote, self.local)],
                raise_on_missing_files=True,
            )
        return self.local.read_bytes()


class BucketStore(CloudStore):
    def __init__(self, runtime: Path, persistent: Path, bucket_id: str, api=None):
        if api is None:
            from huggingface_hub import HfApi

            api = HfApi(token=os.environ["HF_TOKEN"])
        self.bucket_api = api
        self.bucket_id = bucket_id
        info = api.bucket_info(bucket_id)
        # Private bucket contents contain account metadata; fail closed if public.
        if getattr(info, "private", False) is not True:
            raise RuntimeError("SecretVault requires a private storage bucket")
        snapshot_dir = persistent.resolve() / "metadata"
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        entries = list(
            api.list_bucket_tree(
                bucket_id, prefix="secretvault/metadata", recursive=False
            )
        )
        snapshots = sorted(
            (
                entry.path
                for entry in entries
                if hasattr(entry, "size") and entry.path.endswith(".json")
            ),
            reverse=True,
        )
        self._remote_snapshots = set(snapshots)
        self._retention_pending = set()
        self._retention_lock = threading.Lock()
        self._retention_worker = None
        for remote in snapshots[:3]:
            name = Path(remote).name
            if not name.startswith("state-"):
                continue
            api.download_bucket_files(
                bucket_id, [(remote, snapshot_dir / name)], raise_on_missing_files=True
            )
        super().__init__(runtime, persistent)

    def snapshot(self, db):
        target = super().snapshot(db)
        remote = "secretvault/metadata/" + target.name
        try:
            self.bucket_api.batch_bucket_files(self.bucket_id, add=[(target, remote)])
            # Confirm the exact immutable object after upload, independently of
            # local filesystem caches. Do not acknowledge failed durability.
            verify = target.with_suffix(".verify")
            self.bucket_api.download_bucket_files(
                self.bucket_id, [(remote, verify)], raise_on_missing_files=True
            )
            try:
                if (
                    hashlib.sha256(verify.read_bytes()).digest()
                    != hashlib.sha256(target.read_bytes()).digest()
                ):
                    raise OSError("Remote metadata verification failed")
            finally:
                verify.unlink(missing_ok=True)
        except Exception:
            target.unlink(missing_ok=True)
            raise
        return target

    def trim_snapshots(self):
        # Called only after commit. Retain three verified versions; cleanup does
        # not list the bucket or block an authenticated request on remote deletion.
        with self._retention_lock:
            self._remote_snapshots.update(
                "secretvault/metadata/" + p.name
                for p in self.snapshots.glob("state-*.json")
            )
            obsolete = sorted(self._remote_snapshots, reverse=True)[3:]
            self._retention_pending.update(obsolete)
            self._remote_snapshots.difference_update(obsolete)
            if self._retention_pending and self._retention_worker is None:
                self._retention_worker = threading.Thread(
                    target=self._flush_retention, daemon=True
                )
                self._retention_worker.start()
        super().trim_snapshots()

    def _flush_retention(self):
        while True:
            with self._retention_lock:
                pending = list(self._retention_pending)
                self._retention_pending.clear()
                if not pending:
                    self._retention_worker = None
                    return
            try:
                self.bucket_api.batch_bucket_files(self.bucket_id, delete=pending)
            except Exception:
                with self._retention_lock:
                    self._retention_pending.update(pending)
                    self._retention_worker = None
                return  # Next commit or restart retries; acknowledged data remains safe.

    def wait_for_retention(self, timeout=10):
        """Bounded shutdown/test hook; normal API requests never wait here."""
        worker = self._retention_worker
        if worker:
            worker.join(timeout)

    def chunk_path(self, file_id, index):
        return BucketBlob(self, file_id, index)

    def delete_blobs(self, file_id, indices):
        # Include an object whose upload succeeded just before a metadata failure.
        entries = self.bucket_api.list_bucket_tree(
            self.bucket_id, prefix="secretvault/ciphertext", recursive=False
        )
        names = [
            Path(entry.path).name
            for entry in entries
            if hasattr(entry, "size")
            and Path(entry.path).name.startswith(file_id + "-")
            and entry.path.endswith(".bin")
        ]
        if names:
            self.bucket_api.batch_bucket_files(
                self.bucket_id,
                delete=["secretvault/ciphertext/" + name for name in names],
            )
        super().delete_blobs(file_id, indices)
