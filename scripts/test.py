"""Run tests against isolated storage and loopback-only servers."""

from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / ".test-results"
PYTHON_TESTS = [
    "cloud-persistence.py",
    "cloud-bucket.py",
    "cloud-availability.py",
    "delivery-persistence.py",
    "remember-server.py",
    "bucket-retention.py",
]
API_TESTS = ["integration.mjs", "cloud-policy.mjs", "delivery.mjs"]


def environment():
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("SV_", "HF_", "SPACE_"))
        and key not in ("RENDER", "PORT", "HOST")
    }
    env.update(PYTHONPATH=str(ROOT), PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
    return env


def run(command, env):
    print("\n" + " ".join(str(item) for item in command), flush=True)
    subprocess.run(command, cwd=ROOT, env=env, check=True, timeout=240)


def api_suite(node, name, env):
    with tempfile.TemporaryDirectory(prefix="secretvault-tests-") as directory:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        base = f"http://127.0.0.1:{port}"
        local = env | {
            "HOST": "127.0.0.1",
            "PORT": str(port),
            "SV_RUNTIME_DIR": str(Path(directory) / "runtime"),
            "SV_PERSISTENT_DIR": str(Path(directory) / "persistent"),
            "SV_TEST_URL": base,
            "SV_ALLOWED_ORIGINS": f"{base},http://127.0.0.1:8787,http://localhost:8787",
            "SV_ADMIN_CLAIM_HASH": hashlib.sha256(
                b"test-local-admin-activation"
            ).hexdigest(),
        }
        with (RESULTS / (name + ".log")).open("w", encoding="utf-8") as log:
            server = subprocess.Popen(
                [sys.executable, "-m", "cloudserver.main"],
                cwd=ROOT,
                env=local,
                stdout=log,
                stderr=subprocess.STDOUT,
            )
            try:
                ready = False
                for _ in range(100):
                    if server.poll() is not None:
                        raise RuntimeError(
                            f"{name}: server exited; see .test-results/{name}.log"
                        )
                    try:
                        with urllib.request.urlopen(
                            base + "/api/health", timeout=1
                        ) as response:
                            ready = json.load(response)["ok"]
                        if ready:
                            break
                    except (OSError, ValueError):
                        time.sleep(0.1)
                if not ready:
                    raise RuntimeError("Local test server did not become ready")
                run([node, "tests/" + name], local)
            finally:
                server.terminate()
                try:
                    server.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)


def main():
    node = shutil.which("node")
    if not node:
        raise RuntimeError("Node.js 22 or later is required")
    RESULTS.mkdir(exist_ok=True)
    env = environment()
    run([node, "hosting/build-web.mjs"], env)
    for name in ["web-regressions.mjs", "remember.mjs"]:
        run([node, "tests/" + name], env)
    for name in PYTHON_TESTS:
        run([sys.executable, "tests/" + name], env)
    for name in API_TESTS:
        api_suite(node, name, env)
    print("\nAll test suites passed.", flush=True)


if __name__ == "__main__":
    main()
