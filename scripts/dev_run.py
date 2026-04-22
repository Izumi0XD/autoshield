import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _is_port_open(port: int, host: str = "127.0.0.1") -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.2)
    try:
        return s.connect_ex((host, port)) == 0
    finally:
        s.close()


def _wait_for_port(port: int, timeout: float = 10.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if _is_port_open(port):
            return True
        time.sleep(0.2)
    return False


def _pick_free_port(start: int = 8503, end: int = 8600) -> int:
    for p in range(start, end + 1):
        if not _is_port_open(p):
            return p
    raise RuntimeError("No free API port found in range 8505-8600")


def _repo_python() -> str:
    venv_python = ROOT / "venv" / "bin" / "python"
    if venv_python.exists():
        return str(venv_python)
    return sys.executable


def main() -> int:
    python_bin = _repo_python()
    npm_bin = shutil.which("npm")
    if not npm_bin:
        print("[dev-run] npm not found in PATH", file=sys.stderr)
        return 1

    api_port = _pick_free_port(8505, 8600)
    test_site_port = int(os.environ.get("AUTOSHIELD_TEST_SITE_PORT", "9091"))

    print(f"[dev-run] Using Python: {python_bin}")
    print(f"[dev-run] API port: {api_port}")
    print(f"[dev-run] Frontend URL: http://localhost:5173 (or next free Vite port)")
    print(f"[dev-run] Test site URL: http://localhost:{test_site_port}")

    base_env = os.environ.copy()
    base_env["AUTOSHIELD_API_PORT"] = str(api_port)
    base_env["AUTOSHIELD_TEST_SITE_PORT"] = str(test_site_port)

    procs: list[subprocess.Popen] = []

    try:
        bootstrap = subprocess.run(
            [python_bin, "scripts/dev_bootstrap.py"],
            cwd=ROOT,
            env=base_env,
            check=False,
        )
        if bootstrap.returncode != 0:
            return bootstrap.returncode

        api = subprocess.Popen([python_bin, "api_layer.py"], cwd=ROOT, env=base_env)
        procs.append(api)

        if not _wait_for_port(api_port, timeout=15.0):
            print(f"[dev-run] API failed to bind on port {api_port}", file=sys.stderr)
            return 1

        web_env = base_env.copy()
        web_env["VITE_API_URL"] = f"http://127.0.0.1:{api_port}"
        web = subprocess.Popen(
            [
                npm_bin,
                "--prefix",
                "autoshield-react",
                "run",
                "dev:vite",
                "--",
                "--host",
                "0.0.0.0",
            ],
            cwd=ROOT,
            env=web_env,
        )
        procs.append(web)

        site = subprocess.Popen(
            [python_bin, "test_website/server.py"], cwd=ROOT, env=base_env
        )
        procs.append(site)

        agent = subprocess.Popen(
            [
                python_bin,
                "nginx_agent.py",
                "--log",
                "test_website/access.log",
                "--api",
                f"http://127.0.0.1:{api_port}",
                "--key",
                "as_demo_key_change_in_production",
            ],
            cwd=ROOT,
            env=base_env,
        )
        procs.append(agent)

        print("[dev-run] Stack is live.")
        print(f"[dev-run] Backend:  http://127.0.0.1:{api_port}")
        print(f"[dev-run] Test site: http://127.0.0.1:{test_site_port}")

        while True:
            for p in procs:
                rc = p.poll()
                if rc is not None:
                    print(f"[dev-run] Child exited ({p.args}): {rc}", file=sys.stderr)
                    return rc
            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\n[dev-run] Shutting down...")
        return 0
    finally:
        for p in reversed(procs):
            if p.poll() is None:
                try:
                    p.send_signal(signal.SIGTERM)
                except Exception:
                    pass
        time.sleep(0.8)
        for p in reversed(procs):
            if p.poll() is None:
                try:
                    p.kill()
                except Exception:
                    pass


if __name__ == "__main__":
    raise SystemExit(main())
