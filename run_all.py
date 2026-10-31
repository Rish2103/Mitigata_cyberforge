"""
run_all.py — Single-command launcher for CYBERFORGE CORRELATE Live Demo.

Starts all 3 servers in one process group so you only need ONE command during judging:
  1. Target App #1 (Mock Web Shop)          -> http://127.0.0.1:5000
  2. Target App #2 (Unseen Billing Portal)  -> http://127.0.0.1:5001
  3. CyberForge Correlate Dashboard & API   -> http://127.0.0.1:8000

Usage:
  python run_all.py
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from typing import List


def main() -> int:
    repo_root = os.path.dirname(os.path.abspath(__file__))
    py = sys.executable

    commands = [
        (
            "Target App #1 (Mock Web Shop :5000)",
            [py, "-m", "tests.mock_shop_app.app"],
        ),
        (
            "Target App #2 (Unseen Billing Portal :5001)",
            [py, "-m", "tests.unseen_app_sim.app"],
        ),
        (
            "CyberForge Correlate Dashboard (:8000)",
            [py, "-m", "uvicorn", "api.main:app", "--host", "127.0.0.1", "--port", "8000"],
        ),
    ]

    procs: List[subprocess.Popen] = []
    print("=" * 78)
    print(" CYBERFORGE CORRELATE - UNIFIED 3-SERVER DEMO LAUNCHER")
    print("=" * 78)

    try:
        for label, cmd in commands:
            print(f" [+] Starting {label} ...")
            proc = subprocess.Popen(cmd, cwd=repo_root)
            procs.append(proc)
            time.sleep(0.4)

        print("-" * 78)
        print(" All 3 services are LIVE:")
        print("   -> Main Dashboard (:8000)        : http://127.0.0.1:8000")
        print("   -> Mock Web Shop (:5000)         : http://127.0.0.1:5000")
        print("   -> Unseen Billing Portal (:5001) : http://127.0.0.1:5001")
        print(" Press Ctrl+C to stop all 3 servers.")
        print("=" * 78)

        while True:
            for proc in procs:
                ret = proc.poll()
                if ret is not None:
                    print(f" [!] A child server exited with code {ret}. Shutting down...")
                    return ret
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n [*] Stopping all 3 servers...")
        return 0
    finally:
        for proc in procs:
            if proc.poll() is None:
                try:
                    proc.send_signal(signal.SIGTERM)
                except Exception:
                    proc.terminate()
        for proc in procs:
            try:
                proc.wait(timeout=3.0)
            except Exception:
                proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
