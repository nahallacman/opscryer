# SPDX-License-Identifier: Apache-2.0
"""Offline CI verification gate for OpsCryer (unit tests, CLI entrypoints, 6-gate audit, showcase)."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parent.parent


def _run_step(cmd: list[str], env: dict[str, str]) -> int:
    print(f"[CI] Running: {' '.join(cmd)}", flush=True)
    proc = subprocess.run(cmd, cwd=str(REPO_ROOT), env=env, check=False)
    return proc.returncode


def main() -> int:
    os.chdir(REPO_ROOT)
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    # Install nodejs inside Debian CI containers when absent so EPIC-1 browser JS tests run with 0 skips.
    if os.environ.get("CI") == "true" and not shutil.which("node") and shutil.which("apt-get"):
        subprocess.run(["apt-get", "update", "-qq"], check=True)
        subprocess.run(["apt-get", "install", "-y", "-qq", "--no-install-recommends", "nodejs"], check=True)
    env = {**os.environ, "OPSCRYER_OFFLINE_ONLY": "1"}
    env.pop("OPSCRYER_GRAPH_FILE", None)
    saved_graph_file = os.environ.pop("OPSCRYER_GRAPH_FILE", None)
    os.environ["OPSCRYER_OFFLINE_ONLY"] = "1"
    try:
        suite = unittest.defaultTestLoader.discover(str(REPO_ROOT / "tests"))
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        if not result.wasSuccessful():
            return 1

        import golden_path_gates

        cli_report = golden_path_gates.verify_public_cli_entrypoints(REPO_ROOT)
        print("[CI] verify_public_cli_entrypoints:", json.dumps(cli_report), flush=True)
        if not cli_report.get("passed"):
            return 1

        if (REPO_ROOT / ".git").exists() and shutil.which("git"):
            gates_report = golden_path_gates.run_six_gate_prepush_audit(REPO_ROOT)
            print("[CI] run_six_gate_prepush_audit:", json.dumps(gates_report), flush=True)
            if not gates_report.get("passed"):
                return 1

        for act in ("1", "2"):
            if _run_step([sys.executable, "opscryer_showcase.py", "--act", act, "--json"], env) != 0:
                return 1

        return 0
    finally:
        if saved_graph_file is not None:
            os.environ["OPSCRYER_GRAPH_FILE"] = saved_graph_file


if __name__ == "__main__":
    raise SystemExit(main())
