# SPDX-License-Identifier: Apache-2.0
"""Offline CI verification gate for OpsCryer (unit tests, CLI entrypoints, 6-gate audit, showcase)."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parent.parent
_FORBIDDEN_SKILL_DIRS = frozenset(
    {
        "authentik_configuration",
        "game_server_steam_probe_and_recovery",
        "kubernetes_manifest_standards",
        "swarm_c2_and_ramcache_architecture",
    }
)
_INTERNAL_LEAK_RE = re.compile(
    r"(?i)(?:home" + r"\.arpa|duckdns" + r"\.org|\b192\.168\.\d{1,3}\.\d{1,3}\b|\b10\.10\.\d{1,3}\.\d{1,3}\b)"
)


def _has_valid_strict_frontmatter(skill_md: Path) -> tuple[bool, str]:
    raw = skill_md.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        return False, "utf8_bom_forbidden"
    lines = raw.decode("utf-8", errors="replace").replace("\r\n", "\n").splitlines()
    if len(lines) < 3 or lines[0].strip() != "---":
        return False, "missing_frontmatter_start"
    end_idx = next((idx for idx in range(1, len(lines)) if lines[idx].strip() == "---"), -1)
    if end_idx < 0:
        return False, "missing_frontmatter_end"
    seen_keys: set[str] = set()
    for ln in lines[1:end_idx]:
        stripped = ln.strip()
        if not stripped or stripped.startswith("#") or ":" not in stripped:
            continue
        key, val = stripped.split(":", 1)
        clean_k = key.strip()
        val_s = val.strip()
        if clean_k and val_s:
            seen_keys.add(clean_k)
        if val_s and not (val_s.startswith(('"', "'")) and val_s.endswith(val_s[0])) and ": " in val_s:
            return False, f"unquoted_colon_in_yaml:{clean_k}"
    if "name" not in seen_keys or "description" not in seen_keys:
        return False, "missing_name_or_description"
    return True, ""


def verify_ai_project_hygiene(root: Path = REPO_ROOT) -> dict:
    """Verify lowercase .ai/ docs, valid skill frontmatter, zero unrelated homelab skills, and OPSEC."""
    root = Path(root).resolve()
    findings: list[str] = []
    checked = 0
    passed_count = 0

    def _record(ok: bool, issue: str = "") -> None:
        nonlocal checked, passed_count
        checked += 1
        if ok:
            passed_count += 1
        elif issue:
            findings.append(issue)

    names = sorted(p.name for p in root.iterdir())
    _record(".ai" in names and ".AI" not in names and (root / ".ai").is_dir(), "lowercase_ai_dir_invalid")

    gi_ok = False
    gi_file = root / ".gitignore"
    if gi_file.is_file():
        gi_lines = {ln.strip().lstrip("/") for ln in gi_file.read_text(encoding="utf-8", errors="replace").splitlines()}
        gi_ok = any(ln in {".ai/local", ".ai/local/", ".ai/local/*", ".ai/local/**"} for ln in gi_lines)
    _record(gi_ok, "gitignore_missing_ai_local")

    pjson = root / ".ai" / "project.json"
    pjson_ok = False
    if pjson.is_file():
        try:
            pdata = json.loads(pjson.read_text(encoding="utf-8"))
            pjson_ok = isinstance(pdata, dict) and pdata.get("project_id") == "opscryer"
        except Exception:
            pjson_ok = False
    _record(pjson_ok, "invalid_project_json")

    sjson = root / ".agents" / "skills.json"
    sjson_ok = False
    if sjson.is_file():
        try:
            sdata = json.loads(sjson.read_text(encoding="utf-8"))
            entries = sdata.get("entries") if isinstance(sdata, dict) else []
            sjson_ok = isinstance(entries, list) and any(
                isinstance(item, dict) and item.get("path") == ".ai/skills" for item in entries
            )
        except Exception:
            sjson_ok = False
    _record(sjson_ok, "invalid_agents_skills_json")

    for sub in ("design", "plans"):
        sub_dir = root / ".ai" / sub
        mds = sorted(p for p in sub_dir.rglob("*.md") if p.is_file()) if sub_dir.is_dir() else []
        _record(len(mds) >= 1, f"missing_markdown:.ai/{sub}")
        for md in mds:
            text = md.read_text(encoding="utf-8", errors="replace")
            rel = md.relative_to(root).as_posix()
            _record(bool(text.strip()) and _INTERNAL_LEAK_RE.search(text) is None, f"invalid_or_leak:{rel}")

    skills_root = root / ".ai" / "skills"
    skill_dirs = sorted(p for p in skills_root.iterdir() if p.is_dir()) if skills_root.is_dir() else []
    stray = sorted(p.name for p in skill_dirs if p.name in _FORBIDDEN_SKILL_DIRS)
    _record(len(stray) == 0, f"forbidden_homelab_skills:{stray}")
    _record(len(skill_dirs) >= 1, "missing_repo_skills")
    for sdir in skill_dirs:
        smd = sdir / "SKILL.md"
        ok_fm, err = _has_valid_strict_frontmatter(smd) if smd.is_file() else (False, "missing_skill_md")
        text = smd.read_text(encoding="utf-8", errors="replace") if smd.is_file() else ""
        _record(ok_fm and _INTERNAL_LEAK_RE.search(text) is None, f"skill_invalid:{sdir.name}:{err}")

    return {
        "passed": len(findings) == 0,
        "checked": checked,
        "passed_count": passed_count,
        "violations": len(findings),
        "findings": findings,
    }


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

        hygiene_report = verify_ai_project_hygiene(REPO_ROOT)
        print("[CI] verify_ai_project_hygiene:", json.dumps(hygiene_report), flush=True)
        if not hygiene_report.get("passed"):
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
