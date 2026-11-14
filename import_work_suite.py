# SPDX-License-Identifier: Apache-2.0
"""Portable Work Importer for the OpsCryer 3-Tool Suite and Gemini CLI Skills Pack.

Installs or updates:
  1. Scrubbed `.ai/skills/` library (with direct Gemini CLI commands, no Antigravity args-file wrappers)
  2. Native Gemini CLI `GEMINI.md` (with lazy-loaded Skill Routing Table)
  3. Native Gemini CLI `.gemini/settings.json` (prefix allowlist) and `.gemini/commands/**/*.toml` slash commands
  4. The decoupled 3-Tool Operations & Knowledge Suite (`OpsCryer`, `The Brain`, and `The Swarm`)
into any target work repository or standalone directory.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


BUNDLE_ROOT = Path(__file__).resolve().parent

CORE_TOOL_FILES = (
    "opscryer_abstraction.py",
    "opscryer_browser.py",
    "yaml_shim.py",
    "settled_production_systems.yaml",
    "sample-graph-data.json",
    "index.html",
    "config.public.example.yaml",
    ".env.example",
)

OPTIONAL_SUITE_FILES = (
    "opscryer_backend.py",
    "opscryer_showcase.py",
    "jev_client.py",
    "cluster_harvester.py",
    "tactical_security_deck.py",
    "noc_golden_signals.py",
    "ticket_chat_portal.py",
    "live_advisor.py",
    "demo_rehearsal.py",
    "chat_walkthrough.py",
    "live_e2e_runner.py",
    "golden_path_gates.py",
    "live-cluster-sanitized.json",
)


def list_bundled_skills(bundle_root: Path = BUNDLE_ROOT) -> list[str]:
    skills_dir = bundle_root / ".ai" / "skills"
    if not skills_dir.is_dir():
        return []
    return sorted(
        p.parent.name
        for p in skills_dir.glob("*/SKILL.md")
        if p.is_file()
    )


def verify_work_bundle(bundle_root: Path = BUNDLE_ROOT) -> dict[str, Any]:
    skills = list_bundled_skills(bundle_root)
    has_gemini_md = (bundle_root / "GEMINI.md").is_file()
    has_gemini_settings = (bundle_root / ".gemini" / "settings.json").is_file()
    gemini_commands = sorted(
        str(p.relative_to(bundle_root)).replace("\\", "/")
        for p in (bundle_root / ".gemini" / "commands").rglob("*.toml")
    ) if (bundle_root / ".gemini" / "commands").is_dir() else []
    has_skills_json = (bundle_root / ".agents" / "skills.json").is_file()
    present_core = [f for f in CORE_TOOL_FILES if (bundle_root / f).is_file()]
    abstraction_ok = False
    abstraction_path = bundle_root / "opscryer_abstraction.py"
    if abstraction_path.is_file():
        proc = subprocess.run(
            [sys.executable, str(abstraction_path), "--ai-brief"],
            cwd=str(bundle_root),
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        abstraction_ok = proc.returncode == 0
    passed = (
        len(skills) >= 10
        and has_gemini_md
        and has_gemini_settings
        and len(gemini_commands) >= 4
        and has_skills_json
        and len(present_core) >= 4
        and abstraction_ok
    )
    return {
        "passed": passed,
        "agent_runtime": "gemini-cli",
        "bundle_root": str(bundle_root),
        "skill_count": len(skills),
        "skills": skills,
        "has_gemini_md": has_gemini_md,
        "has_gemini_settings_json": has_gemini_settings,
        "gemini_slash_commands": gemini_commands,
        "has_agents_skills_json": has_skills_json,
        "core_tool_files_present": present_core,
        "three_tool_self_test_passed": abstraction_ok,
    }


def import_into_target_workspace(
    target_dir: Path,
    mode: str = "all",
    tools_subdir: str = "tools/opscryer",
    agent_runtime: str = "gemini-cli",
    bundle_root: Path = BUNDLE_ROOT,
) -> dict[str, Any]:
    target_dir = target_dir.resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    copied_skills: list[str] = []
    copied_tools: list[str] = []
    gemini_files_updated: list[str] = []

    norm_tools_subdir = "" if (not tools_subdir or tools_subdir == ".") else tools_subdir.strip("/")

    if mode in ("all", "skills-only"):
        src_skills = bundle_root / ".ai" / "skills"
        dst_skills = target_dir / ".ai" / "skills"
        if src_skills.is_dir():
            for skill_md in sorted(src_skills.glob("*/SKILL.md")):
                skill_name = skill_md.parent.name
                out_md = dst_skills / skill_name / "SKILL.md"
                out_md.parent.mkdir(parents=True, exist_ok=True)
                out_md.write_bytes(skill_md.read_bytes().replace(b"\r\n", b"\n"))
                copied_skills.append(skill_name)

        if agent_runtime in ("gemini-cli", "both"):
            # 1. Install or non-destructively merge GEMINI.md
            src_gemini_md = bundle_root / "GEMINI.md"
            if src_gemini_md.is_file():
                gemini_text = src_gemini_md.read_text(encoding="utf-8").replace("\r\n", "\n")
                if norm_tools_subdir:
                    gemini_text = gemini_text.replace(
                        "`opscryer_browser.py`", f"`{norm_tools_subdir}/opscryer_browser.py`"
                    ).replace(
                        "`opscryer_abstraction.py`", f"`{norm_tools_subdir}/opscryer_abstraction.py`"
                    ).replace(
                        "python opscryer_abstraction.py", f"python {norm_tools_subdir}/opscryer_abstraction.py"
                    )
                dst_gemini_md = target_dir / "GEMINI.md"
                if dst_gemini_md.is_file():
                    existing_md = dst_gemini_md.read_text(encoding="utf-8").replace("\r\n", "\n")
                    if "OpsCryer 3-Tool Suite & Lazy Skill Index" not in existing_md:
                        merged_md = existing_md.rstrip() + "\n\n" + gemini_text
                        dst_gemini_md.write_text(merged_md, encoding="utf-8", newline="\n")
                else:
                    dst_gemini_md.write_text(gemini_text, encoding="utf-8", newline="\n")
                gemini_files_updated.append("GEMINI.md")

            # 2. Non-destructively merge .gemini/settings.json
            src_settings_path = bundle_root / ".gemini" / "settings.json"
            if src_settings_path.is_file():
                src_settings = json.loads(src_settings_path.read_text(encoding="utf-8"))
                dst_settings_path = target_dir / ".gemini" / "settings.json"
                dst_settings_path.parent.mkdir(parents=True, exist_ok=True)
                merged_settings: dict[str, Any] = {}
                if dst_settings_path.is_file():
                    try:
                        merged_settings = json.loads(dst_settings_path.read_text(encoding="utf-8"))
                    except Exception:
                        merged_settings = {}
                tools_cfg = merged_settings.setdefault("tools", {})
                allowed_list: list[str] = list(tools_cfg.get("allowed", []))
                for item in src_settings.get("tools", {}).get("allowed", []):
                    if item not in allowed_list:
                        allowed_list.append(item)
                tools_cfg["allowed"] = allowed_list
                if "contextFileName" not in merged_settings:
                    merged_settings["contextFileName"] = src_settings.get("contextFileName", ["GEMINI.md", "AGENTS.md"])
                dst_settings_path.write_text(
                    json.dumps(merged_settings, indent=2) + "\n",
                    encoding="utf-8",
                    newline="\n",
                )
                gemini_files_updated.append(".gemini/settings.json")

            # 3. Copy .gemini/commands/**/*.toml and rewrite tool prefix if needed
            src_cmds_root = bundle_root / ".gemini" / "commands"
            if src_cmds_root.is_dir():
                for toml_file in sorted(src_cmds_root.rglob("*.toml")):
                    rel_toml = toml_file.relative_to(bundle_root)
                    toml_text = toml_file.read_text(encoding="utf-8").replace("\r\n", "\n")
                    if norm_tools_subdir:
                        toml_text = toml_text.replace(
                            "python opscryer_abstraction.py",
                            f"python {norm_tools_subdir}/opscryer_abstraction.py",
                        ).replace(
                            "sys.path.insert(0, '.')",
                            f"sys.path.insert(0, '{norm_tools_subdir}')",
                        ).replace(
                            "Use `opscryer_abstraction.py`",
                            f"Use `{norm_tools_subdir}/opscryer_abstraction.py`",
                        )
                    dst_toml = target_dir / rel_toml
                    dst_toml.parent.mkdir(parents=True, exist_ok=True)
                    dst_toml.write_text(toml_text, encoding="utf-8", newline="\n")
                    gemini_files_updated.append(str(rel_toml).replace("\\", "/"))

        if agent_runtime in ("antigravity", "both"):
            agents_dir = target_dir / ".agents"
            agents_dir.mkdir(parents=True, exist_ok=True)
            skills_json_file = agents_dir / "skills.json"
            existing_entries: list[dict[str, str]] = []
            if skills_json_file.is_file():
                try:
                    loaded = json.loads(skills_json_file.read_text(encoding="utf-8"))
                    if isinstance(loaded.get("entries"), list):
                        existing_entries = list(loaded["entries"])
                except Exception:
                    existing_entries = []
            if not any(e.get("path") == ".ai/skills" for e in existing_entries if isinstance(e, dict)):
                existing_entries.append({"path": ".ai/skills"})
            skills_json_file.write_text(
                json.dumps({"entries": existing_entries}, indent=2) + "\n",
                encoding="utf-8",
                newline="\n",
            )

    if mode in ("all", "tools-only"):
        tools_dst = target_dir if not norm_tools_subdir else (target_dir / norm_tools_subdir)
        tools_dst.mkdir(parents=True, exist_ok=True)
        for filename in (*CORE_TOOL_FILES, *OPTIONAL_SUITE_FILES):
            src_file = bundle_root / filename
            if src_file.is_file():
                dst_file = tools_dst / filename
                dst_file.parent.mkdir(parents=True, exist_ok=True)
                dst_file.write_bytes(src_file.read_bytes().replace(b"\r\n", b"\n"))
                copied_tools.append(str(dst_file.relative_to(target_dir)).replace("\\", "/"))

    return {
        "status": "imported",
        "agent_runtime": agent_runtime,
        "target_dir": str(target_dir),
        "mode": mode,
        "imported_skill_count": len(copied_skills),
        "imported_skills": copied_skills,
        "gemini_cli_files_configured": gemini_files_updated,
        "imported_tool_file_count": len(copied_tools),
        "imported_tool_files": copied_tools,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify or import the OpsCryer 3-Tool Suite and portable Gemini CLI Skills into a work repository."
    )
    parser.add_argument(
        "--target",
        type=Path,
        default=None,
        help="Target workspace directory to import into (e.g. /path/to/work-repo).",
    )
    parser.add_argument(
        "--mode",
        choices=("all", "skills-only", "tools-only"),
        default="all",
        help="Import both skills + 3-tool suite ('all'), only skills + Gemini CLI config ('skills-only'), or only tools ('tools-only').",
    )
    parser.add_argument(
        "--agent-runtime",
        choices=("gemini-cli", "antigravity", "both"),
        default="gemini-cli",
        help="Target AI coding CLI runtime at work (defaults to 'gemini-cli').",
    )
    parser.add_argument(
        "--tools-subdir",
        default="tools/opscryer",
        help="Subdirectory under --target for the OpsCryer 3-Tool Suite (use '.' for target root).",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify bundled skills, Gemini CLI configuration, and 3-Tool Suite offline self-test.",
    )
    args = parser.parse_args(argv)

    if args.verify or args.target is None:
        report = verify_work_bundle(BUNDLE_ROOT)
        print(json.dumps(report, indent=2))
        return 0 if report["passed"] else 1

    import_report = import_into_target_workspace(
        target_dir=args.target,
        mode=args.mode,
        tools_subdir=args.tools_subdir,
        agent_runtime=args.agent_runtime,
        bundle_root=BUNDLE_ROOT,
    )
    print(json.dumps(import_report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
