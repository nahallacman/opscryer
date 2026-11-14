# SPDX-License-Identifier: Apache-2.0
"""Portable UTF-8 file helpers and a path-free runtime capability report."""

import argparse
import json
import os
from pathlib import Path
import shutil
import sys


def detect_runtime_capabilities() -> dict:
    """Return compatibility facts without executable paths or user details."""
    return {
        "python_version": ".".join(str(part) for part in sys.version_info[:3]),
        "os_family": "windows" if os.name == "nt" else "posix",
        "utf8_mode": bool(sys.flags.utf8_mode),
        "available_binaries": {
            name: shutil.which(name) is not None
            for name in ("kubectl", "ollama", "codex", "git", "node")
        },
    }


def read_utf8_text(path: Path) -> str:
    """Read strict UTF-8, normalizing CRLF and CR line endings to LF."""
    with path.open("r", encoding="utf-8", newline=None) as stream:
        return stream.read()


def write_utf8_lf(path: Path, content: str) -> None:
    """Write UTF-8 without a BOM, normalizing all line endings to LF."""
    content = content.replace("\r\n", "\n").replace("\r", "\n")
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(content)


def main(argv=None) -> int:
    """Print runtime facts as JSON (the default) or Markdown."""
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--json", action="store_true", help="print JSON (default)")
    mode.add_argument("--markdown", action="store_true", help="print Markdown")
    args = parser.parse_args(argv)
    facts = detect_runtime_capabilities()
    if args.markdown:
        lines = ["# Runtime compatibility", "", "| Capability | Value |",
                 "| --- | --- |"]
        for key in ("python_version", "os_family", "utf8_mode"):
            lines.append(f"| {key} | {facts[key]} |")
        for name, available in facts["available_binaries"].items():
            lines.append(f"| {name} | {available} |")
        print("\n".join(lines))
    else:
        print(json.dumps(facts, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
