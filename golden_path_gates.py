# SPDX-License-Identifier: Apache-2.0
"""Six local pre-push checks. Reports contain counts, never scanned values.

Tracked-file checks inspect working-tree bytes, so Windows checkout conversion
is visible. Commit policy applies to HEAD's subject. The nine-Epic lock manifest
is CODEX_OVERNIGHT_SWARM_TASKS.md; missing inputs fail closed. No Git state changes.
"""

from ipaddress import IPv4Address
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys

from opscryer_backend import validate_spatial_graph_contract


SPDX_HEADER = "# SPDX-License-Identifier: Apache-2.0"
_SUBJECT = re.compile(
    r"(?:feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)"
    r"(?:\([a-z0-9][a-z0-9._/-]*\))?!?: [^\s]+(?: [^\s]+)*")


def verify_public_cli_entrypoints(repo_root=None) -> dict:
    """Check the seven public scripts for an importable, callable ``main``.

    Default to this module's directory. Load scripts with a non-CLI run name
    and never invoke their entrypoints. Reports contain only fixed filenames
    and booleans; missing files and load errors fail the affected check.
    This check is independent of the six-gate pre-push audit.
    """
    root = Path(repo_root) if repo_root is not None else Path(__file__).resolve().parent
    root = root.resolve()
    entrypoints = {}
    original_path = sys.path[:]
    try:
        sys.path.insert(0, str(root))
        for filename in ("opscryer_showcase.py", "opscryer_browser.py",
                         "ticket_chat_portal.py", "live_advisor.py",
                         "demo_rehearsal.py", "chat_walkthrough.py",
                         "live_e2e_runner.py"):
            result = {"exists": False, "callable_main": False, "passed": False}
            entrypoints[filename] = result
            try:
                path = root / filename
                result["exists"] = path.is_file()
                if result["exists"]:
                    namespace = runpy.run_path(str(path), run_name="_opscryer_cli_check_")
                    result["callable_main"] = callable(namespace.get("main"))
                    result["passed"] = result["callable_main"]
            except (Exception, SystemExit):
                # Do not expose arbitrary file contents or exception details.
                pass
    finally:
        sys.path[:] = original_path
    return {"passed": all(result["passed"] for result in entrypoints.values()),
            "entrypoints": entrypoints}


def validate_conventional_commit_subject(subject):
    """Return whether a single lowercase Conventional Commit subject is valid.

    Standard types, optional scope and breaking-change marker are supported.
    The 100-character limit includes all punctuation and spaces.
    """
    return (isinstance(subject, str) and 0 < len(subject) <= 100
            and subject == subject.lower()
            and not any(ord(char) < 32 or ord(char) == 127 for char in subject)
            and _SUBJECT.fullmatch(subject) is not None)


def _lock_prefix(scope):
    # Locks are portable repository-relative paths. Case folding prevents two
    # agents from owning aliases on a Windows checkout. Glob roots reserve the
    # whole subtree conservatively, including files not yet present on disk.
    if not isinstance(scope, str) or not scope or scope != scope.strip():
        raise ValueError("invalid lock")
    scope = scope.replace("\\", "/")
    if scope.startswith("/") or ":" in scope:
        raise ValueError("invalid lock")
    parts = scope.rstrip("/").split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("invalid lock")
    prefix = []
    for part in parts:
        if any(char in part for char in "*?["):
            break
        prefix.append(part.casefold())
    return tuple(prefix)


def verify_epic_lock_disjointness(epics):
    """Return True for well-formed, pairwise-disjoint Epic lock records.

    Accept a nonempty list of dicts with unique ``epic_id`` (or ``id``) and
    nonempty ``locked_scopes`` lists. Directory locks include descendants.
    Wildcards conservatively reserve their literal parent directory. This
    helper accepts any Epic count; the audit separately requires EPIC-1..9.
    """
    if not isinstance(epics, (list, tuple)) or not epics:
        return False
    owners, identifiers = [], set()
    try:
        for epic in epics:
            if not isinstance(epic, dict):
                return False
            identifier = epic.get("epic_id", epic.get("id"))
            scopes = epic.get("locked_scopes")
            if (not isinstance(identifier, str) or not identifier.strip()
                    or identifier.casefold() in identifiers
                    or not isinstance(scopes, (list, tuple)) or not scopes):
                return False
            identifiers.add(identifier.casefold())
            locks = [_lock_prefix(scope) for scope in scopes]
            for previous in owners:
                for left in locks:
                    for right in previous:
                        length = min(len(left), len(right))
                        if left[:length] == right[:length]:
                            return False
            owners.append(locks)
    except ValueError:
        return False
    return True


def _manifest_epics(root):
    text = (root / "CODEX_OVERNIGHT_SWARM_TASKS.md").read_text(encoding="utf-8")
    sections = re.split(r"(?m)^## (EPIC-\d+)\b[^\n]*\n", text)
    epics = []
    for index in range(1, len(sections), 2):
        matches = re.findall(r"(?m)^- \*\*Locked Scopes:\*\* `([^`]+)`\s*$",
                             sections[index + 1])
        if len(matches) != 1:
            raise ValueError("invalid manifest")
        epics.append({"epic_id": sections[index],
                      "locked_scopes": [scope.strip() for scope in matches[0].split(",")]})
    return epics


def _opsec_count(content):
    count = 0
    for match in re.finditer(rb"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)", content):
        try:
            address = IPv4Address(match[0].decode("ascii"))
        except ValueError:
            continue
        count += (address.is_global and not address.is_multicast
                  and str(address) != "203.0.113.1")
    patterns = [
        rb"(?<![\w:-])[0-9a-f]{2}([:-])(?:[0-9a-f]{2}\1){4}[0-9a-f]{2}(?![\w:-])",
        rb"(?<![\w.])(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}(?!\w|\.[0-9a-f])",
    ]
    count += sum(len(re.findall(pattern, content, re.IGNORECASE)) for pattern in patterns)
    prefixes = [b"gh" + b"o_", b"gh" + b"p_", b"gl" + b"pat-", b"s" + b"k-"]
    # Match token starts, not suffixes of words such as HTML risk-register IDs.
    count += len(re.findall(rb"(?<![A-Za-z0-9_])(?:" + b"|".join(prefixes)
                            + rb")[A-Za-z0-9_-]+", content))
    return count


def _public_files(root):
    def fail(error):
        raise OSError("unreadable directory") from None

    for directory, directories, files in os.walk(root, onerror=fail, followlinks=False):
        directories[:] = sorted(name for name in directories if name not in {".git", "__pycache__"})
        # Do not silently skip linked directories, or follow them outside root.
        if any((Path(directory) / name).is_symlink() for name in directories):
            raise OSError("linked directory")
        for name in sorted(files):
            path = Path(directory) / name
            if path != root / ".git":
                if path.is_symlink():
                    raise OSError("linked file")
                yield path


def run_six_gate_prepush_audit(root_dir=None):
    """Return ``passed`` and six named gate results with violation/error counts.

    OPSEC and Python-header checks include hidden, untracked and binary files,
    excluding Git metadata and bytecode caches. An unreadable input fails its
    gate without stopping the other checks. A nonrepository cannot pass.
    """
    root = Path(root_dir) if root_dir is not None else Path(__file__).resolve().parent
    root = root.resolve()
    names = ("crlf", "opsec", "spdx", "graph_contract", "commit_subject", "epic_locks")
    gates = {name: {"passed": False, "violations": 0, "errors": 0} for name in names}

    def git(*args):
        result = subprocess.run(["git", "-C", str(root), *args], check=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout

    try:
        # --show-prefix avoids comparing native paths with POSIX paths returned
        # by Git wrappers on Windows, while still rejecting nested directories.
        if (git("rev-parse", "--is-inside-work-tree").strip() != b"true"
                or git("rev-parse", "--show-prefix").strip()):
            raise ValueError("not repository root")
        paths = git("ls-files", "-z").split(b"\0")
        for name in filter(None, paths):
            path = root / os.fsdecode(name)
            if path.is_symlink() or not path.resolve().is_relative_to(root):
                raise OSError("unsafe tracked path")
            gates["crlf"]["violations"] += b"\r\n" in path.read_bytes()
    except (OSError, ValueError, subprocess.SubprocessError):
        gates["crlf"]["errors"] += 1

    try:
        if (git("rev-parse", "--is-inside-work-tree").strip() != b"true"
                or git("rev-parse", "--show-prefix").strip()):
            raise ValueError("not repository root")
        subject = git("log", "-1", "--format=%s").decode("utf-8").removesuffix("\n")
        gates["commit_subject"]["violations"] = int(not validate_conventional_commit_subject(subject))
    except (OSError, ValueError, subprocess.SubprocessError):
        gates["commit_subject"]["errors"] += 1

    try:
        for path in _public_files(root):
            content = path.read_bytes()
            relative = path.relative_to(root).as_posix().encode("utf-8")
            gates["opsec"]["violations"] += _opsec_count(relative + b"\n" + content)
            if path.name == ".env" or (path.name.startswith(".env.") and path.name != ".env.example"):
                gates["opsec"]["violations"] += 1
            if path.suffix.lower() == ".py":
                lines = content.decode("utf-8-sig").splitlines()
                offset = int(bool(lines and lines[0].startswith("#!")))
                gates["spdx"]["violations"] += (len(lines) <= offset or lines[offset] != SPDX_HEADER)
    except (OSError, UnicodeError):
        gates["opsec"]["errors"] += 1
        gates["spdx"]["errors"] += 1

    try:
        catalog = json.loads((root / "sample-graph-data.json").read_text(encoding="utf-8"))
        gates["graph_contract"]["violations"] = len(validate_spatial_graph_contract(catalog))
    except (OSError, ValueError, RecursionError):
        gates["graph_contract"]["errors"] += 1

    try:
        epics = _manifest_epics(root)
        valid = (len(epics) == 9 and {e["epic_id"] for e in epics}
                 == {f"EPIC-{index}" for index in range(1, 10)}
                 and verify_epic_lock_disjointness(epics))
        gates["epic_locks"]["violations"] = int(not valid)
    except (OSError, ValueError):
        gates["epic_locks"]["errors"] += 1

    for gate in gates.values():
        gate["passed"] = gate["violations"] == gate["errors"] == 0
    return {"passed": all(gate["passed"] for gate in gates.values()), "gates": gates}


if __name__ == "__main__":
    report = run_six_gate_prepush_audit()
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["passed"] else 1)
