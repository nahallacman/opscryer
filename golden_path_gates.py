# SPDX-License-Identifier: Apache-2.0
"""Six local pre-push checks. Reports contain counts, never scanned values.

Tracked-file checks inspect working-tree bytes, so Windows checkout conversion
is visible. Commit policy applies to HEAD's subject. The nine-Epic lock manifest
is EPIC_SCOPE_MANIFEST.md; missing inputs fail closed. No Git state changes.
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
_EXPECTED_DEMO_PIECE_ROLE = "PIECE_A_FRONTEND_SPATIAL_BROWSER_DEMO_DATASET"
_FORBIDDEN_EXACT_GRAPH_FILENAMES = frozenset({"curated-graph.json", "knowledge-graph.json"})
_FORBIDDEN_GRAPH_FILENAME = re.compile(r"(?:company|enterprise|internal|private|personal)[-_].*graph.*\.json$")
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
    passed_count = sum(1 for result in entrypoints.values() if result["passed"])
    checked_count = len(entrypoints)
    failed_count = checked_count - passed_count
    return {
        "passed": checked_count > 0 and passed_count == checked_count,
        "checked_count": checked_count,
        "passed_count": passed_count,
        "failed_count": failed_count,
        "entrypoints": entrypoints,
    }


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
    text = (root / "EPIC_SCOPE_MANIFEST.md").read_text(encoding="utf-8")
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


_IPV4_RE = re.compile(rb"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")
_MAC_COLON_RE = re.compile(
    rb"(?<![\w:-])[0-9a-f]{2}([:-])(?:[0-9a-f]{2}\1){4}[0-9a-f]{2}(?![\w:-])",
    re.IGNORECASE,
)
_MAC_CISCO_RE = re.compile(
    rb"(?<![\w.])(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}(?!\w|\.[0-9a-f])",
    re.IGNORECASE,
)
_TOKEN_PREFIXES = (b"gh" + b"o_", b"gh" + b"p_", b"gl" + b"pat-", b"s" + b"k-")
_TOKEN_RE = re.compile(
    rb"(?<![A-Za-z0-9_])(?:" + b"|".join(_TOKEN_PREFIXES) + rb")[A-Za-z0-9_-]+"
)


def _opsec_count(content):
    count = 0
    for match in _IPV4_RE.finditer(content):
        raw_ip = match[0]
        if raw_ip in (b"127.0.0.1", b"203.0.113.1", b"0.0.0.0"):
            continue
        try:
            address = IPv4Address(raw_ip.decode("ascii"))
        except ValueError:
            continue
        count += address.is_global and not address.is_multicast
    count += sum(1 for _ in _MAC_COLON_RE.finditer(content))
    count += sum(1 for _ in _MAC_CISCO_RE.finditer(content))
    # Match token starts, not suffixes of words such as HTML risk-register IDs.
    count += sum(1 for _ in _TOKEN_RE.finditer(content))
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
    """Return ``passed`` and six named gate results with explicit checked/passed/violation/error counts.

    OPSEC and Python-header checks include hidden, untracked and binary files,
    excluding Git metadata and bytecode caches. An unreadable input fails its
    gate without stopping the other checks. A nonrepository cannot pass.
    Recording ``checked`` and ``passed_count`` alongside ``violations`` and
    ``errors`` guarantees that 0 errors with 0 checks run is never
    indistinguishable from verified passing checks.
    """
    root = Path(root_dir) if root_dir is not None else Path(__file__).resolve().parent
    root = root.resolve()
    names = ("crlf", "opsec", "spdx", "graph_contract", "commit_subject", "epic_locks")
    gates = {
        name: {
            "passed": False,
            "status": "not_run",
            "checked": 0,
            "passed_count": 0,
            "violations": 0,
            "errors": 0,
        }
        for name in names
    }

    def git(*args):
        result = subprocess.run(["git", "-C", str(root), *args], check=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout

    tracked_bytes = {}
    is_repo_root = False
    try:
        # --show-prefix avoids comparing native paths with POSIX paths returned
        # by Git wrappers on Windows, while still rejecting nested directories.
        rev_lines = git("rev-parse", "--is-inside-work-tree", "--show-prefix").splitlines()
        if len(rev_lines) < 1 or rev_lines[0].strip() != b"true" or (len(rev_lines) > 1 and rev_lines[1].strip()):
            raise ValueError("not repository root")
        is_repo_root = True
        paths = git("ls-files", "-z").split(b"\0")
        for name in filter(None, paths):
            path = root / os.fsdecode(name)
            if path.is_symlink() or not path.resolve().is_relative_to(root):
                raise OSError("unsafe tracked path")
            raw = path.read_bytes()
            tracked_bytes[path] = raw
            gates["crlf"]["checked"] += 1
            if b"\r\n" in raw:
                gates["crlf"]["violations"] += 1
            else:
                gates["crlf"]["passed_count"] += 1
    except (OSError, ValueError, subprocess.SubprocessError):
        gates["crlf"]["errors"] += 1

    try:
        if not is_repo_root:
            rev_lines = git("rev-parse", "--is-inside-work-tree", "--show-prefix").splitlines()
            if len(rev_lines) < 1 or rev_lines[0].strip() != b"true" or (len(rev_lines) > 1 and rev_lines[1].strip()):
                raise ValueError("not repository root")
        head_info = git("log", "-1", "--format=%P%n%s").decode("utf-8").removesuffix("\n")
        parents_line, _, subject = head_info.partition("\n")
        parents = parents_line.strip().split()
        gates["commit_subject"]["checked"] += 1
        # Permit genuine multi-parent GitLab merge commits on default branches while keeping single-parent commits strict.
        if len(parents) >= 2 and subject.startswith("Merge branch "):
            gates["commit_subject"]["violations"] = 0
            gates["commit_subject"]["passed_count"] += 1
        else:
            is_valid_subject = validate_conventional_commit_subject(subject)
            gates["commit_subject"]["violations"] = int(not is_valid_subject)
            gates["commit_subject"]["passed_count"] += int(bool(is_valid_subject))
    except (OSError, ValueError, subprocess.SubprocessError):
        gates["commit_subject"]["errors"] += 1

    try:
        for path in _public_files(root):
            content = tracked_bytes.get(path)
            if content is None:
                content = path.read_bytes()
            relative = path.relative_to(root).as_posix().encode("utf-8")
            gates["opsec"]["checked"] += 1
            file_opsec_violations = _opsec_count(relative + b"\n" + content)
            if path.name == ".env" or (path.name.startswith(".env.") and path.name != ".env.example"):
                file_opsec_violations += 1
            # Reject live, company, enterprise, or personal Knowledge Graph files committed inside the tool repo.
            lowered_name = path.name.lower()
            if lowered_name in _FORBIDDEN_EXACT_GRAPH_FILENAMES or _FORBIDDEN_GRAPH_FILENAME.search(lowered_name):
                file_opsec_violations += 1
            gates["opsec"]["violations"] += file_opsec_violations
            if file_opsec_violations == 0:
                gates["opsec"]["passed_count"] += 1
            if path.suffix.lower() == ".py":
                gates["spdx"]["checked"] += 1
                lines = content.decode("utf-8-sig").splitlines()
                offset = int(bool(lines and lines[0].startswith("#!")))
                spdx_bad = len(lines) <= offset or lines[offset] != SPDX_HEADER
                gates["spdx"]["violations"] += int(spdx_bad)
                if not spdx_bad:
                    gates["spdx"]["passed_count"] += 1
    except (OSError, UnicodeError):
        gates["opsec"]["errors"] += 1
        gates["spdx"]["errors"] += 1

    try:
        catalog = json.loads((root / "sample-graph-data.json").read_text(encoding="utf-8"))
        gates["graph_contract"]["checked"] += 1
        violations = len(validate_spatial_graph_contract(catalog))
        # Ensure the checked-in demo fixture retains its generic Piece A role rather than being overwritten.
        if isinstance(catalog, dict) and catalog.get("piece_role") != _EXPECTED_DEMO_PIECE_ROLE:
            violations += 1
        gates["graph_contract"]["violations"] = violations
        if violations == 0:
            gates["graph_contract"]["passed_count"] += 1
    except (OSError, ValueError, RecursionError):
        gates["graph_contract"]["errors"] += 1

    try:
        epics = _manifest_epics(root)
        gates["epic_locks"]["checked"] += len(epics) if epics else 1
        valid = (len(epics) == 9 and {e["epic_id"] for e in epics}
                 == {f"EPIC-{index}" for index in range(1, 10)}
                 and verify_epic_lock_disjointness(epics))
        gates["epic_locks"]["violations"] = int(not valid)
        if valid:
            gates["epic_locks"]["passed_count"] = len(epics)
    except (OSError, ValueError):
        gates["epic_locks"]["errors"] += 1

    for gate in gates.values():
        gate["passed"] = gate["violations"] == gate["errors"] == 0
        if not gate["passed"]:
            gate["status"] = "failed"
        elif gate["checked"] > 0:
            gate["status"] = "verified_pass"
        else:
            gate["status"] = "no_applicable_inputs"

    gates_verified_pass = [name for name, g in gates.items() if g["status"] == "verified_pass"]
    gates_no_inputs = [name for name, g in gates.items() if g["status"] == "no_applicable_inputs"]
    gates_failed = [name for name, g in gates.items() if g["status"] == "failed"]
    return {
        "passed": all(gate["passed"] for gate in gates.values()),
        "summary": {
            "gates_total": len(gates),
            "gates_verified_pass": len(gates_verified_pass),
            "gates_no_applicable_inputs": len(gates_no_inputs),
            "gates_failed": len(gates_failed),
            "total_items_checked": sum(g["checked"] for g in gates.values()),
            "total_items_passed": sum(g["passed_count"] for g in gates.values()),
            "total_violations": sum(g["violations"] for g in gates.values()),
            "total_errors": sum(g["errors"] for g in gates.values()),
        },
        "gates": gates,
    }


if __name__ == "__main__":
    report = run_six_gate_prepush_audit()
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["passed"] else 1)
