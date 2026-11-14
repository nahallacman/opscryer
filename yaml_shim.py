#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Pure-Python YAML 1.2 Loader Shim & Site-Packages Resolver (`scripts/devops/yaml_shim.py`).

Ensures all Kubernetes manifest and Grafana dashboard unit test suites (`test_game_servers_isolation`,
`test_hardware_cockpit_metrics`, `test_fleet_gitops_metrics`, `test_openzfs_storage_metrics`,
`test_node_stability_guard`, `test_agy_fleet`, `test_argus_sandbox_auditor`, `test_opscryer_post_merge_verifier`)
execute in `inline_docs_migration.py verify` even when the system Python interpreter (`C:\\msys64\\ucrt64`)
does not have C-extension `PyYAML` pre-installed.
"""

from __future__ import annotations

import json
import re
import sys
import types
from pathlib import Path
from typing import Any, Iterator

REPO_ROOT = Path(__file__).resolve().parents[2]


class YAMLError(Exception):
    """Standard YAML parsing error."""


def _parse_scalar(val: str) -> Any:
    s = val.strip()
    if not s:
        return None
    if not s.startswith(('"', "'")) and " #" in s:
        s = s.split(" #", 1)[0].strip()
    if (s.startswith('"') and s.endswith('"') and len(s) >= 2):
        inner = s[1:-1]
        return inner.replace('\\"', '"').replace("\\n", "\n").replace("\\\\", "\\")
    if (s.startswith("'") and s.endswith("'") and len(s) >= 2):
        return s[1:-1].replace("''", "'")
    low = s.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "~", "none"):
        return None
    if s == "{}":
        return {}
    if s == "[]":
        return []
    if (s.startswith("[") and not s.endswith("]")) or (s.startswith("{") and not s.endswith("}")):
        raise YAMLError(f"Unclosed YAML flow collection: {s!r}")
    if (s.startswith("[") and s.endswith("]")) or (s.startswith("{") and s.endswith("}")):
        try:
            return json.loads(s)
        except Exception as exc:
            if s.startswith("[") and s.endswith("]") and "{" not in s and "}" not in s:
                items = [x.strip() for x in s[1:-1].split(",") if x.strip()]
                return [_parse_scalar(x) for x in items]
            raise YAMLError(f"Malformed YAML flow collection: {s!r}") from exc
    if re.match(r"^-?\d+$", s):
        try:
            return int(s)
        except ValueError:
            pass
    if re.match(r"^-?\d+\.\d+$", s):
        try:
            return float(s)
        except ValueError:
            pass
    return s


def _preprocess_lines(text: str) -> list[tuple[int, str]]:
    """Return list of `(indent, stripped_line)` preserving block scalar lines via raw line indexing."""
    raw_lines = text.splitlines()
    out: list[tuple[int, str]] = []
    i = 0
    n = len(raw_lines)
    while i < n:
        line = raw_lines[i]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        indent = len(line) - len(line.lstrip(" "))
        # Check if this line starts a block scalar (`|`, `|-`, `>`, `>-`) on a key or list item
        if re.search(r"(:|-)\s*(\|-|\||>-|>)\s*$", stripped):
            sep_char = ":" if re.search(r":\s*(\|-|\||>-|>)\s*$", stripped) else "-"
            key_part, _, indicator = stripped.rpartition(sep_char)
            indicator = indicator.strip()
            i += 1
            block_lines: list[tuple[int, str]] = []
            block_indent: int | None = None
            while i < n:
                bline = raw_lines[i]
                if not bline.strip():
                    block_lines.append((block_indent or (indent + 2), ""))
                    i += 1
                    continue
                bind = len(bline) - len(bline.lstrip(" "))
                if bind <= indent:
                    break
                if block_indent is None:
                    block_indent = bind
                content_slice = bline[block_indent:] if len(bline) >= block_indent else bline.lstrip(" ")
                block_lines.append((bind, content_slice))
                i += 1
            joined = ("\n" if indicator.startswith("|") else " ").join(c for _, c in block_lines)
            if indicator.endswith("-"):
                joined = joined.rstrip("\n")
            elif block_lines:
                joined = joined + "\n"
            encoded_json = json.dumps(joined)
            if sep_char == "-":
                out.append((indent, f"- {encoded_json}"))
            else:
                out.append((indent, f"{key_part}: {encoded_json}"))
            continue
        out.append((indent, stripped))
        i += 1
    return out


def _parse_block(lines: list[tuple[int, str]], idx: int, min_indent: int) -> tuple[Any, int]:
    if idx >= len(lines):
        return None, idx
    first_indent, first_text = lines[idx]
    if first_indent < min_indent:
        return None, idx

    if first_text.startswith("- ") or first_text == "-":
        arr: list[Any] = []
        list_indent = first_indent
        while idx < len(lines):
            cur_indent, cur_text = lines[idx]
            if cur_indent < list_indent:
                break
            if cur_indent > list_indent or not (cur_text.startswith("- ") or cur_text == "-"):
                break
            rest = cur_text[1:].strip() if cur_text.startswith("-") else ""
            idx += 1
            if not rest:
                sub_val, idx = _parse_block(lines, idx, list_indent + 1)
                arr.append(sub_val)
            elif ":" in rest and not rest.startswith(('"', "'")):
                # Inline mapping item inside a list (`- name: foo`)
                k, _, v = rest.partition(":")
                item_dict: dict[str, Any] = {}
                key = _parse_scalar(k)
                v_str = v.strip()
                if v_str:
                    item_dict[str(key)] = _parse_scalar(v_str)
                else:
                    sub_val, idx = _parse_block(lines, idx, list_indent + 1)
                    item_dict[str(key)] = sub_val
                # Consume subsequent keys indented deeper than `list_indent`
                while idx < len(lines):
                    nxt_indent, nxt_text = lines[idx]
                    if nxt_indent <= list_indent:
                        break
                    if nxt_text.startswith("- ") or nxt_text == "-":
                        break
                    if ":" in nxt_text:
                        nk, _, nv = nxt_text.partition(":")
                        nkey = str(_parse_scalar(nk))
                        nv_str = nv.strip()
                        idx += 1
                        if nv_str:
                            item_dict[nkey] = _parse_scalar(nv_str)
                        else:
                            if idx < len(lines):
                                sub_indent, sub_text = lines[idx]
                                if sub_indent > nxt_indent or (
                                    sub_indent == nxt_indent
                                    and (sub_text.startswith("- ") or sub_text == "-")
                                ):
                                    sub_val, idx = _parse_block(lines, idx, sub_indent)
                                    item_dict[nkey] = sub_val
                                else:
                                    item_dict[nkey] = None
                            else:
                                item_dict[nkey] = None
                    else:
                        idx += 1
                arr.append(item_dict)
            else:
                arr.append(_parse_scalar(rest))
        return arr, idx

    mapping: dict[str, Any] = {}
    map_indent = first_indent
    while idx < len(lines):
        cur_indent, cur_text = lines[idx]
        if cur_indent < map_indent:
            break
        if cur_indent > map_indent:
            # Unexpected extra indentation; skip or attach
            idx += 1
            continue
        if cur_text.startswith("- ") or cur_text == "-":
            break
        if ":" not in cur_text:
            idx += 1
            continue
        k, _, v = cur_text.partition(":")
        key = str(_parse_scalar(k))
        v_str = v.strip()
        idx += 1
        if v_str:
            mapping[key] = _parse_scalar(v_str)
        else:
            if idx < len(lines) and lines[idx][0] >= map_indent:
                # Note: in YAML, sequence items under a mapping key can be at the same indent as the key (`map_indent`)
                nxt_indent, nxt_text = lines[idx]
                if nxt_indent > map_indent or (
                    nxt_indent == map_indent and (nxt_text.startswith("- ") or nxt_text == "-")
                ):
                    sub_val, idx = _parse_block(lines, idx, nxt_indent)
                    mapping[key] = sub_val
                else:
                    mapping[key] = None
            else:
                mapping[key] = None
    return mapping, idx


def safe_load(stream: Any) -> Any:
    """Parse a single YAML document from a string or file-like object."""
    docs = list(safe_load_all(stream))
    return docs[0] if docs else None


def safe_load_all(stream: Any) -> Iterator[Any]:
    """Parse all YAML documents separated by `---` from a string or file-like object."""
    text = stream.read() if hasattr(stream, "read") else str(stream)
    raw_docs = re.split(r"(?m)^---\s*$", text)
    for doc_str in raw_docs:
        stripped_doc = doc_str.strip()
        if not stripped_doc:
            continue
        non_comment_lines = [
            ln for ln in stripped_doc.splitlines() if ln.strip() and not ln.strip().startswith("#")
        ]
        if not non_comment_lines:
            continue
        first_char = non_comment_lines[0].lstrip()[0]
        if first_char in ("{", "["):
            try:
                yield json.loads("\n".join(non_comment_lines))
                continue
            except Exception as exc:
                raise YAMLError(f"Invalid JSON/flow YAML document: {exc}") from exc
        lines = _preprocess_lines(doc_str)
        if not lines:
            continue
        parsed, _ = _parse_block(lines, 0, lines[0][0])
        yield parsed


def safe_dump(data: Any, stream: Any = None, **kwargs: Any) -> str:
    """Serialize data as YAML-compatible JSON."""
    rendered = json.dumps(data, indent=2) + "\n"
    if stream is not None and hasattr(stream, "write"):
        stream.write(rendered)
    return rendered


def ensure_yaml_module_registered() -> str:
    """
    Ensure `import yaml` succeeds by checking native `yaml` first, searching local
    virtualenv site-packages second, and registering this pure-Python `yaml_shim` third.
    """
    try:
        import yaml  # noqa: F401
        return "native_pyyaml"
    except ModuleNotFoundError:
        pass

    candidate_roots = [
        REPO_ROOT / ".venv",
        Path.home() / "AppData" / "Local" / "Programs" / "Python",
        Path.home() / "AppData" / "Roaming" / "Python",
    ]
    for root in candidate_roots:
        if not root.exists():
            continue
        for init_py in root.rglob("site-packages/yaml/__init__.py"):
            sp = str(init_py.parent.parent)
            if sp not in sys.path:
                sys.path.insert(0, sp)
            try:
                import yaml  # noqa: F401
                return f"site_packages:{sp}"
            except Exception:
                sys.path.remove(sp)

    mod = types.ModuleType("yaml")
    mod.YAMLError = YAMLError  # type: ignore[attr-defined]
    mod.safe_load = safe_load  # type: ignore[attr-defined]
    mod.safe_load_all = safe_load_all  # type: ignore[attr-defined]
    mod.load = safe_load  # type: ignore[attr-defined]
    mod.dump = safe_dump  # type: ignore[attr-defined]
    mod.safe_dump = safe_dump  # type: ignore[attr-defined]
    sys.modules["yaml"] = mod
    return "pure_python_yaml_shim"


def ensure_yaml_module() -> Any:
    """Register `yaml` if needed and return the imported `yaml` module object."""
    ensure_yaml_module_registered()
    import yaml

    return yaml
