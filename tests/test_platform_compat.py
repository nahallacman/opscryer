# SPDX-License-Identifier: Apache-2.0
"""Offline capability privacy checks and portable UTF-8/LF contracts."""

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import call, patch

import platform_compat as compat


class RuntimeCapabilitiesTests(unittest.TestCase):
    def test_capabilities_are_sanitized_for_windows_linux_and_macos(self):
        binaries = ("kubectl", "ollama", "codex", "git", "node")
        for os_name, expected, private_path in (
            ("nt", "windows", "C:\\Users\\private-user\\bin\\tool.exe"),
            ("posix", "posix", "/home/private-user/bin/tool"),
            ("posix", "posix", "/Users/private-user/bin/tool"),
        ):
            for utf8_mode in (0, 1):
                with self.subTest(os_name=os_name, utf8_mode=utf8_mode):
                    with patch.object(compat.os, "name", os_name), \
                         patch.object(compat.sys, "version_info", (3, 12, 7)), \
                         patch.object(compat.sys, "flags", SimpleNamespace(utf8_mode=utf8_mode)), \
                         patch.object(compat.shutil, "which", side_effect=[
                             private_path, None, private_path, None, private_path
                         ]) as which:
                        facts = compat.detect_runtime_capabilities()
                    self.assertEqual(facts, {
                        "python_version": "3.12.7",
                        "os_family": expected,
                        "utf8_mode": bool(utf8_mode),
                        "available_binaries": dict(zip(binaries, (True, False, True, False, True))),
                    })
                    self.assertEqual(which.call_args_list, [call(name) for name in binaries])
                    self.assertIs(type(facts["utf8_mode"]), bool)
                    for value in facts["available_binaries"].values():
                        self.assertIs(type(value), bool)
                    serialized = json.dumps(facts)
                    for private_value in (private_path, "private-user", "/", "\\"):
                        self.assertNotIn(private_value, serialized)


class Utf8FileTests(unittest.TestCase):
    def test_write_normalizes_line_endings_and_preserves_utf8(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unicode.txt"
            for content in ("caf\u00e9\r\n\u6771\u4eac\rfin\n", "", "no final newline"):
                with self.subTest(content=content):
                    expected = content.replace("\r\n", "\n").replace("\r", "\n")
                    compat.write_utf8_lf(path, content)
                    self.assertEqual(path.read_bytes(), expected.encode("utf-8"))
                    self.assertEqual(compat.read_utf8_text(path), expected)

    def test_read_normalizes_existing_crlf_cr_and_lf(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "existing.txt"
            path.write_bytes("caf\u00e9\r\n\u6771\u4eac\rfin\n".encode("utf-8"))
            self.assertEqual(compat.read_utf8_text(path), "caf\u00e9\n\u6771\u4eac\nfin\n")

    def test_read_rejects_invalid_utf8(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.txt"
            path.write_bytes(b"\xff")
            with self.assertRaises(UnicodeDecodeError):
                compat.read_utf8_text(path)


class CliTests(unittest.TestCase):
    def test_json_script_entrypoint(self):
        result = subprocess.run(
            [sys.executable, str(Path(compat.__file__)), "--json"],
            capture_output=True, text=True, encoding="utf-8", timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        facts = json.loads(result.stdout)
        expected = compat.detect_runtime_capabilities()
        # UTF-8 mode may differ when the parent was started with -X utf8.
        self.assertIs(type(facts.pop("utf8_mode")), bool)
        expected.pop("utf8_mode")
        self.assertEqual(facts, expected)

    def test_default_json_and_markdown_use_sanitized_facts(self):
        with patch.object(compat.shutil, "which", return_value=None):
            expected = compat.detect_runtime_capabilities()
            for args in ([], ["--json"], ["--markdown"]):
                with self.subTest(args=args):
                    output = io.StringIO()
                    with redirect_stdout(output):
                        self.assertEqual(compat.main(args), 0)
                    if args == ["--markdown"]:
                        self.assertIn("# Runtime compatibility", output.getvalue())
                        for name in expected["available_binaries"]:
                            self.assertIn(f"| {name} | False |", output.getvalue())
                    else:
                        self.assertEqual(json.loads(output.getvalue()), expected)


if __name__ == "__main__":
    unittest.main()
