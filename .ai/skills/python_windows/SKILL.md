---
name: python_windows
description: Python Environment Execution (Windows)
---

# AI Skill: Python Environment Execution (Windows)

## Context
When operating on this local Windows machine (`nahal` user), multiple Python installations exist (MSYS2 vs Windows Store). This causes a severe token burn and execution loop when AI agents attempt to run native `python`, `pip`, or `pytest` commands, as the system paths and module availability are inconsistent.

## Core Rules

1. **Do NOT rely on the default `python` or `pip` aliases.** 
   The default `python` command resolves to the MSYS2 environment (`C:\msys64\ucrt64\bin\python.exe`), which does *not* have `pip` installed and lacks standard Windows site-packages.

2. **Use the Exact Windows App Path:**
   To execute python scripts or use pip, you MUST use the fully qualified path to the Windows Store Python executable:
   ```powershell
   C:\Users\nahal\AppData\Local\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\python.exe
   ```

3. **Running PyTest:**
   Because `pytest` isn't globally exported to the PATH correctly, you must install dependencies explicitly to the Windows Python instance and run pytest via the module invocation natively.
   ```powershell
   # Install dependencies
   C:\Users\nahal\AppData\Local\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\python.exe -m pip install pytest pytest-testinfra pyyaml requests

   # Run PyTest
   C:\Users\nahal\AppData\Local\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\python.exe -m pytest <workspace>\tests -v
   ```

4. **Running Standalone Test Scripts:**
   Some tests are written to be executed as standalone scripts rather than pytest plugins (e.g., parsing args inside `if __name__ == "__main__":`). Run these natively with the full python path:
   ```powershell
   C:\Users\nahal\AppData\Local\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\python.exe <workspace>\tests\test_devcontainer_isolation.py
   ```

## Pre-Flight Check
Before running any Python-based validation suites in the cluster directory, ensure you have actively reviewed the dependencies required by those scripts (e.g., `pyyaml` for `test_pvc_stability.py`) and verified they are installed in the Windows Store Python environment.
