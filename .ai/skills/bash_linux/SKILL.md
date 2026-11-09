---
name: bash_linux
description: Bash on Linux
---

# AI SKILL: Bash on Linux
**Purpose:** Define the platform-specific standards for writing automation scripts using native Bash on Linux environments (such as Kubernetes Nodes, Ubuntu VMs, or Raspberry Pis). This skill builds upon the generic `AI_SKILL_SCRIPT_PLANNING_AND_EXECUTION.md` rules.

## 1. Strict Error Handling (Fail-Fast)
Unlike interactive shells, automation scripts must halt immediately upon failure to prevent cascading destruction.
- **Rule:** Every bash script must start with the following strict mode header:
  ```bash
  #!/bin/bash
  set -euo pipefail
  ```
  - `-e`: Exit immediately if a command exits with a non-zero status.
  - `-u`: Treat unset variables as an error when substituting.
  - `-o pipefail`: The return value of a pipeline is the status of the last command to exit with a non-zero status.

## 2. Command Existence Validation
Scripts must not assume that necessary CLI binaries (`jq`, `curl`, `kubectl`, etc.) are installed on the host Linux system.
- **Rule:** Before executing any logic, the script must verify that all required dependencies exist using `command -v`:
  ```bash
  if ! command -v jq &> /dev/null; then
      echo -e "\e[31mError: jq is required but not installed.\e[0m"
      exit 1
  fi
  ```

## 3. Standard Logging and Sub-Shells
When capturing the output of a command into a variable while simultaneously logging to the user, ensure `stderr` is not swallowed.
- **Rule:** Avoid suppressing `stderr` unconditionally (e.g., `2>/dev/null`) unless explicitly expected.
- **Rule:** Use standard ANSI color codes for `echo` statements to align with generic UX standards:
  - `echo -e "\e[36m[INFO] ...\e[0m"` (Cyan for headers)
  - `echo -e "\e[32m[SUCCESS] ...\e[0m"` (Green for success)
  - `echo -e "\e[31m[ERROR] ...\e[0m"` (Red for failure)

## 4. Temporary Files and Cleanup
When scripts require temporary files for JSON parsing or downloading binaries, do not leave garbage in `/tmp`.
- **Rule:** Use `mktemp` to generate secure, unique temporary files or directories.
- **Rule:** Use `trap` to ensure temporary resources are cleaned up regardless of whether the script succeeds or fails:
  ```bash
  TEMP_DIR=$(mktemp -d)
  trap 'rm -rf -- "$TEMP_DIR"' EXIT
  ```
