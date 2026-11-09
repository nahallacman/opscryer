---
name: gitbash_windows
description: Git Bash on Windows
---

# AI SKILL: Git Bash on Windows
**Purpose:** Define the platform-specific standards for writing automation scripts using Git Bash (MinTTY) on Windows environments. This skill builds upon the generic `AI_SKILL_SCRIPT_PLANNING_AND_EXECUTION.md` rules.

## 1. Path Translation (Windows vs POSIX)
Git Bash on Windows uses a translation layer (MSYS2) to convert Unix-style paths (`/c/dev/infra-gitops`) to Windows-style paths (`<workspace>`) when interacting with native Windows executables (like `kubectl.exe` or `docker.exe`).
- **Rule:** When passing file paths as arguments to native Windows executables, always use Windows-style paths or ensure Git Bash accurately translates them by prefixing the command with `MSYS_NO_PATHCONV=1` if path mangling occurs.
- **Rule:** When navigating directories within the bash script itself using `cd`, `ls`, or `cat`, use POSIX-style paths (e.g., `/c/Users/`).

## 2. Terminal Emulation and Execution
Git Bash often runs using `MinTTY`, which does not behave like a standard Windows Console (`conhost.exe`).
- **Rule:** Some interactive Windows CLI tools (like `docker run -it` or AWS CLI prompts) will fail or hang in Git Bash because they cannot allocate a standard pseudo-terminal (PTY). Prefix these commands with `winpty` (e.g., `winpty docker run -it`).

## 3. Credential Prompting
To align with the generic credential masking rules, standard `read` commands must use the `-s` (silent) flag.
- **Rule:** Always use `read -s -p "Enter Secret: " SECRET_VAR` when asking the user for a PAT or password in Git Bash.

## 4. Error Handling and Logging
- **Rule:** Always include `set -euo pipefail` at the top of your scripts to ensure execution halts if any command fails, preventing silent cascading failures.
- **Rule:** Use standard ANSI escape codes for coloring output (e.g., `\e[36m` for Cyan, `\e[32m` for Green) using `echo -e`.
