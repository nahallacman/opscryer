---
name: zero_knowledge_secrets
description: Zero-Knowledge Secret Handling & Output Redirection
---

# AI Skill: Zero-Knowledge Secret Handling & Output Redirection

## Goal
To guarantee that sensitive credentials, unseal keys, tokens, and passwords are **never** accidentally ingested into an AI agent's context window or the local LLM conversation history.

## Context
When an AI agent runs a terminal command (e.g., generating an SSH key, initializing a Vault, or decoding a Kubernetes Secret), the `stdout` and `stderr` streams are automatically recorded in the `.system_generated/tasks/` logs. This means the AI "reads" the output, permanently baking the secret into the conversation history. This is a severe security vulnerability.

## Mandatory Rules for AI Agents

1. **Never Print Secrets to Stdout:**
   If a command generates or retrieves a secret, you **must not** let the command output to the terminal. You must pipe or redirect the output directly to a secure file.
   - **WRONG:** `kubectl get secret my-secret -o jsonpath='{.data.password}' | base64 --decode`
   - **CORRECT:** `kubectl get secret my-secret -o jsonpath='{.data.password}' | base64 --decode > scratch/decrypted-password.txt`

2. **Never Read Secret Files:**
   If you have successfully piped a secret to a file, **do not** use tools like `cat`, `view_file`, or `Get-Content` to read that file. Instruct the human user to open the file themselves.

3. **Background Task Masking:**
   When using background tasks to generate infrastructure that outputs keys (like `bao operator init`), always pipe the output to a file and tell the user where it is. If you must verify success, check the exit code of the command (`$?`) rather than parsing the text output.

4. **Testing Secure Systems:**
   When writing tests for secure systems (e.g., verifying a password works), inject the password into the test script via environment variables or file reads, and ensure the test script itself does not `print()` the variable to the console upon success or failure.

## Enforcement
Any agent found printing unencrypted secrets to the console will have its execution halted and the conversation history flagged for deletion.
