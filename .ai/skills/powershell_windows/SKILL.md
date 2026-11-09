---
name: powershell_windows
description: PowerShell on Windows
---

# AI SKILL: PowerShell on Windows
**Purpose:** Define the platform-specific standards for writing automation scripts using PowerShell (versions 5.1 and above) on Windows environments. This skill builds upon the generic `AI_SKILL_SCRIPT_PLANNING_AND_EXECUTION.md` rules.

## 1. Network & TLS Enforcement
Older versions of Windows PowerShell default to deprecated TLS versions (TLS 1.0/1.1), which will instantly fail when connecting to modern APIs like GitHub or external endpoints.
- **Rule:** Always enforce TLS 1.2 at the absolute top of any script that makes external network requests:
  ```powershell
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  ```
- **Rule:** Avoid global SSL certificate validation overrides (`ServerCertificateValidationCallback = {$true}`) unless absolutely necessary. Because this setting modifies the `.NET` AppDomain, it persists in the user's terminal window even after the script finishes, frequently breaking subsequent secure requests.

## 2. Error Handling & Try/Catch
PowerShell cmdlets (especially `Invoke-RestMethod` or `Invoke-WebRequest`) often emit non-terminating errors by default, which means `try/catch` blocks will fail to catch them.
- **Rule:** When calling critical cmdlets inside a `try` block, you MUST append `-ErrorAction Stop` to force the exception to terminate into the `catch` block.
- **Rule:** Use `$_.Exception.Message` to extract the human-readable error from the catch block to present to the user.

## 3. Credential Prompting
When prompting a user for a password, PAT, or API key, ensure the characters do not echo to the terminal (preventing leakage into terminal history logs).
- **Rule:** Always use `Read-Host` with the `-AsSecureString` flag.
- **Rule:** Since most REST APIs require plaintext strings for headers, immediately decrypt it back to a standard string variable in memory using the proper .NET interop:
  ```powershell
  $SecureVar = Read-Host "Enter Secret" -AsSecureString
  $PlainVar = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureVar))
  ```

## 4. Logging UX
To separate script UI/logging from actual data pipeline output, avoid `Write-Output`.
- **Rule:** Use `Write-Host` for all user-facing logging.
- **Rule:** Use `-ForegroundColor` to adhere to the generic color standards defined in the `SCRIPT_PLANNING_AND_EXECUTION` skill.
