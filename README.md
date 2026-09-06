# rdpRegInfo

![Alt text](./logo-wordmark.svg)

A PowerShell script that collects Remote Desktop (RDP) connection history and
related artifacts for the current user - or, optionally, every local user
profile on the machine - and merges them into a single, exportable result set.


> [!WARNING]
> *    **Work in Progress (WIP):** This is an experimental project and is actively being updated. Breaking changes may occur, and you should test the code thoroughly before using it in any critical applications.
>  *   Additionally, this codebase was built with AI assistance, which means you might encounter unintended behavior or inaccuracies.
> I am actively looking to improve this repository, and your feedback is invaluable. You can help by:
> *   **Reporting bugs:** If you find a mistake, please open an Issue with a brief description of the problem.
> *   **Suggesting improvements:** Feel free to submit a Pull Request with fixes or optimizations.

## What it collects

| Source | Details |
|---|---|
| `HKCU:\Software\Microsoft\Terminal Server Client\Servers\*` | One subkey per host ever connected to (e.g. `UsernameHint`). |
| `HKCU:\Software\Microsoft\Terminal Server Client\Default` | The `MRU0`, `MRU1`, ... list of recently typed targets, including ones never saved as a `Servers` entry. |
| Registry key `LastWriteTime` | Read via a small P/Invoke helper, used as an approximate "last seen" timestamp for each entry above. |
| `cmdkey /list` | Cross-referenced against `TERMSRV/<host>` targets to flag which hosts have a saved credential. |
| `Microsoft-Windows-TerminalServices-RDPClient/Operational` event log | Actual connection timestamps and counts, when the log is available. |
| Saved `.rdp` files (`-IncludeRdpFiles`) | Desktop/Documents/Downloads are scanned for `full address:s:` / `username:s:` values. |
| Other user profiles (`-AllUsers`) | Loads each profile's `NTUSER.DAT` read-only (if not already loaded), scans it, then always unloads it. |

Everything is read-only against the local machine's own registry and files -
nothing is modified, and any hive the script loads itself is unloaded when
it's done, even on error.

## Usage

```powershell
# Basic run - current user only, printed to the console
.\rdpRegInfo.ps1

# Include saved .rdp connection files, export to CSV
.\rdpRegInfo.ps1 -IncludeRdpFiles -ExportCsv .\rdp_history.csv

# All local user profiles (needs an elevated/Administrator shell), export to JSON
.\rdpRegInfo.ps1 -AllUsers -ExportJson .\rdp_history.json -Quiet
```

See `Get-Help .\rdpRegInfo.ps1 -Full` for every parameter, including
`-SkipCredentialCheck`, `-SkipEventLog`, and `-MaxEvents`.

The script also returns its results to the pipeline as objects, so you can
filter or reshape them directly, e.g.:

```powershell
.\rdpRegInfo.ps1 -Quiet | Where-Object HasSavedCredential | Format-Table Host, User, SavedCredentialUser
```

## Requirements

- Windows PowerShell 5.1+ or PowerShell 7+
- Administrator privileges only for `-AllUsers`

## Use cases

- Auditing which RDP targets a user (or all users) has connected to
- Identifying hosts with saved credentials that could enable lateral movement
- Incident response / forensic triage of Remote Desktop activity

This script only reads data that is already local to the machine it runs on;
use it against systems and accounts you're authorized to inspect.
