# PowerSCAP

![PowerShell](https://img.shields.io/badge/PowerShell-7.0+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)
![Status](https://img.shields.io/badge/Status-Beta-yellow.svg)
![Version](https://img.shields.io/badge/Version-2.2.0-informational.svg)

**PowerSCAP** is a modular PowerShell implementation of a Windows **SCAP / OVAL compliance evaluator** with SQL Server STIG scanning support.

This repository represents a **complete rewrite of PowerSCAP v1**. Version 1 was a single, monolithic script; version 2 is a **proper PowerShell module** with a clear public API, private helper layers, and a structure designed to grow into larger automation toolchains.

> ⚠️ **BETA WARNING**
>
> PowerSCAP v2 is **early beta** and **lightly tested**. Testing to date has been limited to **local execution on Windows 11 and Windows Server 2019**. Remote scanning and SQL Server scanning have not been tested against production environments. Expect bugs, incomplete coverage, and breaking changes.

---

## Why PowerSCAP Exists

Most Windows SCAP tooling is:
- Heavyweight
- Closed-source
- Difficult to automate
- Tightly coupled to GUIs or external executables

PowerSCAP's goals are intentionally different:

- 🪶 **Lightweight** — pure PowerShell, no additional executables required
- 📦 **Portable** — easy to drop into scripts and automation pipelines
- 🧩 **Composable** — designed to be embedded in larger PowerShell toolsets
- 🔍 **Transparent** — compliance logic is readable and auditable

This project focuses on **evaluating OVAL definitions** from SCAP 1.3 data streams, with a strong emphasis on Windows security baselines (notably DISA STIGs). Version 2.2 extends this to **SQL Server STIG manual check guides**, extracting and executing embedded T-SQL checks directly.

---

## Project Status

- **Rewrite Status**: Complete (v2 architecture)
- **Current Version**: 2.2.0
- **Test Coverage**: Minimal
- **Production Readiness**: ❌ Not production-ready

If you are looking for a battle‑tested compliance scanner, this is **not** it (yet). If you are interested in **automation, experimentation, or extending SCAP logic in PowerShell**, this project may be useful.

---

## Module Layout

```text
PowerSCAP/
├── PowerSCAP.psd1            # Module manifest
├── PowerSCAP.psm1            # Module entry point
│
├── Public/                   # Public commands (exported)
│   ├── Scan-Computer.ps1
│   ├── Scan-Domain.ps1
│   ├── Scan-Database.ps1
│   ├── Scan-SQLInstance.ps1  # NEW in 2.2.0
│   └── Scan-SQLDatabase.ps1  # NEW in 2.2.0
│
├── Private/                  # Internal helpers (not exported)
│   ├── XmlHelpers.ps1
│   ├── OvalCore.ps1
│   ├── Criteria.ps1
│   ├── TestEvaluators.ps1
│   ├── RegistryAndWmi.ps1
│   ├── AuditHelpers.ps1
│   ├── LocalAccounts.ps1
│   ├── Output.ps1
│   └── SqlHelpers.ps1        # NEW in 2.2.0
```

Only the commands in **`Public/`** are part of the supported interface. Everything under **`Private/`** may change without notice.

---

## Requirements

- **Operating System**: Windows (for `Scan-Computer`); any OS with PowerShell 7 and network access to a SQL Server (for `Scan-SQLInstance` / `Scan-SQLDatabase`)
- **PowerShell**: **7.0 or later**
- **Privileges**: Administrator (required for many local checks; `sysadmin` or equivalent recommended for SQL Server checks)
- **SCAP Content**: SCAP 1.3 data streams for Windows checks; XCCDF manual check guides for SQL Server checks (e.g. DISA STIG SCAP bundles)

---

## Installation

### Manual Import (Current Recommended Method)

```powershell
# Clone or extract the repository
Import-Module .\PowerSCAP -Force

# Verify commands
Get-Command -Module PowerSCAP
```

PowerSCAP is not yet published to the PowerShell Gallery.

---

## Public Commands

### `Scan-Computer`

Runs a SCAP / OVAL evaluation against **the local or a remote Windows system**.

```powershell
# Local scan
Scan-Computer -ScapFile 'C:\SCAP\Windows_Server_2019_STIG.xml'

# Remote scan (see Remote Scanning Limitations below)
$cred = Get-Credential
Scan-Computer -ScapFile 'C:\SCAP\Windows_Server_2019_STIG.xml' -ComputerName SERVER01 -Credential $cred
```

Typical use cases:
- Local compliance checks
- Scheduled scans
- Integration with remediation scripts

---

### `Scan-SQLInstance`

Runs a DISA STIG compliance scan against a **SQL Server instance** using an XCCDF manual check guide. Extracts embedded T-SQL from each rule's check-content, executes it against the instance, and heuristically evaluates pass/fail based on the documented criteria in the check text.

```powershell
# Scan local default instance with integrated auth
Scan-SQLInstance -ScapFile '.\U_MS_SQL_Server_2016_Instance_STIG_V3R6_Manual-xccdf.xml'

# Scan remote instance with SQL auth, JSON output
$cred = Get-Credential "sa"
Scan-SQLInstance -ScapFile '.\Instance_STIG.xml' -ComputerName "DBSERVER01\SQLEXPRESS" -Credential $cred -OutputJson

# Scan with an explicit connection string
Scan-SQLInstance -ScapFile '.\Instance_STIG.xml' -ConnectionString "Server=DBSERVER01;Database=master;Integrated Security=true;Encrypt=true;"
```

Connects to the `master` database and runs all instance-level checks from there.

---

### `Scan-SQLDatabase`

Runs a DISA STIG compliance scan against a **specific database** on a SQL Server instance. Works the same as `Scan-SQLInstance` but opens two connections internally: one to the target database and one to `master`. Queries are automatically routed to the correct connection based on whether they reference instance-level catalog views (e.g. `sys.server_principals`, `sys.databases`) or database-level views (e.g. `sys.database_principals`, `sys.schemas`).

```powershell
# Scan a specific database on the local instance
Scan-SQLDatabase -ScapFile '.\U_MS_SQL_Server_2016_Database_STIG_V3R4_Manual-xccdf.xml' -Database "MyAppDB"

# Scan a remote database with SQL auth, JSON output
$cred = Get-Credential "dbadmin"
Scan-SQLDatabase -ScapFile '.\Database_STIG.xml' -ComputerName "DBSERVER01" -Database "Production" -Credential $cred -OutputJson

# Scan with an explicit connection string (Database= appended automatically if missing)
Scan-SQLDatabase -ScapFile '.\Database_STIG.xml' -Database "MyDB" -ConnectionString "Server=DBSERVER01;Integrated Security=true;"
```

Evidence output labels each query result with its execution context (`[master]` or `[DatabaseName]`) so it is clear which connection was used.

---

### `Scan-Domain`

Intended entry point for **domain‑scoped** or directory‑aware checks.

> ⚠️ This command currently provides scaffolding and structure, not a finalized workflow.

```powershell
Scan-Domain -ScapFile 'C:\SCAP\Domain_STIG.xml'
```

---

### `Scan-Database`

Intended entry point for **database‑backed result storage or processing**.

> ⚠️ This command currently provides scaffolding and structure, not a finalized workflow.

```powershell
Scan-Database -ScapFile 'C:\SCAP\Windows_STIG.xml'
```

---

## Remote Scanning Limitations

`Scan-Computer` supports a `-ComputerName` parameter for remote scanning via CIM sessions. Coverage is good but not complete. The following checks work fully over CIM:

- Registry reads (via `StdRegProv`)
- Registry key existence checks (via `StdRegProv EnumKey`)
- WMI / CIM queries
- File existence, size, and version (via `Win32_File`)
- Service state and start mode (via `Win32_Service`)
- Process enumeration (via `Win32_Process`)
- Local group membership (via `Win32_Group` / `Get-CimAssociatedInstance`)

The following checks **cannot** be performed remotely over a standard CIM session and will return an indeterminate result when `-ComputerName` is used:

- **File ACLs** — fine-grained ACL enumeration is not available via CIM. The file's existence is confirmed but rights cannot be evaluated.
- **Audit policy subcategories** — requires execution of `auditpol.exe` on the target.
- **Access token privileges** — requires execution of `secedit.exe` on the target.
- **Account lockout policy** — requires execution of `secedit.exe` on the target.

These checks are clearly flagged in output rather than silently skipped or run against the local machine by mistake.

---

## SQL Server STIG Scanning — Design Notes

### Why XCCDF instead of OVAL

DISA's SQL Server STIGs ship as **manual check guides** (`*Manual-xccdf.xml`), not as automated OVAL data streams. The check procedures are procedural text with embedded T-SQL, not machine-structured OVAL definitions. `Scan-SQLInstance` and `Scan-SQLDatabase` parse this procedural text directly, extracting executable SQL statements and running them against the target.

### Query extraction

The T-SQL extractor (`Extract-SqlQueries` in `SqlHelpers.ps1`) walks the check-content text line by line looking for SQL statement starters (`SELECT`, `WITH`, `EXEC`, `USE`, `IF...BEGIN`). It accumulates continuation lines until it hits a terminator — an empty line, or a line beginning with prose keywords like `If`, `Note`, `Review`, `Otherwise`. Trailing `GO` statements are stripped. Lines that are clearly instructional rather than executable are filtered out.

### Heuristic pass/fail evaluation

STIG checks follow predictable patterns in their documented criteria. The evaluator reads the check-content for these patterns and determines the expected outcome:

- *"If no [X] returned, this is not a finding"* — rows returned means FAIL; no rows means PASS.
- *"If [X] returned, this is a finding"* — rows returned means FAIL; no rows means PASS.
- *"If no [X] returned, this is a finding"* — no rows means FAIL; rows means PASS.
- Fallback: any occurrence of *"this is a finding"* without a clear row-count qualifier defaults to treating rows as a finding.

When the heuristic cannot determine the expected outcome, the check is marked **Manual Review Required** and the raw query results are included in the evidence output for human evaluation.

### Dual-connection routing

`Scan-SQLDatabase` opens two connections: one to the target database and one to `master`. Each query is inspected before execution and routed to the appropriate connection based on whether it references instance-level catalog views. The routing table covers `sys.server_principals`, `sys.server_permissions`, `sys.server_role_members`, `sys.databases`, `sys.server_audits`, `sys.configurations`, `sys.dm_server_*`, `sys.linked_logins`, `sys.credentials`, `sys.endpoints`, `sys.sql_logins`, `sp_configure`, and queries prefixed with `master.`. Everything else routes to the target database. If the `master` connection fails to open, instance-level queries run in the database context with a warning.

---

## SCAP / OVAL Support

PowerSCAP evaluates **OVAL definitions** inside SCAP 1.3 data streams and supports:

- Nested criteria (`AND`, `OR`, `NOT`)
- Variable resolution
- Registry checks
- WMI / CIM queries
- File and service checks
- Process and hotfix checks
- Audit policy parsing
- Local account and SID resolution
- AccessToken privilege evaluation with regex-based principal matching
- Severity extraction from XCCDF Benchmarks

Coverage is expanding, but **not all OVAL test types are implemented**, and some implementations are incomplete.

---

## What's New in 2.2.0

Version 2.2.0 adds SQL Server STIG compliance scanning and fixes remote scanning in `Scan-Computer`. Everything is new code or reworked existing code; no previously working local-scan behavior was changed.

### Remote scanning fixes — `Scan-Computer`

Eleven bugs were fixed across `RegistryAndWmi.ps1`, `TestEvaluators.ps1`, and `LocalAccounts.ps1`. Every one of these was a case where the remote code path either did not exist or silently fell through to a local-only implementation, meaning `-ComputerName` appeared to work but was actually scanning the local machine.

**Registry reads.** `Get-RegistryItemProperty` used `[Microsoft.Win32.RegistryKey]::OpenBaseKey`, which is a local-only .NET API. The remote path was rewritten to use `StdRegProv` via the CIM session. It tries each typed getter (`GetStringValue`, `GetDWordValue`, `GetBinaryValue`, `GetMultiStringValue`, `GetExpandStringValue`) in order and returns the first successful result.

**Registry key existence.** `Evaluate-RegistryTest` used `Test-Path` to check whether a registry key existed before reading values. The remote path now uses `StdRegProv`'s `EnumKey` method; a return value of 0 confirms the key exists.

**Service checks.** `Evaluate-ServiceTest` called `Get-Service` (local-only) and then `Get-CimInstance` without passing the CIM session. Both calls now use `Get-CimInstance Win32_Service` with the CIM session splatted in.

**Process checks.** `Evaluate-ProcessTest` called `Get-CimInstance Win32_Process` without the CIM session. Fixed by splatting `$script:CimSession` into the call.

**File checks.** `Evaluate-FileTest` used `Test-Path` and `Get-Item` (both local-only). The remote path now queries `Win32_File` via CIM, with backslashes properly escaped in the WQL filter, and retrieves `Size` and `Version` from the returned object.

**File ACL checks.** `Evaluate-FileEffectiveRights53Test` used `Get-Acl`, which is local-only. Fine-grained ACL enumeration is not available via standard CIM. The remote path now confirms file existence via `Win32_File` but returns an indeterminate result for the rights evaluation rather than silently running against the local filesystem.

**Audit policy checks.** `Evaluate-AuditEventPolicySubcategoriesTest` called into `AuditHelpers`, which runs `auditpol.exe`. This cannot execute on a remote machine via CIM. Returns indeterminate when a CIM session is active.

**Access token checks.** `Evaluate-AccessTokenTest` called `secedit.exe` via the local helper. Returns indeterminate when a CIM session is active.

**Lockout policy checks.** `Evaluate-LockoutPolicyTest` called `Get-SystemAccessPolicy`, which runs `secedit.exe`. Returns indeterminate when a CIM session is active.

**Group membership enumeration.** `Evaluate-GroupTest` called `Get-CimInstance Win32_Group` without the CIM session. Fixed by splatting `$script:CimSession`.

**Local group member listing.** `Get-LocalGroupMembers` in `LocalAccounts.ps1` used `Get-LocalGroupMember` and the ADSI `WinNT://` provider, both of which are local-only. The remote path now uses `Get-CimAssociatedInstance` on the `Win32_Group` object to retrieve `Win32_UserAccount` and nested `Win32_Group` members across the CIM session.

### SQL Server STIG scanning — new commands and helpers

Three files were added. `SqlHelpers.ps1` is the shared private engine; `Scan-SQLInstance.ps1` and `Scan-SQLDatabase.ps1` are the public commands.

**`SqlHelpers.ps1`** provides five functions. `Build-SqlConnection` constructs and opens a `System.Data.SqlClient.SqlConnection` from either a full connection string or individual components (`ComputerName`, `Credential`, `Database`). `Invoke-SqlQuery` executes a query and returns rows as an array of `PSCustomObject`s via `SqlDataReader`, setting `$script:SqlQueryError` on failure. `Extract-SqlQueries` parses procedural XCCDF check-content text and pulls out executable T-SQL statements. `Parse-XccdfRules` loads an XCCDF Benchmark XML and returns structured rule objects containing the rule ID, severity, title, check-content, and pre-extracted SQL queries. `Evaluate-SqlRule` runs those queries against a connection and applies the heuristic pass/fail logic described in the Design Notes section above.

**`Scan-SQLInstance`** connects to `master` and evaluates every rule in an instance-level XCCDF benchmark. It accepts `-ComputerName` / `-Credential` or a full `-ConnectionString`, supports `-OutputJson` for machine-readable output, and shows a color-coded summary table with detailed failure evidence including the executed queries and returned rows.

**`Scan-SQLDatabase`** works identically but adds a `-Database` parameter and the dual-connection routing described in the Design Notes section. Evidence output labels each query with its execution context so instance-level and database-level checks are distinguishable in the results.

---

## What's New in 2.1.0

Version 2.1.0 adds XCCDF severity support across all output formats and substantially overhauls AccessToken test evaluation and display. Everything below was developed and verified against the DISA Windows 11 STIG V2R7 SCAP bundle.

### XCCDF Severity Parsing — `Scan-Computer.ps1`

Severity was previously pulled only from OVAL definition metadata, which is unreliable and frequently missing. The authoritative source is the XCCDF Benchmark component of the SCAP data stream, where each `<Rule>` carries a `severity` attribute.

`Scan-Computer` now parses the XCCDF Benchmark at startup, extracts every Rule's severity, and builds a lookup table that maps OVAL definition IDs to their severity. This lookup is used as the primary source; OVAL metadata remains as a last-resort fallback.

Three bugs had to be resolved to get this working:

**StrictMode crash on XCCDF node access.** `Select-XmlNodes` can return a single `XmlNode` rather than an array when only one Benchmark is present. Under `Set-StrictMode -Version Latest`, calling `.Count` or indexing directly on that node throws a terminating error. Fixed by wrapping all node references in `@()` to force array coercion before any property access.

**Null Benchmark after successful detection.** Verbose logging confirmed the XCCDF node was found (`Found 1 XCCDF nodes`), but the variable evaluated to `$null` inside the conditional block. Root cause was that the truthiness check on the node itself was failing due to how PowerShell evaluates `XmlNode` objects in a boolean context. Fixed with an explicit null check and `@()-Measure-Object` count guard.

**Namespace mismatch between XCCDF and OVAL.** The XCCDF Benchmark references definitions as `oval:mil.disa.stig.windows11:def:253254`, but generic OVAL definitions use a different namespace prefix: `oval:mil.disa.stig.defs:def:253254`. Same numeric ID, different namespace — so exact dictionary lookup fails for the generic definitions. Fixed by adding a numeric-suffix fallback: when the exact lookup misses, the trailing digits are extracted and compared against all XCCDF keys. This resolved severity for all 216 definitions in the V2R7 benchmark.

The final severity lookup chain per definition is:

1. Exact match against the XCCDF rule table
2. Numeric-suffix fallback (cross-namespace match)
3. OVAL `<metadata><severity>` fallback

Severity now appears in summary tables, color-coded in detailed failure output (red / yellow / green for high / medium / low), and in JSON output.

### AccessToken Test Overhaul — `TestEvaluators.ps1`

`Evaluate-AccessTokenTest` was rewritten to fix four distinct issues.

**Missing function.** The original `TestEvaluators.ps1` shipped without `Evaluate-AccessTokenTest` entirely. The function was added in full, covering the `secedit` export, privilege lookup, principal detection, and pass/fail logic.

**SID resolution.** Raw SIDs (e.g. `S-1-5-32-544`) were displayed directly. The function now resolves each SID to its friendly account name via `SecurityIdentifier.Translate()`, displaying results as `BUILTIN\Administrators (S-1-5-32-544)`. Resolution failures are caught and fall back to the raw SID.

**Regex principal matching.** OVAL definitions frequently express the target principal as a regex pattern (e.g. `^(?i)(.+\\)?Enterprise Admins$`) rather than a literal name. The original code used `-eq` for all comparisons, which never matched. The function now detects regex patterns by checking for special characters, resolves each assigned SID to its account name, and tests against the pattern. Matched principals are tracked separately for evidence output.

**Expanded privilege map.** The original map covered nine privileges. The expanded map includes all standard logon rights (`SeBatchLogonRight`, `SeServiceLogonRight`, `SeInteractiveTSLogonRight`), all corresponding deny rights (`SeDenyBatchLogonRight`, `SeDenyServiceLogonRight`, etc.), and common privileges (`SeDebugPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`, `SeShutdownPrivilege`, `SeAssignPrimaryTokenPrivilege`, `SeIncreaseQuotasPrivilege`). Unmapped privilege names now fall through with proper PascalCase conversion instead of using the raw lowercase OVAL field name, which was causing `secedit` queries to return empty results.

### AccessToken Display — `Output.ps1`

`Print-EvidenceRecursive` now branches on test type for AccessToken results. Privilege and Principal are shown before Expected/Actual. The Expected field is annotated with plain-English meaning (`should have privilege` / `should NOT have privilege`). The Actual field splits the resolved principals into one entry per line for readability. All of this applies only to AccessToken tests; other test types are unchanged.

### Testing Notes

All changes were verified against the DISA Windows 11 STIG V2R7 SCAP bundle (`U_MS_Windows_11_V2R7_STIG_SCAP_1-3_Benchmark.xml`):

- 216 XCCDF Rule nodes parsed, 216 severity mappings created
- Both namespace variants (`windows11:def:*` and `defs:def:*`) resolve severity correctly
- A small number of definitions correctly show blank severity — these are secondary or generic audit definitions with no corresponding XCCDF Rule in the V2R7 benchmark
- AccessToken tests display resolved account names, regex match results, and structured evidence

---

## Testing Disclaimer

Testing so far has been limited to:

- ✔ Windows 11
- ✔ Windows Server 2019
- ✔ Local execution only
- ✘ No remote scanning validation
- ✘ No SQL Server scanning validation
- ✘ No domain‑wide testing
- ✘ No cross‑version Windows testing
- ✘ No automated test suite

**Do not rely on PowerSCAP for compliance decisions without independent validation.**

---

## Versioning

- **v1** — Single monolithic PowerShell script
- **v2.0** — Modular PowerShell module rewrite
- **v2.1.0** — XCCDF severity parsing, AccessToken evaluation overhaul, namespace-fallback severity resolution
- **v2.2.0** — SQL Server STIG scanning (`Scan-SQLInstance`, `Scan-SQLDatabase`), remote scanning fixes for `Scan-Computer`

Breaking changes between v1 and v2 are expected and intentional.

---

## Roadmap (Aspirational)

- Expand OVAL test coverage
- Improve evidence and output formats
- Add structured result objects for automation
- Domain and multi‑host scanning support
- Remote scanning via PowerShell remoting (would cover the checks currently indeterminate over CIM)
- Automated test suite
- Linux Support

No timelines are promised.

---

## Contributing

This project is **open to handoff**.

If you are interested in:
- Taking over long‑term maintenance
- Adding test coverage
- Expanding OVAL support
- Turning this into a production‑ready tool

…contributions are welcome.

Please open an issue or discussion before large changes.

---

## License

MIT License

---

## Final Notes

PowerSCAP is a **foundation**, not a finished product.

If it solves a problem for you — great. If it inspires a better tool — even better.
