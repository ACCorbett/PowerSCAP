# PowerSCAP

![PowerShell](https://img.shields.io/badge/PowerShell-7.0+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)
![Status](https://img.shields.io/badge/Status-Beta-yellow.svg)
![Version](https://img.shields.io/badge/Version-2.1.0-informational.svg)

**PowerSCAP** is a modular PowerShell implementation of a Windows **SCAP / OVAL compliance evaluator**.

This repository represents a **complete rewrite of PowerSCAP v1**. Version 1 was a single, monolithic script; version 2 is a **proper PowerShell module** with a clear public API, private helper layers, and a structure designed to grow into larger automation toolchains.

> ⚠️ **BETA WARNING**
>
> PowerSCAP v2 is **early beta** and **lightly tested**. Testing to date has been limited to **local execution on Windows 11 and Windows Server 2019**. Expect bugs, incomplete coverage, and breaking changes.

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

This project focuses on **evaluating OVAL definitions** from SCAP 1.3 data streams, with a strong emphasis on Windows security baselines (notably DISA STIGs).

---

## Project Status

- **Rewrite Status**: Complete (v2 architecture)
- **Current Version**: 2.1.0
- **Test Coverage**: Minimal
- **Production Readiness**: ❌ Not production-ready

If you are looking for a battle‑tested compliance scanner, this is **not** it (yet). If you are interested in **automation, experimentation, or extending SCAP logic in PowerShell**, this project may be useful.

---

## Module Layout

```text
PowerSCAP/
├── PowerSCAP.psd1        # Module manifest
├── PowerSCAP.psm1        # Module entry point
│
├── Public/               # Public commands (exported)
│   ├── Scan-Computer.ps1
│   ├── Scan-Domain.ps1
│   └── Scan-Database.ps1
│
├── Private/              # Internal helpers (not exported)
│   ├── XmlHelpers.ps1
│   ├── OvalCore.ps1
│   ├── Criteria.ps1
│   ├── TestEvaluators.ps1
│   ├── RegistryAndWmi.ps1
│   ├── AuditHelpers.ps1
│   ├── LocalAccounts.ps1
│   └── Output.ps1
```

Only the commands in **`Public/`** are part of the supported interface. Everything under **`Private/`** may change without notice.

---

## Requirements

- **Operating System**: Windows
- **PowerShell**: **7.0 or later**
- **Privileges**: Administrator (required for many checks)
- **SCAP Content**: SCAP 1.3 data streams (e.g. DISA STIG SCAP bundles)

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

Runs a SCAP / OVAL evaluation against the **local system**.

```powershell
Scan-Computer -ScapFile 'C:\SCAP\Windows_Server_2019_STIG.xml'
```

Typical use cases:
- Local compliance checks
- Scheduled scans
- Integration with remediation scripts

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

- ✓ Windows 11
- ✓ Windows Server 2019
- ✓ Local execution only
- ✗ No domain‑wide testing
- ✗ No cross‑version Windows testing
- ✗ No automated test suite

**Do not rely on PowerSCAP for compliance decisions without independent validation.**

---

## Versioning

- **v1** — Single monolithic PowerShell script
- **v2.0** — Modular PowerShell module rewrite
- **v2.1.0** — XCCDF severity parsing, AccessToken evaluation overhaul, namespace-fallback severity resolution

Breaking changes between v1 and v2 are expected and intentional.

---

## Roadmap (Aspirational)

- Expand OVAL test coverage
- Improve evidence and output formats
- Add structured result objects for automation
- Domain and multi‑host scanning support
- Automated test suite
- Optional PowerShell Gallery publishing

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
