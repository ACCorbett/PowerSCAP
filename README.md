# PowerSCAP

![PowerShell](https://img.shields.io/badge/PowerShell-7.0+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)
![Status](https://img.shields.io/badge/Status-Beta-yellow.svg)

**PowerSCAP** is a modular PowerShell implementation of a Windows **SCAP / OVAL compliance evaluator**.

This repository represents a **complete rewrite of PowerSCAP v1**. Version 1 was a single, monolithic script; version 2 is a **proper PowerShell module** with a clear public API, private helper layers, and a structure designed to grow into larger automation toolchains.

> ⚠️ **BETA WARNING**
>
> PowerSCAP v2 is **early beta** and **lightly tested**. Testing to date has been limited to **local execution on Windows Server 2019**. Expect bugs, incomplete coverage, and breaking changes.

---

## Why PowerSCAP Exists

Most Windows SCAP tooling is:
- Heavyweight
- Closed-source
- Difficult to automate
- Tightly coupled to GUIs or external executables

PowerSCAP’s goals are intentionally different:

- 🪶 **Lightweight** – pure PowerShell, no additional executables required
- 📦 **Portable** – easy to drop into scripts and automation pipelines
- 🧩 **Composable** – designed to be embedded in larger PowerShell toolsets
- 🔍 **Transparent** – compliance logic is readable and auditable

This project focuses on **evaluating OVAL definitions** from SCAP 1.3 data streams, with a strong emphasis on Windows security baselines (notably DISA STIGs).

---

## Project Status

- **Rewrite Status**: Complete (v2 architecture)
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

Coverage is expanding, but **not all OVAL test types are implemented**, and some implementations are incomplete.

---

## Testing Disclaimer

Testing so far has been limited to:

- ✔ Windows Server 2019
- ✔ Local execution only
- ❌ No domain‑wide testing
- ❌ No cross‑version Windows testing
- ❌ No automated test suite

**Do not rely on PowerSCAP for compliance decisions without independent validation.**

---

## Versioning

- **v1** – Single monolithic PowerShell script
- **v2 (this repository)** – Modular PowerShell module rewrite

Breaking changes between v1 and v2 are expected and intentional.

---

## Roadmap (Aspirational)

- Expand OVAL test coverage
- Improve evidence and output formats
- Add structured result objects for automation
- Domain and multi‑host scanning support
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

