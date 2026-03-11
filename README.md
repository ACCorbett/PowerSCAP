# PowerSCAP v2.6.2 - Release Notes

## Overview
PowerSCAP v2.6.2 is a bugfix release targeting the SQL scanning subsystem. It resolves a set of issues in `SqlHelpers.ps1` and `Scan-SQLDatabase.ps1` that were identified through static analysis against the full MS SQL Server 2022 Instance and Database STIG corpus. No new features are introduced. See v2.6.0 release notes below for the last major feature release.

> **Note**: This version was developed extensively with AI assistance and needs thorough testing. It is not production ready. Assistance in testing and debugging is welcome.

---

## What Changed in v2.6.2

### SQL Query Extraction Overhaul (`SqlHelpers.ps1` — `Extract-SqlQueries`)

The function that extracts executable T-SQL from XCCDF check-content text was rewritten and validated against all 102 rules in the MS SQL Server 2022 Instance (V1R3) and Database (V1R2) STIGs. The old implementation had six distinct bugs:

| Bug | Effect |
|-----|--------|
| `^EXECUTE\b` matched prose ("Execute the following SQL script:") | Garbage strings like `"Execute the following:"` sent to SQL Server → false FAIL |
| `^IF\b.*BEGIN` required `BEGIN` on same line as `IF` | Multi-line `IF` blocks never recognized; 23 instance rules extracted zero queries |
| `^USE` negative lookahead consumed first letter before checking | `Use the following query to...` incorrectly started SQL collection |
| Missing `DECLARE` and `INSERT INTO` starters | Multi-step checks (declare table variable → insert → select) silently skipped |
| `"Use the "` missing from prose terminators | Intro lines bled into active accumulators |
| `GO` batch separators not split | `USE master; GO SELECT ...` sent as one invalid batch; SQL Server error → false FAIL |

**New implementation adds:**
- SQL-specific patterns for every starter (no English verb collisions)
- `SQL_EMBED` fallback that detects SQL embedded mid-line in prose ("If Mirroring is in use, run: `SELECT name FROM sys...`")
- `SQL_VALIDITY` post-filter requiring at least one SQL hallmark before a query is returned
- Mid-statement `GO` splitting with per-batch validation

**Result:** Zero prose leaks, 105 valid queries extracted across 71 of 102 rules.

### SQL Connection Fixes

- **`Build-SqlConnection` — PowerShell 7 compatibility**: `System.Data.SqlClient` was removed from .NET 5+ (which PowerShell 7 uses). Connection attempts threw a cryptic type-not-found error. Now probes for the type at startup and throws a clear, actionable message pointing to `Install-Module -Name SqlServer -Force`.

- **`Scan-SQLDatabase` — master connection ignored `-ConnectionString`**: The secondary connection to `master` (used to route instance-level queries like `sys.databases`, `sys.server_principals`, etc.) was always built to `localhost` with integrated auth, completely ignoring the user's server, credentials, and TLS settings. It failed silently and fell back to `$connMaster = $null`, causing instance-level queries to run in the wrong database context. Fixed by mutating the `Database=` clause of the provided connection string.

### Minor Cleanup

- Removed dead variable `$anyQueryReturned` from `Evaluate-SqlRule` (assigned but never read).

---

## What Changed in v2.6.1

### OVAL Severity Propagation Fix (`Scan-Computer.ps1`)

Definitions used as shared building blocks via `<extend_definition>` had no XCCDF Rule referencing them directly and therefore no severity in scan output (~15 blank-severity rows in the Windows 11 V2R7 STIG). Fixed by building a reverse parent map during OVAL collection and running a post-load propagation pass with numeric-suffix fallback for multi-hop chains.

---

## What's in v2.6.0 (Last Major Release)

### 1. Full Linux Support
PowerSCAP now supports scanning Linux systems for all scan types including:
- **OVAL Vulnerability Scanning**: Scan Linux systems using OVAL definitions
- **SCAP/STIG Compliance**: Evaluate Linux configurations (with appropriate SCAP files)
- **Remote Linux Scanning**: Scan remote Linux systems via PowerShell 7.x remoting
- **Cross-Platform InstallPowerSCAP**: Automatic module installation works on both Windows and Linux

#### Linux Platform Support Details:
- **Requirements**: PowerShell 7.0+ on target Linux systems
- **Distributions Tested**: Ubuntu, Debian, RHEL, CentOS, Fedora
- **Automatic Platform Detection**: PowerSCAP automatically detects Windows vs Linux
- **Module Paths**: 
  - System scope: `/usr/local/share/powershell/Modules/PowerSCAP`
  - User scope: `~/.local/share/powershell/Modules/PowerSCAP`

#### Linux-Specific Capabilities:
- Package information retrieval (dpkg, rpm)
- Service status checking (systemd, sysvinit)
- User account enumeration
- File system operations
- Command execution
- OS information gathering

#### Limitations on Linux:
- Windows Registry operations (not applicable)
- WMI queries (not applicable)
- Windows-specific STIG tests will be automatically skipped

### 2. Parameter Alignment Across All Functions
All scanning functions now share consistent parameter interfaces:

#### Unified Parameters:
- `Computer` (alias: ComputerName): Target system for scanning
- `ScanSourceType`: How to obtain scan definitions (File, Directory, Download)
- `ScanSource`: Source for scan definitions
- `Output`: Output format (Console, JSON, CSV, TSV, Legacy)
- `IncludePerTestDetails`: Include detailed evidence (default: $true)
- `Credential`: Credentials for authentication
- `InstallPowerSCAP`: Remote installation mode (Yes, Upgrade, WhileScanning, No)

#### Function-Specific Parameters Retained:
- **Scan-Computer**: SkipPlatformFilter, SkipRoleFilter, ForceRole, UseCim, etc.
- **Scan-SQLDatabase**: Database, ConnectionString (SQL-specific)
- **Scan-SQLInstance**: ConnectionString (SQL-specific)

### 3. Enhanced SQL Scanning Functions
Both `Scan-SQLDatabase` and `Scan-SQLInstance` now include:
- All parameters from `Scan-Computer` (where applicable)
- Consistent output formatting (Console, JSON, CSV, TSV)
- Remote scanning support with InstallPowerSCAP
- Cross-platform SQL Server connectivity (Windows and Linux SQL Server)

---

## Breaking Changes
⚠️ **Important**: While we've maintained backward compatibility where possible, note these changes from v2.5.x:

1. **Scan-SQLDatabase and Scan-SQLInstance**:
   - `ComputerName` parameter is now aliased to `Computer` (both work, but `Computer` is preferred)
   - `ScapFile` parameter is now specified via `ScanSourceType` and `ScanSource`
   - `OutputJson` parameter is now `Output` with value 'JSON'

2. **Module Version**: Updated from 2.5.0 to 2.6.2

---

## Upgrade Instructions

### From v2.6.x:
1. Replace `SqlHelpers.ps1` and `Scan-SQLDatabase.ps1` with the updated versions
2. No parameter or interface changes — drop-in replacement

### From v2.5.0 or Earlier:
1. Remove old module: `Remove-Module PowerSCAP -Force`
2. Delete old module directory
3. Import new module: `Import-Module PowerSCAP`
4. Update scripts to use new parameter names (optional, old aliases still work)

### Testing After Upgrade:
```powershell
# Test local Windows scan
Scan-Computer -ScanSourceType File -ScanSource "path\to\stig.xml"

# Test local Linux scan (if on Linux)
Scan-Computer -ScanSourceType File -ScanSource "/path/to/oval.xml"

# Test remote Windows scan
Scan-Computer -Computer "WindowsServer" -ScanSourceType File -ScanSource "stig.xml"

# Test remote Linux scan
Scan-Computer -Computer "LinuxServer" -ScanSourceType File -ScanSource "oval.xml" -Credential $cred

# Test SQL scanning
Scan-SQLInstance -ScanSourceType File -ScanSource "instance_stig.xml" -Computer "SQL01"
Scan-SQLDatabase -ScanSourceType File -ScanSource "database_stig.xml" -Computer "SQL01" -Database "MyDB"

# Test SQL with explicit connection string (v2.6.2 fix validation)
Scan-SQLDatabase -ScanSourceType File -ScanSource "database_stig.xml" `
    -ConnectionString "Server=SQL01;Database=MyDB;Integrated Security=true;Encrypt=true;"
```

---

## Usage Examples

### Windows Scanning
```powershell
# Local Windows STIG compliance scan
Scan-Computer -ScanSourceType File -ScanSource "U_MS_Windows_11_V2R7_STIG.xml"

# Remote Windows server with installation
Scan-Computer -Computer "WEB01" -ScanSourceType File -ScanSource "stig.xml" -InstallPowerSCAP Yes -Credential $cred

# Download and scan with NVD vulnerabilities
Scan-Computer -ScanSourceType Download -ScanSource NVD -VulnerabilityDaysBack 30 -Output JSON
```

### Linux Scanning
```powershell
# Local Linux OVAL vulnerability scan
Scan-Computer -ScanSourceType File -ScanSource "/home/admin/ubuntu.oval.xml"

# Remote Linux server scan
$cred = Get-Credential
Scan-Computer -Computer "linuxserver01" -ScanSourceType File -ScanSource "rhel8.oval.xml" -Credential $cred -InstallPowerSCAP WhileScanning

# Linux package vulnerability scan
Scan-Computer -Computer "ubuntu-web" -ScanSourceType Download -ScanSource OVAL -Output CSV -Credential $cred
```

### SQL Server Scanning
```powershell
# SQL Instance STIG scan - local
Scan-SQLInstance -ScanSourceType File -ScanSource "Instance_STIG.xml"

# SQL Database STIG scan - remote with named instance
$sqlCred = Get-Credential
Scan-SQLDatabase -ScanSourceType File -ScanSource "Database_STIG.xml" -Computer "SQL01\PROD" -Database "Production" -Credential $sqlCred -Output JSON

# SQL scan with explicit connection string (recommended for non-default ports, TLS settings, etc.)
Scan-SQLInstance -ScanSourceType File -ScanSource "Instance_STIG.xml" `
    -ConnectionString "Server=SQL01\INST1;Integrated Security=true;Encrypt=true;TrustServerCertificate=false;"

# SQL scan with CSV output
Scan-SQLInstance -ScanSourceType File -ScanSource "Instance_STIG.xml" -Computer "SQL01\INST1" -Output CSV
```

### Cross-Platform Scenarios
```powershell
# Scan both Windows and Linux from single script
$windowsResults = Scan-Computer -Computer "WinServer" -ScanSourceType File -ScanSource "win_stig.xml" -Credential $winCred
$linuxResults = Scan-Computer -Computer "LinuxServer" -ScanSourceType File -ScanSource "linux_oval.xml" -Credential $linuxCred

# SQL Server on Linux
Scan-SQLInstance -ScanSourceType File -ScanSource "Instance_STIG.xml" -Computer "linuxsql.contoso.com" -Credential $sqlCred
```

---

## Technical Details

### Modified Files in v2.6.2
- `Private/SqlHelpers.ps1` — `Extract-SqlQueries`, `Build-SqlConnection`, `Evaluate-SqlRule`
- `Public/Scan-SQLDatabase.ps1` — master connection derivation logic

### New Helper Functions (v2.6.0)
1. **LinuxHelpers.ps1**:
   - `Test-IsLinux`: Detects if system is Linux
   - `Get-LinuxOSInfo`: Retrieves distribution and version info
   - `Get-LinuxFileContent`: Reads files on Linux systems
   - `Invoke-LinuxCommand`: Executes shell commands
   - `Get-LinuxPackageInfo`: Retrieves package information
   - `Test-LinuxServiceStatus`: Checks service status
   - `Get-LinuxUserInfo`: Retrieves user account information

2. **Updated Functions**:
   - `Install-RemotePowerSCAP`: Now handles both Windows and Linux paths
   - `Remove-RemotePowerSCAP`: Cross-platform module removal
   - `Get-RegistryItemProperty`: Skips gracefully on Linux
   - `Invoke-WmiQuery`: Skips gracefully on Linux

### Module Structure
```
PowerSCAP/
├── PowerSCAP.psd1              # Module manifest (v2.6.2)
├── PowerSCAP.psm1              # Module loader
├── Private/
│   ├── LinuxHelpers.ps1        # NEW in 2.6.0: Linux operations
│   ├── RemotePowerSCAPManagement.ps1  # Updated for Linux
│   ├── RegistryAndWmi.ps1      # Updated with platform detection
│   ├── XmlHelpers.ps1
│   ├── OvalCore.ps1
│   ├── AuditHelpers.ps1
│   ├── LocalAccounts.ps1
│   ├── TestEvaluators.ps1
│   ├── Criteria.ps1
│   ├── Output.ps1
│   ├── SqlHelpers.ps1          # Updated in 2.6.2
│   └── VulnerabilityDownload.ps1
└── Public/
    ├── Scan-Computer.ps1       # Updated in 2.6.1 (severity propagation)
    ├── Scan-SQLInstance.ps1    # Updated parameters in 2.6.0
    ├── Scan-SQLDatabase.ps1    # Updated in 2.6.2 (master connection fix)
    ├── Scan-Domain.ps1
    └── Scan-Database.ps1
```

---

## Known Issues
1. **Linux STIG Scanning**: Windows-specific STIG checks will be skipped on Linux. Use Linux-appropriate OVAL/SCAP files.
2. **SQL Server on Linux**: Requires PowerShell 7.x and the SqlServer module (`Install-Module -Name SqlServer`)
3. **CIM/WMI on Linux**: Not supported — these queries are automatically skipped
4. **`Scan-Database.ps1`**: Still a stub (`throw [NotImplementedException]`). Not yet implemented.

---

## System Requirements
- **PowerShell**: 7.0 or higher (required for Linux support)
- **Windows**: Windows 10/11, Windows Server 2016+
- **Linux**: Any distribution with PowerShell 7.x support
- **SQL Server**: SQL Server 2016+ (Windows or Linux)
- **SQL Scanning on PowerShell 7**: Requires `Install-Module -Name SqlServer -Force`

---

## Installation

### From PowerShell Gallery (when published):
```powershell
Install-Module -Name PowerSCAP -RequiredVersion 2.6.2
```

### Manual Installation:
```powershell
# Windows (System)
Copy-Item -Path "PowerSCAP" -Destination "$env:ProgramFiles\WindowsPowerShell\Modules\" -Recurse

# Windows (User)
Copy-Item -Path "PowerSCAP" -Destination "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\" -Recurse

# Linux (System)
sudo cp -r PowerSCAP /usr/local/share/powershell/Modules/

# Linux (User)
mkdir -p ~/.local/share/powershell/Modules
cp -r PowerSCAP ~/.local/share/powershell/Modules/
```

---

## Support and Feedback
For issues, feature requests, or questions:
1. Check verbose output: Add `-Verbose` to any command
2. Review error messages carefully
3. Verify PowerShell version: `$PSVersionTable`
4. Check platform: `$PSVersionTable.Platform`
5. For SQL scanning issues, verify the SqlServer module is installed: `Get-Module SqlServer -ListAvailable`

---

## Credits
PowerSCAP developed by Adam Corbett
- Initial release: v1.0.0
- Major refactor: v2.0.0
- Parameter cleanup: v2.4.0
- Bug fixes: v2.5.0
- Cross-platform support: v2.6.0
- OVAL severity propagation fix: v2.6.1
- SQL query extraction overhaul + connection fixes: v2.6.2

## License
Copyright (c) Adam Corbett. All rights reserved.

---

**Version**: 2.6.2  
**Release Date**: March 2026  
**PowerShell Version**: 7.0+  
**Platforms**: Windows, Linux
