# PowerSCAP v2.6.0 - Release Notes

## Overview
PowerSCAP v2.6.0 represents a major milestone with full cross-platform support for Windows and Linux systems. This release includes comprehensive Linux scanning capabilities, parameter alignment across all scanning functions, and numerous bug fixes. This version was developed extensively with AI assistance and needs thorough testing. It is not production ready. Assistance in testing and debugging is welcome.

## Major New Features

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

## All Changes Since v2.5.0

### New Features
1. **Linux Platform Support**
   - Added `LinuxHelpers.ps1` with comprehensive Linux operations
   - Platform detection in `Scan-Computer`
   - Cross-platform remote installation
   - Linux-aware registry and WMI operations

2. **Parameter Standardization**
   - `Scan-SQLDatabase` now uses `Computer` instead of `ComputerName`
   - `Scan-SQLInstance` now uses `Computer` instead of `ComputerName`
   - Both SQL functions support `Output` parameter with CSV/TSV options
   - Both SQL functions support `InstallPowerSCAP` parameter

3. **Enhanced Output Options**
   - CSV and TSV output now available for all scan functions
   - Consistent output formatting across all functions
   - Improved JSON structure

### Bug Fixes
1. **Critical .Count Bug**: Fixed all instances of `.Count` usage that could cause null reference errors
   - All code now uses `Get-SafeCount` helper function consistently
   - Affects: Scan-Computer, Scan-SQLDatabase, Scan-SQLInstance, and all helper functions

2. **Remote Scanning Fixes**
   - Fixed path detection for Windows vs Linux in module installation
   - Improved error handling for cross-platform scenarios
   - Better PowerShell remoting compatibility

3. **Platform Detection**
   - More reliable OS detection for remote systems
   - Handles mixed Windows/Linux environments correctly
   - Better error messages for unsupported operations

### Improvements
1. **Code Quality**
   - Consistent error handling across all functions
   - Improved verbose logging for troubleshooting
   - Better parameter validation
   - Enhanced documentation

2. **Performance**
   - Optimized remote scanning with InstallPowerSCAP
   - Reduced unnecessary WMI/CIM queries on Linux
   - Better handling of large result sets

3. **Usability**
   - Clearer parameter names (Computer vs ComputerName)
   - Consistent output formats
   - Better progress indicators
   - **NEW: Visual progress bars for all vulnerability downloads**
   - Improved error messages

4. **Download Experience**
   - **Progress bars show real-time status during downloads**
   - NVD: Shows API query, data processing, conversion, and save stages
   - MSRC: Tracks progress through each monthly update
   - OVAL: Shows download and parsing progress
   - Multi-source ("All"): Shows overall progress through each source
   - Conversion progress for large datasets (updates every 10 items)
   - Proper progress completion even on errors

## Breaking Changes
⚠️ **Important**: While we've maintained backward compatibility where possible, note these changes:

1. **Scan-SQLDatabase and Scan-SQLInstance**:
   - `ComputerName` parameter is now aliased to `Computer` (both work, but `Computer` is preferred)
   - `ScapFile` parameter is now specified via `ScanSourceType` and `ScanSource`
   - `OutputJson` parameter is now `Output` with value 'JSON'

2. **Module Version**: Updated from 2.5.0 to 2.6.0

## Upgrade Instructions

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

# Test SQL scanning with new parameters
Scan-SQLInstance -ScanSourceType File -ScanSource "instance_stig.xml" -Computer "SQL01"
Scan-SQLDatabase -ScanSourceType File -ScanSource "database_stig.xml" -Computer "SQL01" -Database "MyDB"
```

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

# SQL Database STIG scan - remote
$sqlCred = Get-Credential
Scan-SQLDatabase -ScanSourceType File -ScanSource "Database_STIG.xml" -Computer "SQL01" -Database "Production" -Credential $sqlCred -Output JSON

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

## Technical Details

### New Helper Functions
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
├── PowerSCAP.psd1              # Module manifest (v2.6.0)
├── PowerSCAP.psm1              # Module loader
├── Private/
│   ├── LinuxHelpers.ps1        # NEW: Linux operations
│   ├── RemotePowerSCAPManagement.ps1  # Updated for Linux
│   ├── RegistryAndWmi.ps1      # Updated with platform detection
│   ├── XmlHelpers.ps1
│   ├── OvalCore.ps1
│   ├── AuditHelpers.ps1
│   ├── LocalAccounts.ps1
│   ├── TestEvaluators.ps1
│   ├── Criteria.ps1
│   ├── Output.ps1
│   ├── SqlHelpers.ps1
│   └── VulnerabilityDownload.ps1
└── Public/
    ├── Scan-Computer.ps1       # Updated with Linux support
    ├── Scan-SQLInstance.ps1    # Updated parameters
    ├── Scan-SQLDatabase.ps1    # Updated parameters
    ├── Scan-Domain.ps1
    └── Scan-Database.ps1
```

## Known Issues
1. **Linux STIG Scanning**: Windows-specific STIG checks will be skipped on Linux. Use Linux-appropriate OVAL/SCAP files.
2. **SQL Server on Linux**: Requires PowerShell 7.x and appropriate SQL Server drivers
3. **CIM/WMI on Linux**: Not supported - these queries are automatically skipped

## System Requirements
- **PowerShell**: 7.0 or higher (required for Linux support)
- **Windows**: Windows 10/11, Windows Server 2016+
- **Linux**: Any distribution with PowerShell 7.x support
- **SQL Server**: SQL Server 2016+ (Windows or Linux)

## Installation

### From PowerShell Gallery (when published):
```powershell
Install-Module -Name PowerSCAP -RequiredVersion 2.6.0
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

## Support and Feedback
For issues, feature requests, or questions:
1. Check verbose output: Add `-Verbose` to any command
2. Review error messages carefully
3. Verify PowerShell version: `$PSVersionTable`
4. Check platform: `$PSVersionTable.Platform`

## Credits
PowerSCAP v2.6.0 developed by Adam Corbett
- Initial release: v1.0.0
- Major refactor: v2.0.0
- Parameter cleanup: v2.4.0
- Bug fixes: v2.5.0
- Cross-platform support: v2.6.0

## License
Copyright (c) Adam Corbett. All rights reserved.

---

**Version**: 2.6.0  
**Release Date**: February 2026  
**PowerShell Version**: 7.0+  
**Platforms**: Windows, Linux
