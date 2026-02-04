# PowerSCAP v2.6.0 - Quick Start Guide

## Installation

### Requirements
- **PowerShell 7.0+** (required for Linux support)
- Windows 10/11, Windows Server 2016+, or any Linux distribution with PS 7.x
- Administrator/root privileges for system-level installation

### Step 1: Extract the Module
```powershell
# Extract PowerSCAP-v2_6_0.zip to a temporary location
# Example: C:\Temp\PowerSCAP-v2_6_0 or /tmp/PowerSCAP-v2_6_0
```

### Step 2: Install the Module

#### Windows (System-wide):
```powershell
# Run PowerShell 7 as Administrator
Copy-Item -Path "C:\Temp\PowerSCAP-v2_6_0\PowerSCAP-v2_6_0" `
          -Destination "$env:ProgramFiles\PowerShell\Modules\PowerSCAP" `
          -Recurse -Force
```

#### Windows (Current User):
```powershell
# Run PowerShell 7
Copy-Item -Path "C:\Temp\PowerSCAP-v2_6_0\PowerSCAP-v2_6_0" `
          -Destination "$env:USERPROFILE\Documents\PowerShell\Modules\PowerSCAP" `
          -Recurse -Force
```

#### Linux (System-wide):
```bash
# Run as root or with sudo
sudo cp -r /tmp/PowerSCAP-v2_6_0/PowerSCAP-v2_6_0 /usr/local/share/powershell/Modules/PowerSCAP
```

#### Linux (Current User):
```bash
# Run as regular user
mkdir -p ~/.local/share/powershell/Modules
cp -r /tmp/PowerSCAP-v2_6_0/PowerSCAP-v2_6_0 ~/.local/share/powershell/Modules/PowerSCAP
```

### Step 3: Verify Installation
```powershell
# Import the module
Import-Module PowerSCAP -Force

# Check version
Get-Module PowerSCAP

# List commands
Get-Command -Module PowerSCAP
```

Expected output:
```
ModuleType Version Name         ExportedCommands
---------- ------- ----         ----------------
Script     2.6.0   PowerSCAP    {Scan-Computer, Scan-SQLDatabase, Scan-SQLInstance...}
```

## First Scan

### Windows STIG Scan:
```powershell
# Download a Windows STIG from https://public.cyber.mil/stigs/downloads/
# Example: U_MS_Windows_11_V2R7_STIG.xml

Scan-Computer -ScanSourceType File -ScanSource ".\U_MS_Windows_11_V2R7_STIG.xml"
```

### Linux OVAL Scan:
```powershell
# Download OVAL definitions for your distribution
# Example from https://www.canonical.com/security/oval

Scan-Computer -ScanSourceType File -ScanSource "/path/to/ubuntu.oval.xml"
```

### SQL Server STIG Scan:
```powershell
# Download SQL Server STIG from https://public.cyber.mil/stigs/downloads/

# Instance scan
Scan-SQLInstance -ScanSourceType File -ScanSource ".\SQL_Instance_STIG.xml"

# Database scan
Scan-SQLDatabase -ScanSourceType File -ScanSource ".\SQL_Database_STIG.xml" -Database "MyDB"
```

## Common Commands

### Local Scans
```powershell
# Scan local Windows system
Scan-Computer -ScanSourceType File -ScanSource "stig.xml"

# Scan local Linux system
Scan-Computer -ScanSourceType File -ScanSource "oval.xml"

# Output as JSON
Scan-Computer -ScanSourceType File -ScanSource "stig.xml" -Output JSON

# Output as CSV
Scan-Computer -ScanSourceType File -ScanSource "stig.xml" -Output CSV
```

### Remote Scans
```powershell
# Get credentials
$cred = Get-Credential

# Scan remote Windows server
Scan-Computer -Computer "Server01" -ScanSourceType File -ScanSource "stig.xml" -Credential $cred

# Scan remote Linux server
Scan-Computer -Computer "LinuxServer" -ScanSourceType File -ScanSource "oval.xml" -Credential $cred

# Scan with temporary installation (faster, auto-cleanup)
Scan-Computer -Computer "Server01" -ScanSourceType File -ScanSource "stig.xml" `
              -InstallPowerSCAP WhileScanning -Credential $cred
```

### Download and Scan
```powershell
# Download and scan NVD vulnerabilities (last 30 days)
Scan-Computer -ScanSourceType Download -ScanSource NVD -VulnerabilityDaysBack 30

# Download and scan Microsoft security updates
Scan-Computer -ScanSourceType Download -ScanSource MSRC -VulnerabilityDaysBack 90

# Download OVAL definitions (Windows 10)
Scan-Computer -ScanSourceType Download -ScanSource OVAL
```

## Troubleshooting

### Module Not Found
```powershell
# Check module paths
$env:PSModulePath -split [IO.Path]::PathSeparator

# Manually import from path
Import-Module "C:\Path\To\PowerSCAP\PowerSCAP.psd1" -Force
```

### Permission Errors
- Run PowerShell as Administrator (Windows) or with sudo (Linux)
- Check file permissions on the module directory
- Verify firewall settings for remote scanning

### Remote Scanning Issues
```powershell
# Test PowerShell remoting
Test-WSMan -ComputerName "TargetComputer"

# Enable remoting on target (Windows)
Enable-PSRemoting -Force

# Enable remoting on target (Linux)
# Install PowerShell 7.x first, then:
sudo pwsh -Command "Enable-PSRemoting -Force"
```

### Linux-Specific Issues
- Ensure PowerShell 7.x is installed
- Check SSH configuration for remoting
- Verify module paths are correct
- Run `Import-Module PowerSCAP -Verbose` to see loading details

## Getting Help
```powershell
# Function help
Get-Help Scan-Computer -Full
Get-Help Scan-SQLDatabase -Full
Get-Help Scan-SQLInstance -Full

# Examples
Get-Help Scan-Computer -Examples

# Online help
Get-Help Scan-Computer -Online  # (if available)
```

## Next Steps
1. Read the full README.md for detailed documentation
2. Review CHANGELOG.md for all changes in v2.6.0
3. Run tests from TESTING.md to verify functionality
4. Check examples in the help documentation

## Resources
- DISA STIGs: https://public.cyber.mil/stigs/downloads/
- OVAL Repository: https://oval.cisecurity.org/
- NVD API: https://nvd.nist.gov/developers
- Microsoft Security Updates: https://msrc.microsoft.com/

## Support
For issues or questions:
1. Enable verbose output: `-Verbose`
2. Check error messages carefully
3. Verify PowerShell version: `$PSVersionTable`
4. Review documentation files

---
PowerSCAP v2.6.0 | Cross-Platform Security Scanning | PowerShell 7.0+
