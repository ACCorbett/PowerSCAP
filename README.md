# PowerSCAP - Windows SCAP/OVAL Compliance Evaluator

![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Beta-yellow.svg)

A robust PowerShell-based SCAP (Security Content Automation Protocol) and OVAL (Open Vulnerability and Assessment Language) evaluator designed for Windows compliance assessment. This script parses SCAP 1.3 data streams and evaluates common Windows security controls, particularly optimized for DISA STIG SCAP bundles.

> **⚠️ WARNING**: This script is in **BETA** status. Several test types are newly implemented and have **limited production testing**. See [Testing Status](#testing-status) for details.

---

## 🚀 Quick Start

```powershell
# 1. Download the script
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/accorbett/powerscap/main/PowerSCAP.ps1" -OutFile "PowerSCAP.ps1"

# 2. Get a SCAP file (e.g., from DISA: https://public.cyber.mil/stigs/)
# Download: U_MS_Windows_Server_2019_V2R8_STIG_SCAP_1-3_Benchmark.xml

# 3. Run as Administrator
.\PowerSCAP.ps1 -ScapFile "C:\SCAP\Windows_Server_2019_STIG.xml"

# 4. Export results to JSON
.\PowerSCAP.ps1 -ScapFile "C:\SCAP\Windows_Server_2019_STIG.xml" -OutputJson $true | Out-File results.json
```

### ⚡ One-Liner

```powershell
# Quick compliance check without detailed evidence
.\PowerSCAP.ps1 -ScapFile "path\to\scap.xml" -IncludePerTestDetails $false
```

---

## Table of Contents

- [🚀 Quick Start](#-quick-start)
- [Overview](#overview)
- [Testing Status](#testing-status)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Supported Test Types](#supported-test-types)
- [Parameters](#parameters)
- [Output Formats](#output-formats)
- [Examples](#examples)
- [Architecture](#architecture)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [Disclaimer](#disclaimer)
- [License](#license)

## Overview

PowerSCAP automates security compliance assessment by evaluating OVAL definitions against Windows system configurations. It supports nested criteria logic (AND/OR operations), variable references, negation, existence checks, and a wide variety of Windows-specific test types.

The script is designed to work seamlessly with DISA STIG SCAP benchmarks and provides both human-readable console output and machine-parseable JSON results.

## Testing Status

> **⚠️ IMPORTANT**: Please review the testing status of each feature before production use.

### Production Ready ✅
These test types have been extensively tested in production environments:

| Test Type | Status | Confidence Level |
|-----------|--------|-----------------|
| Registry | ✅ Production Ready | High |
| WMI/CIM | ✅ Production Ready | High |
| File | ⚠️ Moderate Testing | Medium |
| Service | ⚠️ Moderate Testing | Medium |
| Process | ⚠️ Moderate Testing | Medium |
| QFE/Hotfix | ⚠️ Moderate Testing | Medium |

### Newly Implemented ⚠️
These test types are **newly implemented** and have **limited production testing**:

| Test Type | Status | Known Issues | Testing Needed |
|-----------|--------|--------------|----------------|
| Audit Policy | ⚠️ **Limited Testing** | Multiple parsing strategies may not cover all edge cases | More diverse SCAP content |
| Lockout Policy | ⚠️ **Limited Testing** | Secedit parsing assumes standard format | Various Windows versions |
| SID/SID | ⚠️ **Limited Testing** | Domain account resolution untested | Domain environments |
| Access Token | ⚠️ **Limited Testing** | Privilege mapping may be incomplete | All privilege types |
| File Effective Rights | ⚠️ **Limited Testing** | Complex ACL structures may not parse correctly | Various permission scenarios |

### Known Limitations ⚠️

#### Audit Policy Tests
```
⚠️ WARNING: Audit policy evaluation uses multiple parsing strategies:
   - Raw mode parsing (/r flag)
   - Table mode fallback
   - Full subcategory cache
   
   Edge cases that may fail:
   - Non-English Windows installations
   - Custom audit subcategory names
   - Malformed auditpol.exe output
   
   Recommendation: Manually verify audit policy results with:
   auditpol.exe /get /subcategory:* /r
```

#### Lockout Policy Tests
```
⚠️ WARNING: Account lockout policy evaluation relies on secedit.exe export:
   - Assumes standard [System Access] section format
   - May fail if security database is locked
   - Requires SYSTEM or Administrator privileges
   
   Edge cases that may fail:
   - Corrupted security policy database
   - Third-party policy management tools
   - Group Policy conflicts
   
   Recommendation: Test in your specific environment before relying on results
```

#### SID/SID Tests
```
⚠️ WARNING: SID to account name resolution is untested in domain environments:
   - Local account resolution: Well tested
   - Domain account resolution: UNTESTED
   - SID pattern matching (regex): Limited testing
   
   Known issues:
   - May fail for domain accounts if domain controller is unreachable
   - Cross-forest SID resolution not implemented
   
   Recommendation: Validate SID resolution for your environment type
```

#### Access Token Tests
```
⚠️ WARNING: User rights assignment evaluation has incomplete privilege mapping:
   - Only two privileges fully mapped:
     * SeProfileSingleProcessPrivilege
     * SeImpersonatePrivilege
   - Other privileges use default mappings
   
   Known issues:
   - Custom privilege assignments may not be detected correctly
   - SID comparison may fail for non-standard accounts
   
   Recommendation: Extend privilege mapping for your required privileges
```

#### File Effective Rights Tests
```
⚠️ WARNING: NTFS permission evaluation has limited ACL parsing:
   - Basic permission checks: Working
   - Complex inheritance: Limited testing
   - Explicit vs inherited permissions: May not distinguish correctly
   
   Known issues:
   - Special permissions may not map correctly
   - Deny ACEs may not be evaluated properly
   - Object-specific ACEs (for directories) untested
   
   Recommendation: Manually verify file permission results with:
   Get-Acl -Path "C:\path\to\file" | Format-List
```

### Testing Recommendations

Before deploying PowerSCAP in production:

1. **Test in Dev/Test Environment First**
   ```powershell
   # Run against a test system
   .\PowerSCAP.ps1 -ScapFile "test_scap.xml" -Verbose
   ```

2. **Validate Critical Checks Manually**
   ```powershell
   # For audit policy
   auditpol.exe /get /subcategory:* /r
   
   # For lockout policy
   net accounts
   
   # For user rights
   secedit.exe /export /cfg C:\temp\secpol.cfg
   Get-Content C:\temp\secpol.cfg
   ```

3. **Compare Results with Known-Good Tools**
   - DISA STIG Viewer
   - Microsoft SCAP Compliance Checker
   - CIS-CAT Pro Assessor
   - Manual validation

4. **Report Issues**
   - Document discrepancies between PowerSCAP and manual checks
   - Open GitHub issues with SCAP file samples (sanitized)
   - Include verbose output for debugging

### Future Testing Priorities

| Priority | Test Type | Action Needed |
|----------|-----------|---------------|
| 🔴 High | Audit Policy | Test with 50+ different SCAP files |
| 🔴 High | SID/SID (Domain) | Test in domain environments |
| 🟡 Medium | Access Token | Expand privilege mapping table |
| 🟡 Medium | File Effective Rights | Test complex ACL scenarios |
| 🟢 Low | Lockout Policy | Test on various Windows versions |

**Want to help?** See [Contributing](#contributing) section for how to submit test results.

## Features

### Core Capabilities

- ✅ **Comprehensive Test Coverage**: Supports 15+ OVAL test types
- ✅ **Nested Criteria Evaluation**: Full support for complex AND/OR/NOT logic
- ✅ **Variable Resolution**: Handles OVAL variable references and literal values
- ✅ **Flexible Operations**: Supports equals, not equal, greater than, less than, pattern match, and more
- ✅ **Multiple Datatypes**: String, integer, float, boolean, version, and record types
- ✅ **Registry View Control**: Configurable 32-bit/64-bit registry access
- ✅ **Detailed Evidence**: Per-test failure evidence with actual vs. expected values
- ✅ **JSON Export**: Machine-readable output for automation and storage

### Test Type Support

| Test Type | Description | Status | Testing Level |
|-----------|-------------|--------|---------------|
| Registry | Windows registry key/value checks | ✅ Fully Supported | 🟢 Well Tested |
| WMI/CIM | WMI query-based assessments | ✅ Fully Supported | 🟢 Well Tested |
| File | File existence, version, and size checks | ✅ Fully Supported | 🟡 Moderately Tested |
| Service | Windows service status and startup type | ✅ Fully Supported | 🟡 Moderately Tested |
| Process | Running process detection | ✅ Fully Supported | 🟡 Moderately Tested |
| QFE/Hotfix | Windows update installation verification | ✅ Fully Supported | 🟡 Moderately Tested |
| Audit Policy | Advanced audit policy subcategories | ✅ Fully Supported | ⚠️ Limited Testing |
| Lockout Policy | Account lockout policy settings | ✅ Fully Supported | ⚠️ Limited Testing |
| SID/SID | Security identifier to account name mapping | ✅ Fully Supported | ⚠️ Limited Testing |
| Access Token | User rights assignment verification | ✅ Fully Supported | ⚠️ Limited Testing |
| File Effective Rights | File system permission checks | ✅ Fully Supported | ⚠️ Limited Testing |

**Legend:**
- 🟢 **Well Tested**: Used extensively in production
- 🟡 **Moderately Tested**: Used in production with some validation
- ⚠️ **Limited Testing**: Newly implemented, needs more real-world validation

## Requirements

### System Requirements

- **Operating System**: Windows Server 2012 R2 or later, Windows 10/11
- **PowerShell**: Version 5.1 or later
- **Execution Policy**: RemoteSigned or Unrestricted
- **Privileges**: Administrator rights (required for many security checks)

### Dependencies

- .NET Framework 4.5 or later
- Windows Management Instrumentation (WMI)
- CIM cmdlets (Get-CimInstance)
- Local Security Policy tools (secedit.exe, auditpol.exe)

### Optional Components

- `Get-LocalUser` cmdlet (PowerShell 5.1+) for enhanced user account resolution
- CIM cmdlets for improved WMI query performance

## Installation

### Quick Start

1. **Download the script**:
   ```powershell
   # Download to your desired location
   Invoke-WebRequest -Uri "https://example.com/PowerSCAP.ps1" -OutFile "C:\Scripts\PowerSCAP.ps1"
   ```

2. **Set execution policy** (if needed):
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

3. **Verify prerequisites**:
   ```powershell
   # Check PowerShell version
   $PSVersionTable.PSVersion
   
   # Verify administrator rights
   ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
   ```

### SCAP Content Acquisition

Download DISA STIG SCAP benchmarks from:
- DISA STIG Viewer: https://public.cyber.mil/stigs/
- SCAP Compliance Checker: https://public.cyber.mil/stigs/scap/

Supported SCAP formats:
- SCAP 1.3 Data Stream Collections
- Standalone OVAL definition files
- DISA STIG SCAP bundles (recommended)

## Usage

> **⚠️ PRODUCTION USE WARNING**
> 
> Before using PowerSCAP in production:
> 1. Test thoroughly in dev/test environments
> 2. Manually validate results for newly implemented test types (Audit Policy, Lockout Policy, SID/SID, Access Token, File Effective Rights)
> 3. Compare results with other compliance tools
> 4. Review the [Testing Status](#testing-status) section
> 
> **Known Risk Areas:**
> - Domain account SID resolution (untested)
> - Non-English Windows installations (audit policy parsing)
> - Complex ACL structures (file effective rights)
> - Custom privilege assignments (access token tests)

### Basic Syntax

```powershell
.\PowerSCAP.ps1 -ScapFile <path-to-scap-file> [parameters]
```

### Common Use Cases

#### 1. Basic Compliance Check
```powershell
.\PowerSCAP.ps1 -ScapFile "C:\SCAP\Windows_Server_2019_STIG.xml"
```

#### 2. JSON Output for Automation
```powershell
.\PowerSCAP.ps1 -ScapFile "C:\SCAP\Windows_Server_2019_STIG.xml" -OutputJson $true | Out-File results.json
```

#### 3. Quick Summary (No Detailed Evidence)
```powershell
.\PowerSCAP.ps1 -ScapFile "C:\SCAP\Windows_Server_2019_STIG.xml" -IncludePerTestDetails $false
```

#### 4. Custom WMI Configuration
```powershell
.\PowerSCAP.ps1 -ScapFile "C:\SCAP\Windows_Server_2019_STIG.xml" -UseCim $false -MaxWmiRows 5000
```

#### 5. 32-bit Registry View
```powershell
.\PowerSCAP.ps1 -ScapFile "C:\SCAP\Windows_Server_2019_STIG.xml" -Prefer64BitRegistry $false
```

## Parameters

### Required Parameters

#### `-ScapFile <string>`
Path to the SCAP 1.3 data stream XML file.

- **Type**: String
- **Mandatory**: Yes
- **Example**: `"C:\SCAP\Windows_Server_2019_STIG.xml"`

### Optional Parameters

#### `-UseCim <bool>`
Use CIM cmdlets instead of legacy WMI cmdlets.

- **Type**: Boolean
- **Default**: `$true`
- **Recommendation**: Keep enabled for better performance
- **Example**: `-UseCim $false`

#### `-IncludePerTestDetails <bool>`
Include detailed per-test evidence in output.

- **Type**: Boolean
- **Default**: `$true`
- **Details**: When enabled, provides expected vs. actual values for all checks
- **Example**: `-IncludePerTestDetails $false`

#### `-OutputJson <bool>`
Output results in JSON format for machine parsing.

- **Type**: Boolean
- **Default**: `$false`
- **Use Case**: Automation, SIEM integration, database storage
- **Example**: `-OutputJson $true`

#### `-MaxWmiRows <int>`
Maximum number of WMI query results to process per query.

- **Type**: Integer
- **Default**: `1000`
- **Range**: 1-10000 (higher values may impact performance)
- **Example**: `-MaxWmiRows 5000`

#### `-Prefer64BitRegistry <bool>`
Prefer 64-bit registry view when accessing registry keys.

- **Type**: Boolean
- **Default**: `$true`
- **Note**: Set to `$false` to use process-default view
- **Example**: `-Prefer64BitRegistry $false`

## Output Formats

### Console Output (Default)

The script provides three sections of output:

#### 1. OVAL Registry Test Summary
```
=== OVAL Registry Test Summary ===
Test ID: oval:test:123
  Hive:      HKEY_LOCAL_MACHINE
  Key:       SOFTWARE\Microsoft\Windows\CurrentVersion
  Name:      ProgramFilesDir
  Expected:  C:\Program Files
  Operation: equals
  Datatype:  string
```

#### 2. Compliance Summary Table
```
=== SCAP Compliance Summary ===
RuleId              Status Title
------              ------ -----
oval:rule:001       PASS   Ensure audit logging is enabled
oval:rule:002       FAIL   Verify password complexity requirements
oval:rule:003       PASS   Check firewall status
```

#### 3. Detailed Failure Information
```
=== Detailed Failure Information ===

Rule: oval:rule:002
Title: Verify password complexity requirements
Severity: high

  Test Type: Registry
    Path: HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa
    Name: NoLMHash
    Expected: 1
    Actual:   0
    Details: op=equals, datatype=int, caseSensitive=false
```

#### 4. Final Summary
```
=== Final Summary ===
Total Rules Evaluated: 150
Compliant (PASS): 143
Non-Compliant (FAIL): 7
Failure Rate: 4.67%
```

### JSON Output

When `-OutputJson $true` is specified:

```json
[
  {
    "RuleId": "oval:rule:001",
    "RuleTitle": "Ensure audit logging is enabled",
    "Severity": "high",
    "Pass": true,
    "Evidence": [
      {
        "Type": "AuditPolicy",
        "Subcategory": "Logon",
        "Expected": "Success and Failure",
        "Actual": "Success and Failure",
        "Pass": true,
        "Evidence": "auditpol.exe /get /subcategory:\"Logon\" => Success and Failure"
      }
    ]
  },
  {
    "RuleId": "oval:rule:002",
    "RuleTitle": "Verify password complexity requirements",
    "Severity": "medium",
    "Pass": false,
    "Evidence": [
      {
        "Type": "Registry",
        "Path": "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa",
        "Name": "NoLMHash",
        "Expected": "1",
        "Actual": "0",
        "Pass": false,
        "Evidence": "op=equals, datatype=int, caseSensitive=false"
      }
    ]
  }
]
```

## Supported Test Types

### 1. Registry Tests (`registry_test`)

Evaluates Windows registry keys and values.

**Capabilities**:
- Key existence checks
- Value comparison (string, integer, boolean, etc.)
- 32-bit/64-bit registry view support
- Variable reference resolution
- Pattern matching

**Example OVAL Definition**:
```xml
<registry_test id="oval:test:123">
  <object object_ref="oval:obj:123"/>
  <state state_ref="oval:state:123"/>
</registry_test>
```

### 2. WMI Tests (`wmi57_test`, `wmi_test`)

Executes WMI queries and validates results.

**Capabilities**:
- Custom WQL query execution
- Multi-row result handling
- Field-based value comparison
- Entity check modes (all, any, none, only one)
- Existence-only checks

**Example Query**:
```sql
SELECT * FROM Win32_OperatingSystem WHERE Caption LIKE '%Windows Server%'
```

### 3. File Tests (`file_test`)

Checks file system objects.

**Capabilities**:
- File existence verification
- File version comparison
- File size checks
- Path and filename pattern matching

**Supported Operations**:
- Equals, not equal, greater than, less than
- Version string comparison
- Size in bytes

### 4. Service Tests (`service_test`)

Validates Windows service configuration.

**Capabilities**:
- Service existence check
- Start type verification (Automatic, Manual, Disabled)
- Service status check (Running, Stopped, Paused)
- Display name and service name support

**Startup Types**:
- `Auto` / `Automatic`
- `Manual`
- `Disabled`
- `Automatic (Delayed Start)`

### 5. Process Tests (`process_test`)

Detects running processes.

**Capabilities**:
- Process name matching
- Executable path verification
- Existence checks
- Multiple process instance handling

**Query Method**: Uses `Win32_Process` CIM class

### 6. QFE/Hotfix Tests (`qfe_test`, `hotfix_test`)

Verifies Windows update installation.

**Capabilities**:
- Hotfix ID lookup (KB numbers)
- Installation date retrieval
- Existence verification

**Example**: Check if KB5034441 is installed

### 7. Audit Policy Tests (`auditeventpolicysubcategories_test`)

<details>
<summary><strong>⚠️ LIMITED TESTING - Click to expand</strong></summary>

Evaluates advanced audit policy settings.

**Testing Status:** ⚠️ Limited production testing. May fail on non-English Windows or with custom audit configurations.

**Capabilities**:
- Subcategory-level audit settings
- Success/Failure/Both/None verification
- Full audit policy cache for performance
- Multiple parsing strategies

**Supported Subcategories**:
- Logon/Logoff
- Account Lockout
- Sensitive Privilege Use
- Process Creation
- Audit Policy Change
- Object Access (File System, Registry, Handle Manipulation)
- And 40+ more subcategories

**Audit Settings**:
- `Success and Failure`
- `Success`
- `Failure`
- `No Auditing`

**Manual Verification:**
```powershell
# Verify a specific subcategory
auditpol.exe /get /subcategory:"Logon"

# Get all audit policies in raw format
auditpol.exe /get /subcategory:* /r
```

**Known Issues:**
- May fail to parse on non-English Windows installations
- Custom subcategory names may not be recognized
- Some edge cases in auditpol.exe output formatting

</details>

### 8. Lockout Policy Tests (`lockoutpolicy_test`)

<details>
<summary><strong>⚠️ LIMITED TESTING - Click to expand</strong></summary>

Validates account lockout policy configuration.

**Testing Status:** ⚠️ Limited production testing. Requires more validation across Windows versions.

**Capabilities**:
- Lockout threshold (invalid logon attempts)
- Observation window (reset lockout count)
- Lockout duration

**Uses**: `secedit.exe` to export Local Security Policy

**Fields**:
- `LockoutBadCount` - Number of invalid logons before lockout
- `ResetLockoutCount` - Minutes before counter resets
- `LockoutDuration` - Minutes account remains locked

**Manual Verification:**
```powershell
# Check account lockout policy
net accounts

# Or use secedit
secedit.exe /export /cfg C:\temp\secpol.cfg
Get-Content C:\temp\secpol.cfg | Select-String -Pattern "Lockout"
```

**Known Issues:**
- May fail if security database is locked or corrupted
- Group Policy conflicts may affect results
- Requires elevated privileges

</details>

### 9. SID/SID Tests (`sid_sid_test`)

<details>
<summary><strong>⚠️ LIMITED TESTING - Domain accounts UNTESTED - Click to expand</strong></summary>

Maps Security Identifiers to account names.

**Testing Status:** ⚠️ Local accounts tested. **Domain account resolution is UNTESTED.**

**Capabilities**:
- SID to name resolution
- Pattern-based SID matching (RID extraction)
- Local and domain account support (domain support untested)

**Resolution Methods**:
1. `Get-LocalUser` cmdlet (for local accounts)
2. CIM `Win32_UserAccount` query
3. .NET `SecurityIdentifier.Translate()`

**Manual Verification:**
```powershell
# Resolve a SID to name
$sid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-21-...-500")
$sid.Translate([System.Security.Principal.NTAccount]).Value

# Get local user by SID
Get-LocalUser | Where-Object { $_.SID -eq "S-1-5-21-...-500" }
```

**Known Issues:**
- **Domain account resolution is UNTESTED**
- May fail if domain controller is unreachable
- Cross-forest SID resolution not implemented
- Pattern-based SID matching has limited testing

**Before Production Use:**
- Test with your specific domain configuration
- Verify domain account resolution works
- Test with disconnected domain scenarios

</details>

### 10. Access Token Tests (`accesstoken_test`)

<details>
<summary><strong>⚠️ LIMITED TESTING - Incomplete privilege mapping - Click to expand</strong></summary>

Verifies user rights assignments.

**Testing Status:** ⚠️ Only 2 privileges fully mapped. Others use defaults.

**Capabilities**:
- Privilege assignment validation
- SID-based permission checks
- Secedit export parsing

**Fully Mapped Privileges:**
- `SeProfileSingleProcessPrivilege` → Administrators
- `SeImpersonatePrivilege` → Administrators, Local Service, Network Service, Service

**Common Privileges (using defaults):**
- `SeRemoteShutdownPrivilege`
- `SeAuditPrivilege`
- `SeBackupPrivilege`
- `SeRestorePrivilege`
- Many others...

**Expected SIDs:**
- `S-1-5-32-544` - Administrators
- `S-1-5-19` - Local Service
- `S-1-5-20` - Network Service
- `S-1-5-6` - Service

**Manual Verification:**
```powershell
# Export and check user rights
secedit.exe /export /cfg C:\temp\secpol.cfg
Get-Content C:\temp\secpol.cfg | Select-String -Pattern "SeImpersonatePrivilege"
```

**Known Issues:**
- Most privileges use default Administrators group mapping
- Custom privilege assignments may not be detected
- Privilege name to secedit key mapping incomplete

**Before Production Use:**
- Review privilege mapping table in code
- Add mappings for privileges you're testing
- Manually verify critical privilege assignments

</details>

### 11. File Effective Rights Tests (`fileeffectiverights53_test`)

<details>
<summary><strong>⚠️ LIMITED TESTING - Complex ACLs untested - Click to expand</strong></summary>

Checks NTFS file system permissions.

**Testing Status:** ⚠️ Basic permissions tested. Complex ACL structures and inheritance untested.

**Capabilities**:
- Trustee-specific permission checks
- Standard and specific rights validation
- ACL (Access Control List) parsing

**Supported Rights:**
- **Standard**: Delete, ReadControl, WriteDac, WriteOwner, Synchronize
- **Generic**: Read, Write, Execute
- **Specific**: ReadData, WriteData, AppendData, Execute, DeleteChild

**Resolution Method**: `Get-Acl` cmdlet with identity matching

**Manual Verification:**
```powershell
# Check ACL for a file
$acl = Get-Acl -Path "C:\path\to\file"
$acl.Access | Format-Table IdentityReference, FileSystemRights, AccessControlType

# Check specific user's access
$acl.Access | Where-Object { $_.IdentityReference -like "*username*" }
```

**Known Issues:**
- Complex inheritance scenarios untested
- Explicit vs inherited permissions may not distinguish correctly
- Deny ACEs may not be evaluated properly
- Object-specific ACEs (for directories) untested
- Right name to FileSystemRights mapping may be incomplete

**Before Production Use:**
- Test with your specific file permission requirements
- Manually verify complex ACL structures
- Test with both files and directories
- Verify inherited permissions are handled correctly

</details>

## Architecture

### Script Structure

```
PowerSCAP.ps1
├── Parameter Validation
├── XML Helper Functions
│   ├── Select-XmlNodes (namespace-agnostic)
│   ├── Select-XmlNode
│   ├── Get-InnerText
│   └── Get-AttrValue
├── Variable Resolution
│   └── Resolve-VarRef
├── Comparison Logic
│   ├── Convert-ToDatatype
│   └── Compare-Value (operations & datatypes)
├── Registry Helpers
│   └── Get-RegistryItemProperty (64/32-bit support)
├── Test Evaluators (per OVAL test type)
│   ├── Evaluate-RegistryTest
│   ├── Evaluate-WMITest
│   ├── Evaluate-FileTest
│   ├── Evaluate-ServiceTest
│   ├── Evaluate-ProcessTest
│   ├── Evaluate-QfeTest
│   ├── Evaluate-AuditEventPolicySubcategoriesTest
│   ├── Evaluate-LockoutPolicyTest
│   ├── Evaluate-SidSidTest
│   ├── Evaluate-AccessTokenTest
│   └── Evaluate-FileEffectiveRights53Test
├── Test Dispatcher
│   └── Evaluate-Test (routes to appropriate evaluator)
├── Criteria Evaluation (recursive)
│   └── Evaluate-Criteria (AND/OR/NOT logic)
├── Main Evaluation Loop
└── Output Formatting
    ├── Print-EvidenceRecursive
    └── JSON/Console output
```

### Data Flow

1. **Load SCAP XML**: Parse SCAP 1.3 data stream
2. **Build Lookups**: Index definitions, tests, objects, states, variables
3. **Iterate Definitions**: For each OVAL definition:
   - Parse criteria (AND/OR/extend_definition)
   - Resolve test references
   - Dispatch to appropriate evaluator
   - Collect evidence
4. **Aggregate Results**: Compile pass/fail status with evidence
5. **Output**: Format and display results

### Criteria Evaluation Logic

The script supports nested criteria structures:

```xml
<criteria operator="AND" negate="false">
  <criterion test_ref="oval:test:001" negate="false"/>
  <criterion test_ref="oval:test:002"/>
  <criteria operator="OR">
    <criterion test_ref="oval:test:003"/>
    <criterion test_ref="oval:test:004"/>
  </criteria>
  <extend_definition definition_ref="oval:def:999"/>
</criteria>
```

**Evaluation Rules**:
- `AND`: All children must pass
- `OR`: At least one child must pass
- `negate="true"`: Inverts the result
- `extend_definition`: Recursively evaluates referenced definition

## Examples

### Example 1: Full STIG Assessment

```powershell
# Run complete Windows Server 2019 STIG assessment
.\PowerSCAP.ps1 -ScapFile "C:\SCAP\U_MS_Windows_Server_2019_V2R8_STIG_SCAP_1-3_Benchmark.xml" `
    -IncludePerTestDetails $true `
    -Verbose

# Save results to file
.\PowerSCAP.ps1 -ScapFile "C:\SCAP\U_MS_Windows_Server_2019_V2R8_STIG_SCAP_1-3_Benchmark.xml" `
    -OutputJson $true | Out-File "compliance_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
```

### Example 2: Quick Compliance Check

```powershell
# Fast check without detailed evidence
.\PowerSCAP.ps1 -ScapFile "C:\SCAP\Windows_10_STIG.xml" -IncludePerTestDetails $false
```

### Example 3: Automated Scheduling

```powershell
# Create scheduled task for daily compliance checks
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-ExecutionPolicy Bypass -File C:\Scripts\PowerSCAP.ps1 -ScapFile 'C:\SCAP\Windows_Server_2019_STIG.xml' -OutputJson `$true | Out-File 'C:\Logs\compliance_$(Get-Date -Format yyyyMMdd).json'"

$trigger = New-ScheduledTaskTrigger -Daily -At 2am

Register-ScheduledTask -TaskName "SCAP Compliance Check" `
    -Action $action `
    -Trigger $trigger `
    -User "SYSTEM" `
    -RunLevel Highest
```

### Example 4: Integration with SIEM

```powershell
# Generate JSON and send to SIEM
$results = .\PowerSCAP.ps1 -ScapFile "C:\SCAP\Windows_Server_2019_STIG.xml" -OutputJson $true | ConvertFrom-Json

# Filter failures only
$failures = $results | Where-Object { -not $_.Pass }

# Send to Splunk HEC
$splunkUri = "https://splunk.example.com:8088/services/collector"
$splunkToken = "YOUR-HEC-TOKEN"

foreach ($failure in $failures) {
    $event = @{
        event = $failure
        sourcetype = "scap:compliance"
        index = "security"
    } | ConvertTo-Json -Depth 10
    
    Invoke-RestMethod -Uri $splunkUri -Method Post -Headers @{Authorization="Splunk $splunkToken"} -Body $event
}
```

### Example 5: Remediation Workflow

```powershell
# Run assessment and generate remediation script
$results = .\PowerSCAP.ps1 -ScapFile "C:\SCAP\Windows_Server_2019_STIG.xml" -OutputJson $true | ConvertFrom-Json

$remediationScript = @()

foreach ($result in $results | Where-Object { -not $_.Pass }) {
    foreach ($evidence in $result.Evidence) {
        if ($evidence.Type -eq 'Registry') {
            $remediationScript += "# Fix: $($result.RuleTitle)"
            $remediationScript += "Set-ItemProperty -Path '$($evidence.Path)' -Name '$($evidence.Name)' -Value $($evidence.Expected)"
            $remediationScript += ""
        }
    }
}

$remediationScript | Out-File "C:\Remediation\fixes_$(Get-Date -Format 'yyyyMMdd').ps1"
```

## Troubleshooting

### Common Issues

#### Issue: "SCAP file not found"

**Cause**: Incorrect file path or quotes  
**Solution**: Use literal paths and verify file exists
```powershell
Test-Path -LiteralPath "C:\SCAP\Windows_Server_2019_STIG.xml"
```

#### Issue: "Access Denied" errors

**Cause**: Insufficient privileges  
**Solution**: Run PowerShell as Administrator
```powershell
# Check if running as admin
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```

#### Issue: WMI query timeouts

**Cause**: Large result sets or slow WMI provider  
**Solution**: Reduce MaxWmiRows or use CIM
```powershell
.\PowerSCAP.ps1 -ScapFile "..." -MaxWmiRows 500 -UseCim $true
```

#### Issue: Audit policy checks fail

**Cause**: `auditpol.exe` not available or policy not configured  
**Solution**: Verify audit policy is set and system has required tools
```powershell
auditpol.exe /get /subcategory:"Logon"
```

#### Issue: Secedit export fails

**Cause**: Insufficient permissions or locked security database  
**Solution**: Run as SYSTEM or restart to release locks
```powershell
# Export security policy manually to test
secedit.exe /export /cfg C:\temp\test_secpol.cfg
```

### Debug Mode

Enable verbose output for troubleshooting:

```powershell
.\PowerSCAP.ps1 -ScapFile "..." -Verbose
```

This provides:
- XML parsing progress
- Definition evaluation order
- Test type identification
- Intermediate results

### Performance Optimization

For large SCAP files (1000+ definitions):

1. **Disable detailed evidence** if not needed:
   ```powershell
   -IncludePerTestDetails $false
   ```

2. **Reduce WMI row limit** for faster queries:
   ```powershell
   -MaxWmiRows 500
   ```

3. **Enable CIM** for better performance:
   ```powershell
   -UseCim $true
   ```

4. **Run during low-activity periods** to avoid system contention

## Best Practices

### Security

1. **Run as Administrator**: Many checks require elevated privileges
2. **Review SCAP content**: Understand what's being checked before running
3. **Protect results**: JSON output may contain sensitive system information
4. **Audit script execution**: Log all compliance checks for accountability

### Operations

1. **Schedule regular assessments**: Daily or weekly compliance checks
2. **Version control SCAP content**: Track baseline changes over time
3. **Automate remediation**: Use results to generate fix scripts
4. **Integrate with SIEM**: Forward results for centralized monitoring
5. **Maintain evidence**: Keep JSON outputs for audit purposes

### Development

1. **Test in non-production**: Validate script changes in dev/test environments
2. **Add custom test types**: Extend script for organization-specific checks
3. **Contribute improvements**: Share enhancements with the community
4. **Document modifications**: Comment any custom logic added

## Limitations

### Known Limitations

1. **PowerShell 5.1 Compatible**: No PowerShell 7+ operators (`??`, `?:`)
2. **Windows Only**: Script requires Windows-specific APIs and tools
3. **Administrator Rights**: Most security checks require elevation
4. **WMI Performance**: Large queries may be slow on older systems
5. **Audit Policy Parsing**: Complex audit configurations may need manual verification
6. **File System Rights**: Some ACL structures may not be fully parsed

### Unsupported Test Types

The following OVAL test types are not currently implemented:

- `ind-def:sql57_test` (SQL database queries)
- `ind-def:ldap57_test` (LDAP directory queries)
- `win-def:activedirectory57_test` (AD-specific checks)
- `win-def:dnscache_test` (DNS cache inspection)
- `win-def:group_test` (Local group membership)
- Custom/vendor-specific test types

For unsupported tests, the script marks them as "Unknown" and continues evaluation.

## Contributing

We welcome contributions, especially for testing newly implemented features!

### Priority: Help Us Test! 🧪

The following test types need **production validation**:

| Test Type | What We Need | How to Help |
|-----------|--------------|-------------|
| Audit Policy | Test with diverse SCAP content | Run against 10+ different SCAP files, compare with manual `auditpol` checks |
| Lockout Policy | Test on various Windows versions | Test on Server 2012 R2, 2016, 2019, 2022, Windows 10, 11 |
| SID/SID | Test in domain environments | Run in AD environments, test domain account resolution |
| Access Token | Validate privilege mappings | Check against systems with non-standard privilege assignments |
| File Effective Rights | Test complex ACL scenarios | Test with inherited permissions, deny ACEs, special permissions |

**To Submit Test Results:**

1. Run PowerSCAP with `-Verbose` flag
2. Manually verify failed checks
3. Open GitHub Issue with:
   - SCAP file source (sanitized)
   - Test type that failed
   - Expected vs actual results
   - Manual verification output
   - Windows version and environment type

Example Issue Title: `[Test Results] Audit Policy: False negative on Windows Server 2019`

### How to Contribute Code

1. **Report Issues**: Use GitHub Issues for bugs and feature requests
2. **Submit Pull Requests**: Contributions are welcome!
3. **Improve Documentation**: Help expand examples and troubleshooting
4. **Add Test Types**: Implement additional OVAL test evaluators
5. **Expand Privilege Mappings**: Add more privilege-to-SID mappings in `Evaluate-AccessTokenTest`

### Development Guidelines

- Follow existing code structure and naming conventions
- Add verbose logging for new test types
- Include comprehensive error handling and null checks
- Update README with new features and testing status
- Add warnings for untested functionality

### Testing Checklist

Before submitting changes:

- [ ] Test with multiple SCAP sources (DISA, CIS, vendor)
- [ ] Verify PowerShell 5.1 compatibility (avoid PS 7+ features)
- [ ] Test with and without administrator privileges
- [ ] Validate JSON output structure
- [ ] Check verbose logging output
- [ ] Test error handling with invalid inputs
- [ ] Compare results with manual verification
- [ ] Update testing status in README if applicable

### Code Areas Needing Enhancement

**High Priority:**
```powershell
# File: Evaluate-AccessTokenTest function
# Issue: Incomplete privilege mapping
# What to do: Add more entries to $privMap hashtable

$privMap = @{
    'seremoteshutdownprivilege' = @('S-1-5-32-544') # Add expected SIDs
    'seauditprivilege' = @('S-1-5-19','S-1-5-20')
    # ADD MORE PRIVILEGE MAPPINGS HERE
}
```

**Medium Priority:**
```powershell
# File: Evaluate-FileEffectiveRights53Test function
# Issue: Incomplete right name mapping
# What to do: Add more entries to $rightMap hashtable

$rightMap = @{
    'standard_delete' = 'Delete'
    'standard_read_control' = 'ReadPermissions'
    # ADD MORE RIGHT MAPPINGS HERE
}
```

**Documentation Enhancements:**
- Add more real-world examples
- Document edge cases discovered in testing
- Create troubleshooting guides for specific SCAP sources
- Add architecture diagrams

## License

This script is provided as-is for security compliance assessment. Please review your organization's policies regarding script usage and modification.



## Disclaimer

```
⚠️ IMPORTANT DISCLAIMERS

BETA SOFTWARE: This script is in beta status. Newly implemented features have
limited production testing. Use at your own risk.

NO WARRANTY: This software is provided "as is", without warranty of any kind,
express or implied, including but not limited to the warranties of
merchantability, fitness for a particular purpose and noninfringement.

VALIDATION REQUIRED: Always validate compliance results with manual checks and
other compliance tools before making security decisions.

PRIVILEGE REQUIREMENTS: This script requires Administrator privileges to
function correctly. Review all actions before running.

ENVIRONMENT TESTING: Test thoroughly in non-production environments before
deploying to production systems.

KNOWN LIMITATIONS: See "Testing Status" section for details on untested
functionality and known issues.

By using this script, you acknowledge that you have read and understood these
disclaimers and accept responsibility for validating results in your environment.
```

## Support

### Getting Help

- **GitHub Issues**: [Report bugs or request features](https://github.com/accorbett/powerscap/issues)
- **GitHub Discussions**: [Ask questions and share experiences](https://github.com/accorbett/powerscap/discussions)
- **Documentation**: Check this README and inline code comments

### Reporting Issues

When reporting issues, please include:

1. **PowerShell Version**: `$PSVersionTable.PSVersion`
2. **Windows Version**: `Get-ComputerItem | Select-Object Caption, Version, BuildNumber`
3. **SCAP Source**: Where the SCAP file came from (DISA, CIS, etc.)
4. **Error Details**: Full error message and verbose output
5. **Expected vs Actual**: What you expected and what actually happened
6. **Manual Verification**: Results of manual check (if applicable)

### Feature Requests

We're especially interested in:
- Additional OVAL test type implementations
- Improved parsing for existing test types
- Better error handling and user experience
- Performance optimizations
- Integration examples with other tools

## Changelog

### Version 1.0 (Current)

**New Features**:
- Added `lockoutpolicy_test` support (Account Lockout Policy)
- Added `sid_sid_test` support (SID to name mapping)
- Added `accesstoken_test` support (User rights assignments)
- Added `fileeffectiverights53_test` support (NTFS permissions)
- Robust audit policy parsing with full-subcategory cache
- Enhanced WMI entity_check support (including "only one")
- Improved evidence printing for PSCustomObject structures

**Fixes**:
- Removed unsafe `.Count` usage (replaced with `Measure-Object`)
- Hardened null checks across all evaluators
- Fixed registry existence handling when state is absent
- Improved process evaluation via `Win32_Process` CIM
- Enhanced variable reference resolution

**Performance**:
- Audit policy full-cache for faster lookups
- Optimized WMI query execution with row limits
- Reduced redundant XML parsing

## Acknowledgments

- DISA STIG team for comprehensive SCAP content
- Open Vulnerability and Assessment Language (OVAL) community
- Microsoft PowerShell team for robust scripting capabilities

---

**Last Updated**: January 2026  
**Script Version**: 1.0  
**Compatibility**: PowerShell 5.1, Windows Server 2012 R2+, Windows 10/11
