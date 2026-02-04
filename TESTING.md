# PowerSCAP v2.6.0 Testing Guide

## Pre-Testing Checklist

### System Requirements
- [ ] PowerShell 7.0 or higher installed
- [ ] Appropriate permissions (Admin/root for system-level operations)
- [ ] Network connectivity for remote testing
- [ ] Test OVAL/SCAP files available

### Verify Installation
```powershell
# Check PowerShell version
$PSVersionTable

# Import module
Import-Module ./PowerSCAP.psd1 -Force -Verbose

# Verify module loaded
Get-Module PowerSCAP

# List exported functions
Get-Command -Module PowerSCAP
```

Expected output:
```
Name               Version
----               -------
Scan-Computer      2.6.0
Scan-Database      2.6.0
Scan-Domain        2.6.0
Scan-SQLDatabase   2.6.0
Scan-SQLInstance   2.6.0
```

## Unit Tests

### Test 1: Module Loading
```powershell
# Test: Module loads without errors
try {
    Import-Module ./PowerSCAP.psd1 -Force -ErrorAction Stop
    Write-Host "✓ Module loaded successfully" -ForegroundColor Green
} catch {
    Write-Host "✗ Module failed to load: $($_.Exception.Message)" -ForegroundColor Red
}
```

### Test 2: Platform Detection (Local)
```powershell
# Test: Platform detection works correctly
$isLinux = ($PSVersionTable.Platform -eq 'Unix' -or $PSVersionTable.OS -like '*Linux*' -or $IsLinux)
if ($isLinux) {
    Write-Host "✓ Platform detected: Linux" -ForegroundColor Green
} else {
    Write-Host "✓ Platform detected: Windows" -ForegroundColor Green
}
```

### Test 3: Helper Functions Available
```powershell
# Test: Linux helper functions available
if (Get-Command Test-IsLinux -ErrorAction SilentlyContinue) {
    Write-Host "✓ Linux helpers loaded" -ForegroundColor Green
} else {
    Write-Host "✗ Linux helpers not found" -ForegroundColor Red
}

# Test: Remote management functions available
if (Get-Command Install-RemotePowerSCAP -ErrorAction SilentlyContinue) {
    Write-Host "✓ Remote management functions loaded" -ForegroundColor Green
} else {
    Write-Host "✗ Remote management functions not found" -ForegroundColor Red
}
```

### Test 4: Parameter Validation
```powershell
# Test: Scan-Computer parameters
try {
    Get-Command Scan-Computer -Syntax | Out-Null
    Write-Host "✓ Scan-Computer parameters valid" -ForegroundColor Green
} catch {
    Write-Host "✗ Scan-Computer parameter syntax error" -ForegroundColor Red
}

# Test: Scan-SQLDatabase parameters
try {
    Get-Command Scan-SQLDatabase -Syntax | Out-Null
    Write-Host "✓ Scan-SQLDatabase parameters valid" -ForegroundColor Green
} catch {
    Write-Host "✗ Scan-SQLDatabase parameter syntax error" -ForegroundColor Red
}

# Test: Scan-SQLInstance parameters
try {
    Get-Command Scan-SQLInstance -Syntax | Out-Null
    Write-Host "✓ Scan-SQLInstance parameters valid" -ForegroundColor Green
} catch {
    Write-Host "✗ Scan-SQLInstance parameter syntax error" -ForegroundColor Red
}
```

## Functional Tests

### Windows Tests (Run on Windows systems)

#### Test 5: Local Windows OVAL Scan
```powershell
# Test: Local OVAL file scan on Windows
$testFile = "path\to\test.oval.xml"
if (Test-Path $testFile) {
    try {
        $results = Scan-Computer -ScanSourceType File -ScanSource $testFile -Verbose
        Write-Host "✓ Local Windows OVAL scan completed" -ForegroundColor Green
        Write-Host "  Results count: $(($results | Measure-Object).Count)" -ForegroundColor Cyan
    } catch {
        Write-Host "✗ Local Windows OVAL scan failed: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "⊘ Skipped: Test file not found" -ForegroundColor Yellow
}
```

#### Test 6: Windows STIG Compliance Scan
```powershell
# Test: Windows STIG compliance scan
$stigFile = "path\to\Windows_STIG.xml"
if (Test-Path $stigFile) {
    try {
        $results = Scan-Computer -ScanSourceType File -ScanSource $stigFile -Verbose
        Write-Host "✓ Windows STIG scan completed" -ForegroundColor Green
        $passCount = ($results | Where-Object { $_.Pass }).Count
        $failCount = ($results | Where-Object { -not $_.Pass }).Count
        Write-Host "  PASS: $passCount, FAIL: $failCount" -ForegroundColor Cyan
    } catch {
        Write-Host "✗ Windows STIG scan failed: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "⊘ Skipped: STIG file not found" -ForegroundColor Yellow
}
```

#### Test 7: Windows Remote Scan
```powershell
# Test: Remote Windows system scan
$remoteComputer = "WindowsServer01"
$cred = Get-Credential -Message "Enter credentials for $remoteComputer"
$testFile = "path\to\test.xml"

if (Test-Connection $remoteComputer -Count 1 -Quiet) {
    try {
        $results = Scan-Computer -Computer $remoteComputer -ScanSourceType File -ScanSource $testFile -Credential $cred -Verbose
        Write-Host "✓ Remote Windows scan completed" -ForegroundColor Green
    } catch {
        Write-Host "✗ Remote Windows scan failed: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "⊘ Skipped: Remote computer not reachable" -ForegroundColor Yellow
}
```

### Linux Tests (Run on Linux or against Linux systems)

#### Test 8: Local Linux Platform Detection
```powershell
# Test: Linux OS detection
if ($IsLinux) {
    try {
        $linuxInfo = Get-LinuxOSInfo
        Write-Host "✓ Linux OS detected" -ForegroundColor Green
        Write-Host "  Distribution: $($linuxInfo.Distribution)" -ForegroundColor Cyan
        Write-Host "  Version: $($linuxInfo.Version)" -ForegroundColor Cyan
        Write-Host "  Kernel: $($linuxInfo.Kernel)" -ForegroundColor Cyan
    } catch {
        Write-Host "✗ Linux OS detection failed: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "⊘ Skipped: Not running on Linux" -ForegroundColor Yellow
}
```

#### Test 9: Local Linux OVAL Scan
```powershell
# Test: Local OVAL scan on Linux
if ($IsLinux) {
    $testFile = "/path/to/ubuntu.oval.xml"
    if (Test-Path $testFile) {
        try {
            $results = Scan-Computer -ScanSourceType File -ScanSource $testFile -Verbose
            Write-Host "✓ Local Linux OVAL scan completed" -ForegroundColor Green
            Write-Host "  Results count: $(($results | Measure-Object).Count)" -ForegroundColor Cyan
        } catch {
            Write-Host "✗ Local Linux OVAL scan failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "⊘ Skipped: Test file not found" -ForegroundColor Yellow
    }
} else {
    Write-Host "⊘ Skipped: Not running on Linux" -ForegroundColor Yellow
}
```

#### Test 10: Remote Linux Scan
```powershell
# Test: Remote Linux system scan
$linuxServer = "linuxserver01"
$cred = Get-Credential -Message "Enter credentials for $linuxServer"
$testFile = "path\to\linux.oval.xml"

try {
    $results = Scan-Computer -Computer $linuxServer -ScanSourceType File -ScanSource $testFile -Credential $cred -Verbose
    Write-Host "✓ Remote Linux scan completed" -ForegroundColor Green
    Write-Host "  Results count: $(($results | Measure-Object).Count)" -ForegroundColor Cyan
} catch {
    Write-Host "✗ Remote Linux scan failed: $($_.Exception.Message)" -ForegroundColor Red
}
```

#### Test 11: Linux Package Detection
```powershell
# Test: Linux package information retrieval
if ($IsLinux) {
    try {
        $packages = Get-LinuxPackageInfo
        $packageCount = ($packages | Measure-Object).Count
        Write-Host "✓ Linux package detection successful" -ForegroundColor Green
        Write-Host "  Packages found: $packageCount" -ForegroundColor Cyan
    } catch {
        Write-Host "✗ Linux package detection failed: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "⊘ Skipped: Not running on Linux" -ForegroundColor Yellow
}
```

### SQL Server Tests

#### Test 12: SQL Instance Scan (Local)
```powershell
# Test: Local SQL Server instance scan
$stigFile = "path\to\SQL_Instance_STIG.xml"
if (Test-Path $stigFile) {
    try {
        $results = Scan-SQLInstance -ScanSourceType File -ScanSource $stigFile -Verbose
        Write-Host "✓ SQL Instance scan completed" -ForegroundColor Green
        $passCount = ($results | Where-Object { $_.Pass }).Count
        $failCount = ($results | Where-Object { -not $_.Pass }).Count
        Write-Host "  PASS: $passCount, FAIL: $failCount" -ForegroundColor Cyan
    } catch {
        Write-Host "✗ SQL Instance scan failed: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "⊘ Skipped: STIG file not found" -ForegroundColor Yellow
}
```

#### Test 13: SQL Database Scan (Local)
```powershell
# Test: Local SQL Server database scan
$stigFile = "path\to\SQL_Database_STIG.xml"
$database = "TestDB"
if (Test-Path $stigFile) {
    try {
        $results = Scan-SQLDatabase -ScanSourceType File -ScanSource $stigFile -Database $database -Verbose
        Write-Host "✓ SQL Database scan completed" -ForegroundColor Green
        $passCount = ($results | Where-Object { $_.Pass }).Count
        $failCount = ($results | Where-Object { -not $_.Pass }).Count
        Write-Host "  PASS: $passCount, FAIL: $failCount" -ForegroundColor Cyan
    } catch {
        Write-Host "✗ SQL Database scan failed: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "⊘ Skipped: STIG file not found" -ForegroundColor Yellow
}
```

#### Test 14: SQL Remote Scan
```powershell
# Test: Remote SQL Server scan
$sqlServer = "SQLSERVER01"
$stigFile = "path\to\SQL_Instance_STIG.xml"
$cred = Get-Credential -Message "Enter SQL credentials for $sqlServer"

try {
    $results = Scan-SQLInstance -ScanSourceType File -ScanSource $stigFile -Computer $sqlServer -Credential $cred -Verbose
    Write-Host "✓ Remote SQL scan completed" -ForegroundColor Green
} catch {
    Write-Host "✗ Remote SQL scan failed: $($_.Exception.Message)" -ForegroundColor Red
}
```

### Output Format Tests

#### Test 15: JSON Output
```powershell
# Test: JSON output format
$testFile = "path\to\test.xml"
if (Test-Path $testFile) {
    try {
        $jsonOutput = Scan-Computer -ScanSourceType File -ScanSource $testFile -Output JSON
        $parsed = $jsonOutput | ConvertFrom-Json
        Write-Host "✓ JSON output successful" -ForegroundColor Green
        Write-Host "  JSON parseable: $($null -ne $parsed)" -ForegroundColor Cyan
    } catch {
        Write-Host "✗ JSON output failed: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "⊘ Skipped: Test file not found" -ForegroundColor Yellow
}
```

#### Test 16: CSV Output
```powershell
# Test: CSV output format
$testFile = "path\to\test.xml"
if (Test-Path $testFile) {
    try {
        $csvOutput = Scan-Computer -ScanSourceType File -ScanSource $testFile -Output CSV
        $parsed = $csvOutput | ConvertFrom-Csv
        Write-Host "✓ CSV output successful" -ForegroundColor Green
        Write-Host "  CSV parseable: $($null -ne $parsed)" -ForegroundColor Cyan
    } catch {
        Write-Host "✗ CSV output failed: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "⊘ Skipped: Test file not found" -ForegroundColor Yellow
}
```

### InstallPowerSCAP Tests

#### Test 17: Remote Installation (WhileScanning)
```powershell
# Test: Temporary remote installation
$remoteComputer = "TestServer"
$testFile = "path\to\test.xml"
$cred = Get-Credential -Message "Enter credentials for $remoteComputer"

try {
    $results = Scan-Computer -Computer $remoteComputer -ScanSourceType File -ScanSource $testFile -InstallPowerSCAP WhileScanning -Credential $cred -Verbose
    Write-Host "✓ WhileScanning mode successful" -ForegroundColor Green
    Write-Host "  (Module should be auto-removed after scan)" -ForegroundColor Cyan
} catch {
    Write-Host "✗ WhileScanning mode failed: $($_.Exception.Message)" -ForegroundColor Red
}
```

## .Count Bug Verification Tests

#### Test 18: Empty Result Handling
```powershell
# Test: Handling of empty results (tests .Count bug fix)
# This should NOT throw "Cannot index into a null array" error
$testFile = "path\to\empty_results.xml"  # File that returns no results
if (Test-Path $testFile) {
    try {
        $results = Scan-Computer -ScanSourceType File -ScanSource $testFile -Verbose
        $count = ($results | Measure-Object).Count
        Write-Host "✓ Empty result handling successful" -ForegroundColor Green
        Write-Host "  No .Count bug encountered" -ForegroundColor Cyan
    } catch {
        Write-Host "✗ Empty result handling failed: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "⊘ Skipped: Test file not found" -ForegroundColor Yellow
}
```

#### Test 19: Single Result Handling
```powershell
# Test: Handling of single result (tests .Count bug fix)
# This should NOT treat single object differently from array
$testFile = "path\to\single_result.xml"  # File that returns exactly one result
if (Test-Path $testFile) {
    try {
        $results = Scan-Computer -ScanSourceType File -ScanSource $testFile -Verbose
        $count = if ($results -is [array]) { $results.Count } else { 1 }
        Write-Host "✓ Single result handling successful" -ForegroundColor Green
        Write-Host "  Result count: $count" -ForegroundColor Cyan
    } catch {
        Write-Host "✗ Single result handling failed: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "⊘ Skipped: Test file not found" -ForegroundColor Yellow
}
```

## Cross-Platform Integration Tests

#### Test 20: Mixed Environment Scan
```powershell
# Test: Scan both Windows and Linux from single session
$windowsServer = "WinServer01"
$linuxServer = "LinuxServer01"
$winFile = "path\to\windows.xml"
$linuxFile = "path\to\linux.xml"
$cred = Get-Credential

try {
    Write-Host "Scanning Windows server..." -ForegroundColor Cyan
    $winResults = Scan-Computer -Computer $windowsServer -ScanSourceType File -ScanSource $winFile -Credential $cred
    
    Write-Host "Scanning Linux server..." -ForegroundColor Cyan
    $linuxResults = Scan-Computer -Computer $linuxServer -ScanSourceType File -ScanSource $linuxFile -Credential $cred
    
    Write-Host "✓ Mixed environment scan successful" -ForegroundColor Green
    Write-Host "  Windows results: $(($winResults | Measure-Object).Count)" -ForegroundColor Cyan
    Write-Host "  Linux results: $(($linuxResults | Measure-Object).Count)" -ForegroundColor Cyan
} catch {
    Write-Host "✗ Mixed environment scan failed: $($_.Exception.Message)" -ForegroundColor Red
}
```

## Performance Tests

#### Test 21: Large File Handling
```powershell
# Test: Handling of large OVAL/SCAP files
$largeFile = "path\to\large.xml"  # File > 10MB
if (Test-Path $largeFile) {
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $results = Scan-Computer -ScanSourceType File -ScanSource $largeFile -Verbose
        $stopwatch.Stop()
        Write-Host "✓ Large file handling successful" -ForegroundColor Green
        Write-Host "  Time: $($stopwatch.Elapsed.TotalSeconds) seconds" -ForegroundColor Cyan
        Write-Host "  Results: $(($results | Measure-Object).Count)" -ForegroundColor Cyan
    } catch {
        Write-Host "✗ Large file handling failed: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "⊘ Skipped: Large test file not found" -ForegroundColor Yellow
}
```

## Test Summary Script

```powershell
# Run all applicable tests and generate summary
$testResults = @()

# Add your test results to this array
# Example:
# $testResults += @{ Name = "Test 1"; Status = "PASS"; Notes = "..." }

# Generate summary
$passCount = ($testResults | Where-Object { $_.Status -eq "PASS" }).Count
$failCount = ($testResults | Where-Object { $_.Status -eq "FAIL" }).Count
$skipCount = ($testResults | Where-Object { $_.Status -eq "SKIP" }).Count

Write-Host "`n=== Test Summary ===" -ForegroundColor Cyan
Write-Host "PASSED: $passCount" -ForegroundColor Green
Write-Host "FAILED: $failCount" -ForegroundColor Red
Write-Host "SKIPPED: $skipCount" -ForegroundColor Yellow
Write-Host "TOTAL: $($testResults.Count)" -ForegroundColor White

if ($failCount -eq 0) {
    Write-Host "`n✓ All tests passed!" -ForegroundColor Green
} else {
    Write-Host "`n✗ Some tests failed. Review output above." -ForegroundColor Red
}
```

## Notes
- Replace file paths with actual test files
- Some tests require network connectivity
- Some tests require appropriate credentials
- Run tests in a non-production environment first
- Linux tests require PowerShell 7.x
- SQL tests require SQL Server access
