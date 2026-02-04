# PowerSCAP v2.4.0 - Automatic Vulnerability Download Feature

## Overview

PowerSCAP v2.4.0 introduces automatic vulnerability definition download from multiple sources including NVD (National Vulnerability Database), MSRC (Microsoft Security Response Center), and archived OVAL repositories. This eliminates the need to manually obtain vulnerability definitions before scanning.

## Quick Start

### Basic Usage - Download and Scan

```powershell
# Download Windows 10 OVAL definitions and scan
Scan-Computer -DownloadVulnerabilities -VulnerabilitySource Windows10OVAL

# Download from NVD and scan
Scan-Computer -DownloadVulnerabilities -VulnerabilitySource NVD

# Download from MSRC and scan
Scan-Computer -DownloadVulnerabilities -VulnerabilitySource MSRC

# Download from all sources
Scan-Computer -DownloadVulnerabilities -VulnerabilitySource All
```

## Vulnerability Sources

### 1. Windows10OVAL (Recommended for Application Vulnerabilities)

Downloads archived OVAL vulnerability definitions from MITRE's repository. These definitions cover application vulnerabilities (Chrome, Java, Adobe, etc.) that also apply to Windows 11.

**Pros:**
- Contains actual OVAL test logic (can detect vulnerabilities)
- Covers many common applications
- No API key required
- No rate limits

**Cons:**
- Archived content (no longer updated)
- Limited to pre-2025 vulnerabilities
- No Windows 11-specific definitions

**Example:**
```powershell
Scan-Computer -DownloadVulnerabilities -VulnerabilitySource Windows10OVAL
```

### 2. NVD (National Vulnerability Database)

Downloads recent CVE data from NVD with CPE matching for Windows platforms.

**Pros:**
- Up-to-date CVE information
- Comprehensive coverage of all software
- Includes CVSS severity scores
- Free to use

**Cons:**
- Does NOT include detection logic (metadata only)
- Requires API key for reasonable rate limits
- Complex to convert to actionable tests

**Get a Free API Key:** https://nvd.nist.gov/developers/request-an-api-key

**Example:**
```powershell
# Without API key (5 requests per 30 seconds)
Scan-Computer -DownloadVulnerabilities -VulnerabilitySource NVD -VulnerabilityDaysBack 30

# With API key (50 requests per 30 seconds - recommended)
Scan-Computer -DownloadVulnerabilities `
              -VulnerabilitySource NVD `
              -NVDApiKey "your-api-key-here" `
              -VulnerabilityDaysBack 90 `
              -MaxVulnerabilities 500
```

### 3. MSRC (Microsoft Security Response Center)

Downloads Microsoft's official CVE data for Windows and Microsoft products.

**Pros:**
- Official Microsoft vulnerability data
- Authoritative for Windows/Microsoft products
- Includes KB article references

**Cons:**
- Does NOT include detection logic (metadata only)
- Limited to Microsoft products only
- Rate limited

**Example:**
```powershell
Scan-Computer -DownloadVulnerabilities `
              -VulnerabilitySource MSRC `
              -VulnerabilityDaysBack 60
```

### 4. All Sources (Comprehensive)

Downloads from all available sources for maximum coverage.

**Example:**
```powershell
Scan-Computer -DownloadVulnerabilities `
              -VulnerabilitySource All `
              -NVDApiKey "your-api-key" `
              -DownloadDirectory "C:\VulnScans\$(Get-Date -Format yyyyMMdd)"
```

## Parameters

### -DownloadVulnerabilities
**Type:** Switch  
**Required:** Yes (when downloading)  
**Description:** Enables automatic vulnerability download before scanning.

### -VulnerabilitySource
**Type:** String  
**Required:** Yes (when downloading)  
**Values:** 'NVD', 'MSRC', 'Windows10OVAL', 'All'  
**Description:** Specifies which source(s) to download from.

### -DownloadDirectory
**Type:** String  
**Default:** `$env:TEMP\PowerSCAP_Vulnerabilities_yyyyMMdd`  
**Description:** Directory for downloaded files. Files are cached and reused if the directory already exists.

### -NVDApiKey
**Type:** String  
**Required:** No  
**Description:** NVD API key for improved rate limits (5→50 requests/30s). Get free key at: https://nvd.nist.gov/developers/request-an-api-key

### -VulnerabilityDaysBack
**Type:** Integer  
**Default:** 90  
**Description:** For NVD and MSRC, how many days back to retrieve CVEs.

### -MaxVulnerabilities
**Type:** Integer  
**Default:** 100  
**Max:** 2000 (NVD limit)  
**Description:** Maximum number of vulnerabilities to download.

## Real-World Examples

### Example 1: Quick Security Check

```powershell
# Fast scan with cached OVAL definitions
Scan-Computer -DownloadVulnerabilities -VulnerabilitySource Windows10OVAL
```

### Example 2: Comprehensive Monthly Scan

```powershell
# Download last 30 days from all sources and scan
$apiKey = Get-Content "C:\Secure\nvd-api-key.txt"

$results = Scan-Computer -DownloadVulnerabilities `
                         -VulnerabilitySource All `
                         -NVDApiKey $apiKey `
                         -VulnerabilityDaysBack 30 `
                         -MaxVulnerabilities 1000 `
                         -OutputJson | ConvertFrom-Json

# Export critical vulnerabilities
$critical = $results | Where-Object { -not $_.Pass -and $_.Severity -in @('Critical','High') }
$critical | Export-Csv "Critical-Vulnerabilities-$(Get-Date -Format yyyyMMdd).csv" -NoTypeInformation
```

### Example 3: Remote Server Scanning

```powershell
# Scan multiple remote servers with downloaded definitions
$servers = Get-Content "servers.txt"
$cred = Get-Credential

# Download once (cached in temp)
Write-Host "Downloading vulnerability definitions..."
Scan-Computer -DownloadVulnerabilities -VulnerabilitySource Windows10OVAL -ComputerName localhost

# Scan all servers using cached downloads
$allResults = foreach ($server in $servers) {
    Write-Host "Scanning $server..."
    
    $scanResults = Scan-Computer -VulnerabilityDirectory "$env:TEMP\PowerSCAP_Vulnerabilities_$(Get-Date -Format yyyyMMdd)" `
                                 -ComputerName $server `
                                 -Credential $cred `
                                 -OutputJson | ConvertFrom-Json
    
    [PSCustomObject]@{
        Server = $server
        ScanDate = Get-Date
        TotalChecks = $scanResults.Count
        Vulnerable = ($scanResults | Where-Object { -not $_.Pass }).Count
        Critical = ($scanResults | Where-Object { -not $_.Pass -and $_.Severity -eq 'Critical' }).Count
        Results = $scanResults
    }
}

# Generate report
$allResults | ConvertTo-Json -Depth 10 | Out-File "Multi-Server-Scan-$(Get-Date -Format yyyyMMdd).json"
```

### Example 4: Scheduled Daily Scans

```powershell
# Script for scheduled task
$ErrorActionPreference = 'Stop'
$logDir = "C:\SecurityScans\Logs"
$apiKey = Get-Content "C:\SecurityScans\nvd-api-key.txt"

try {
    # Download and scan
    $results = Scan-Computer -DownloadVulnerabilities `
                             -VulnerabilitySource All `
                             -NVDApiKey $apiKey `
                             -VulnerabilityDaysBack 7 `
                             -DownloadDirectory "C:\SecurityScans\Definitions\$(Get-Date -Format yyyyMMdd)" `
                             -OutputJson | ConvertFrom-Json
    
    # Save results
    $results | ConvertTo-Json -Depth 10 | Out-File "$logDir\scan-$(Get-Date -Format yyyyMMdd-HHmmss).json"
    
    # Alert on critical findings
    $critical = $results | Where-Object { -not $_.Pass -and $_.Severity -eq 'Critical' }
    if ($critical.Count -gt 0) {
        $emailBody = @"
Critical vulnerabilities found on $env:COMPUTERNAME:

$($critical | ForEach-Object { "- $($_.CVE): $($_.RuleTitle)" } | Out-String)

Full report: $logDir\scan-$(Get-Date -Format yyyyMMdd-HHmmss).json
"@
        
        Send-MailMessage -To "security@company.com" `
                        -From "powerscan@company.com" `
                        -Subject "CRITICAL: $($critical.Count) vulnerabilities on $env:COMPUTERNAME" `
                        -Body $emailBody `
                        -SmtpServer "smtp.company.com"
    }
    
} catch {
    # Log error
    $_ | Out-File "$logDir\error-$(Get-Date -Format yyyyMMdd-HHmmss).txt"
    
    # Email error
    Send-MailMessage -To "security@company.com" `
                    -From "powerscan@company.com" `
                    -Subject "ERROR: PowerSCAP scan failed on $env:COMPUTERNAME" `
                    -Body $_.Exception.Message `
                    -SmtpServer "smtp.company.com"
}
```

## Download Caching

PowerSCAP caches downloads by date to avoid re-downloading the same data:

```powershell
# First run - downloads files
Scan-Computer -DownloadVulnerabilities -VulnerabilitySource NVD
# Downloads to: $env:TEMP\PowerSCAP_Vulnerabilities_20260202

# Second run same day - uses cached files
Scan-Computer -DownloadVulnerabilities -VulnerabilitySource NVD
# Output: "Using cached vulnerability definitions from: ..."

# Force re-download
Remove-Item "$env:TEMP\PowerSCAP_Vulnerabilities_$(Get-Date -Format yyyyMMdd)" -Recurse -Force
Scan-Computer -DownloadVulnerabilities -VulnerabilitySource NVD

# Or use custom directory
Scan-Computer -DownloadVulnerabilities -VulnerabilitySource NVD -DownloadDirectory "C:\VulnScans\Fresh"
```

## Understanding Limitations

### Important: Detection Logic vs. Metadata

**Sources with Detection Logic (Can actually detect vulnerabilities):**
- ✅ **Windows10OVAL** - Contains complete OVAL tests with detection logic

**Sources with Metadata Only (Cannot detect, just provides information):**
- ⚠️ **NVD** - CVE descriptions, severity, CPE matching (NO detection logic)
- ⚠️ **MSRC** - CVE information, KB articles (NO detection logic)

### What This Means

When you download from NVD or MSRC, PowerSCAP creates OVAL-like XML files with **placeholder criteria**. These files contain vulnerability metadata (CVE ID, severity, description) but **cannot actually test if the vulnerability exists**.

**Example - NVD/MSRC Output:**
```xml
<definition id="oval:org.nvd:def:1000" class="vulnerability">
  <metadata>
    <title>CVE-2024-12345 - Windows Vulnerability</title>
    <reference source="CVE" ref_id="CVE-2024-12345"/>
    <severity>High</severity>
    <description>...</description>
  </metadata>
  <criteria comment="Placeholder - NVD data does not include detection logic"/>
  <!-- ^ This means it WON'T actually test your system -->
</definition>
```

**Recommendation:**
- Use **Windows10OVAL** for actual vulnerability detection
- Use **NVD/MSRC** for awareness and correlation with other tools
- Combine sources: OVAL for detection + NVD for current awareness

## Troubleshooting

### Issue: NVD Rate Limit Errors

**Error:** "NVD API Error: Too Many Requests"

**Solution:**
1. Get a free API key: https://nvd.nist.gov/developers/request-an-api-key
2. Add `-NVDApiKey` parameter
3. Reduce `-MaxVulnerabilities` or `-VulnerabilityDaysBack`

### Issue: MSRC Returns No Data

**Error:** "No vulnerabilities found in MSRC"

**Cause:** MSRC uses monthly update format (2026-Jan, 2026-Feb, etc.)

**Solution:**
- Increase `-VulnerabilityDaysBack` to span more months
- MSRC may have no updates for very recent dates

### Issue: Windows10OVAL Download Fails

**Error:** "Failed to download: 404"

**Cause:** MITRE archived site may be unavailable

**Solution:**
1. Manual download from: https://oval.mitre.org/rep-data/5.10/org.mitre.oval/v/family/windows.xml
2. Save to a directory
3. Use: `Scan-Computer -VulnerabilityDirectory "C:\path\to\oval\files"`

### Issue: Downloaded Files But No Vulnerabilities Found

**Cause:** Most likely downloaded NVD/MSRC data which lacks detection logic

**Solution:**
- Use Windows10OVAL source for actual vulnerability detection
- Check if files contain `<criteria>` with actual tests (not "Placeholder")

## Best Practices

1. **Get an NVD API Key** - Essential for reasonable rate limits
2. **Use Windows10OVAL for Detection** - Only source with actual test logic
3. **Cache Aggressively** - Reuse downloads for multiple machines
4. **Schedule Weekly** - Check for new vulnerabilities regularly
5. **Combine Sources** - OVAL for detection + NVD for current awareness
6. **Monitor Critical Only** - Filter for Critical/High severity to reduce noise
7. **Version Control Definitions** - Keep dated backups of vulnerability definitions

## Integration with CI/CD

```powershell
# In build pipeline
$scanResults = Scan-Computer -DownloadVulnerabilities `
                             -VulnerabilitySource Windows10OVAL `
                             -OutputJson | ConvertFrom-Json

$criticalVulns = $scanResults | Where-Object { -not $_.Pass -and $_.Severity -eq 'Critical' }

if ($criticalVulns.Count -gt 0) {
    Write-Error "Build blocked: $($criticalVulns.Count) critical vulnerabilities found"
    exit 1
}

Write-Host "✓ No critical vulnerabilities detected"
```

## API Key Management

### Secure Storage

```powershell
# Save API key securely
$apiKey = Read-Host "Enter NVD API Key" -AsSecureString
$apiKey | ConvertFrom-SecureString | Out-File "C:\Secure\nvd-api.key"

# Load API key
$secureKey = Get-Content "C:\Secure\nvd-api.key" | ConvertTo-SecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
$apiKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

# Use in scan
Scan-Computer -DownloadVulnerabilities -VulnerabilitySource NVD -NVDApiKey $apiKey
```

## Conclusion

The automatic download feature in PowerSCAP v2.4.0 streamlines vulnerability scanning by eliminating manual definition management. While only Windows10OVAL provides actual detection capabilities, combining multiple sources provides comprehensive vulnerability awareness for your Windows environment.

For questions or issues, please file an issue at the PowerSCAP GitHub repository.
