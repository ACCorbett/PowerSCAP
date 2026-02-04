function Scan-SQLInstance {
<#
.SYNOPSIS
  Scan a SQL Server instance for STIG compliance using an XCCDF benchmark.

.DESCRIPTION
  PowerSCAP v2.6.0 - Parses an XCCDF STIG benchmark (e.g., MS SQL Server 2016 Instance STIG),
  extracts T-SQL checks from each rule's check-content, executes them against
  the target SQL Server instance, and evaluates results against documented
  pass/fail criteria. Outputs match the schema of Scan-Computer for consistency.

  Connection can be established via an explicit -ConnectionString, or by
  specifying -Computer (with optional -Credential). When no connection
  parameters are given, connects to the default local instance (localhost).

.PARAMETER ScanSourceType
  How to obtain scan definitions (REQUIRED):
  - File: Single XCCDF STIG file

.PARAMETER ScanSource
  Source for scan definitions (REQUIRED):
  - For File: Path to XCCDF file (e.g., "U_MS_SQL_Server_2016_Instance_STIG_*.xml")

.PARAMETER Computer
  Target SQL Server hostname or IP. Defaults to localhost when omitted.
  Can include an instance name (e.g., "SERVER01\SQLEXPRESS").

.PARAMETER Output
  Output format:
  - Console: Formatted console output with color coding (default)
  - JSON: JSON format
  - CSV: Comma-separated values
  - TSV: Tab-separated values
  - Legacy: Original PowerSCAP console output

.PARAMETER IncludePerTestDetails
  Include per-query evidence and row data in the output (default: $true).

.PARAMETER Credential
  PSCredential for SQL Server authentication. When omitted, Windows (integrated)
  authentication is used.

.PARAMETER InstallPowerSCAP
  Controls PowerSCAP installation for remote scanning:
  - No (default): Direct connection (no installation)
  - Yes: Installs if needed, then runs locally (faster for multiple scans)
  - Upgrade: Always installs/upgrades, then runs locally
  - WhileScanning: Temporarily installs, scans, then removes

.PARAMETER ConnectionString
  Full ADO.NET connection string. When provided, Computer and Credential are
  ignored. This gives full control over connection options (timeouts, encryption, etc.).

.EXAMPLE
  # Scan local default instance with integrated auth
  Scan-SQLInstance -ScanSourceType File -ScanSource ".\Instance_STIG.xml"

.EXAMPLE
  # Scan remote instance with SQL auth
  $cred = Get-Credential "sa"
  Scan-SQLInstance -ScanSourceType File -ScanSource ".\Instance_STIG.xml" -Computer "DBSERVER01" -Credential $cred -Output JSON

.EXAMPLE
  # Scan with an explicit connection string
  Scan-SQLInstance -ScanSourceType File -ScanSource ".\Instance_STIG.xml" -ConnectionString "Server=DBSERVER01\INST1;Database=master;Integrated Security=true;Encrypt=true;"

.NOTES
  PowerSCAP v2.6.0 - Aligned parameters with Scan-Computer for consistency
#>
    [CmdletBinding()]
    param(
        # Scan Configuration - Aligned with Scan-Computer
        [Parameter(Mandatory)]
        [ValidateSet('File')]
        [string]$ScanSourceType = 'File',

        [Parameter(Mandatory)]
        [string]$ScanSource,
        
        # Target System - Aligned with Scan-Computer
        [Parameter()]
        [Alias('ComputerName')]
        [string]$Computer,

        # Output Configuration - Aligned with Scan-Computer
        [Parameter()]
        [ValidateSet('Console', 'JSON', 'CSV', 'TSV', 'Legacy')]
        [string]$Output = 'Console',
        
        # Execution Parameters - Aligned with Scan-Computer
        [Parameter()]
        [bool]$IncludePerTestDetails = $true,
        
        # Remote Scanning Parameters - Aligned with Scan-Computer
        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,
        
        [Parameter()]
        [ValidateSet('Yes', 'Upgrade', 'WhileScanning', 'No')]
        [string]$InstallPowerSCAP = 'No',
        
        # SQL-Specific Parameters
        [Parameter()]
        [string]$ConnectionString
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    
    # Map ScanSource to internal ScapFile parameter
    $ScapFile = $ScanSource
    
    # Map Output to internal flags
    $OutputJson = ($Output -eq 'JSON')
    $outputNeedsConversion = ($Output -in @('CSV', 'TSV'))

    # --- Validate SCAP file ---
    $ScapFile = ($ScapFile -replace '[""]', '"').Trim().Trim('"').Trim("'")
    try {
        $resolvedPath = (Resolve-Path -LiteralPath $ScapFile -ErrorAction Stop).Path
    } catch {
        throw "SCAP file not found. Checked path: $ScapFile. Error: $($_.Exception.Message)"
    }

    # --- Load and parse XML ---
    Write-Verbose "Loading XCCDF benchmark: $resolvedPath"
    try {
        [xml]$xml = Get-Content -LiteralPath $resolvedPath -Raw -ErrorAction Stop
    } catch {
        throw "Failed to load XML from '$resolvedPath'. Error: $($_.Exception.Message)"
    }

    # --- Parse XCCDF rules ---
    Write-Verbose "Parsing XCCDF rules..."
    $rules = Parse-XccdfRules -Xml $xml
    $ruleCount = (Get-SafeCount $rules)
    if ($ruleCount -eq 0) {
        Write-Error "No XCCDF rules found in the benchmark file."
        return
    }
    Write-Verbose "Found $ruleCount rules."

    # --- Establish SQL connection ---
    $targetLabel = if (-not [string]::IsNullOrWhiteSpace($ConnectionString)) {
        # Extract server name from connection string for display
        $m = [System.Text.RegularExpressions.Regex]::Match($ConnectionString, '(?i)Server\s*=\s*([^;]+)')
        if ($m.Success) { $m.Groups[1].Value.Trim() } else { '(connection string)' }
    } elseif (-not [string]::IsNullOrWhiteSpace($Computer)) {
        $Computer.Trim()
    } else {
        'localhost'
    }

    Write-Verbose "Connecting to SQL instance: $targetLabel"
    $conn = $null
    try {
        $conn = Build-SqlConnection -ConnectionString $ConnectionString -ComputerName $Computer -Credential $Credential -Database 'master'
    } catch {
        throw "Failed to connect to SQL Server '$targetLabel'. Error: $($_.Exception.Message)"
    }

    # --- Evaluate each rule ---
    $results = @()
    $evalCount = 0

    try {
        foreach ($rule in $rules) {
            $evalCount++
            $pct = [math]::Round(($evalCount / [double]$ruleCount) * 100, 2)
            Write-Progress -Activity "Scanning SQL Instance: $targetLabel" `
                           -Status "Evaluating rule $evalCount of $ruleCount ($pct%)" `
                           -PercentComplete $pct

            $evalResult = Evaluate-SqlRule -Rule $rule -Connection $conn -IncludeDetails $IncludePerTestDetails

            $obj = [PSCustomObject]@{
                RuleId    = $evalResult.RuleId
                RuleTitle = $evalResult.RuleTitle
                Severity  = $evalResult.Severity
                Pass      = $evalResult.Pass
            }

            if ($IncludePerTestDetails) {
                $obj | Add-Member -NotePropertyName Evidence  -NotePropertyValue $evalResult.Evidence
                $obj | Add-Member -NotePropertyName StatusNote -NotePropertyValue $evalResult.StatusNote
            }

            $results += $obj
        }
    } finally {
        # Always clean up the connection
        if ($conn) {
            try { $conn.Close(); $conn.Dispose() } catch {}
        }
        Write-Progress -Activity "Scanning SQL Instance: $targetLabel" -Completed
    }

    # --- Output ---
    $passResults = @($results | Where-Object { $_.Pass })
    $failResults = @($results | Where-Object { -not $_.Pass })
    $passCount = (Get-SafeCount $passResults)
    $failCount = (Get-SafeCount $failResults)
    $totalCount = (Get-SafeCount $results)

    if ($outputNeedsConversion) {
        # Convert to CSV or TSV
        $delimiter = if ($Output -eq 'CSV') { ',' } else { "`t" }
        $flatResults = $results | Select-Object RuleId, @{n='Status'; e={ if ($_.Pass) { 'PASS' } else { 'FAIL' } }}, Severity, RuleTitle
        return ($flatResults | ConvertTo-Csv -NoTypeInformation -Delimiter $delimiter)
    } elseif ($OutputJson) {
        return ($results | ConvertTo-Json -Depth 8)
    } else {
        Write-Host "`n=== SQL Instance STIG Compliance Summary ===" -ForegroundColor Cyan
        Write-Host "Target: $targetLabel" -ForegroundColor White
        $results |
          Select-Object RuleId, @{n='Status'; e={ if ($_.Pass) { 'PASS' } else { 'FAIL' } }}, Severity, RuleTitle |
          Format-Table -AutoSize

        Write-Host "`nCompleted: $evalCount/$ruleCount rules evaluated" -ForegroundColor White
        Write-Host "PASS: $passCount, FAIL: $failCount" -ForegroundColor White

        if ($failCount -gt 0 -and $totalCount -gt 0) {
            $failureRate = [math]::Round(($failCount / $totalCount) * 100, 2)
            Write-Host ("Failure Rate: {0}%" -f $failureRate) -ForegroundColor Yellow

            Write-Host "`n=== Failure Details ===" -ForegroundColor Yellow
            foreach ($result in $failResults) {
                Write-Host "`nRule: $($result.RuleId)" -ForegroundColor Red
                Write-Host "Title: $($result.RuleTitle)" -ForegroundColor Blue
                if ($result.Severity) {
                    $sevColor = switch ($result.Severity.ToLower()) { 'high' { 'Red' }; 'medium' { 'Yellow' }; 'low' { 'Green' }; default { 'White' } }
                    Write-Host "Severity: $($result.Severity.ToUpper())" -ForegroundColor $sevColor
                }
                if ($result.PSObject.Properties['StatusNote'] -and $result.StatusNote) {
                    Write-Host "  Status: $($result.StatusNote)" -ForegroundColor DarkGray
                }
                if ($result.PSObject.Properties['Evidence'] -and $result.Evidence) {
                    foreach ($ev in $result.Evidence) {
                        Write-Host "  Query: $($ev.Query)" -ForegroundColor Gray
                        Write-Host "  Result: $($ev.Evidence)" -ForegroundColor Magenta
                        if ($ev.PSObject.Properties['Rows'] -and $ev.Rows -and (Get-SafeCount $ev.Rows) -gt 0) {
                            Write-Host "  Rows (first 10):" -ForegroundColor Gray
                            $ev.Rows | Format-Table -AutoSize | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkYellow }
                        }
                    }
                }
                Write-Host ("=" * 80) -ForegroundColor DarkGray
            }
        }
    }
}
