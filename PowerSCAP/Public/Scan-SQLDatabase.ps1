function Scan-SQLDatabase {
<#
.SYNOPSIS
  Scan a SQL Server database for STIG compliance using an XCCDF benchmark.

.DESCRIPTION
  PowerSCAP v2.6.0 - Parses an XCCDF STIG benchmark (e.g., MS SQL Server 2016 Database STIG),
  extracts T-SQL checks from each rule's check-content, executes them against
  the target database on the specified SQL Server, and evaluates results
  against documented pass/fail criteria. Outputs match the schema of
  Scan-Computer for consistency.

  Connection can be established via an explicit -ConnectionString, or by
  specifying -Computer and -Database (with optional -Credential). When
  no connection parameters are given, connects to the default local instance
  and the specified database.

  The -Database parameter is required unless -ConnectionString already
  includes a Database= clause. Instance-level queries (e.g., queries against
  sys.databases or sys.server_principals) are automatically routed through
  the master database context when needed.

.PARAMETER ScanSourceType
  How to obtain scan definitions (REQUIRED):
  - File: Single XCCDF STIG file

.PARAMETER ScanSource
  Source for scan definitions (REQUIRED):
  - For File: Path to XCCDF file (e.g., "U_MS_SQL_Server_2016_Database_STIG_*.xml")

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

.PARAMETER Database
  Name of the target database to scan. Required unless -ConnectionString already
  specifies a database. Some checks automatically execute against master for
  instance-level context.

.PARAMETER ConnectionString
  Full ADO.NET connection string. When provided, Computer, Credential, and
  Database parameters are ignored (except Database is appended if not already present).

.EXAMPLE
  # Scan a specific database on the local instance
  Scan-SQLDatabase -ScanSourceType File -ScanSource ".\Database_STIG.xml" -Database "MyAppDB"

.EXAMPLE
  # Scan a remote database with SQL auth, JSON output
  $cred = Get-Credential "dbadmin"
  Scan-SQLDatabase -ScanSourceType File -ScanSource ".\Database_STIG.xml" -Computer "DBSERVER01" -Database "Production" -Credential $cred -Output JSON

.EXAMPLE
  # Scan with an explicit connection string
  Scan-SQLDatabase -ScanSourceType File -ScanSource ".\Database_STIG.xml" -ConnectionString "Server=DBSERVER01;Database=MyDB;Integrated Security=true;" 

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
        [string]$Database,

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

    # --- Validate that we have a database target ---
    if ([string]::IsNullOrWhiteSpace($ConnectionString)) {
        if ([string]::IsNullOrWhiteSpace($Database)) {
            throw "Either -Database or -ConnectionString (containing a Database= clause) must be specified."
        }
    } else {
        # If ConnectionString is provided but has no Database= and -Database is given, it will be appended by Build-SqlConnection
        if ($ConnectionString -notmatch '(?i)database\s*=' -and [string]::IsNullOrWhiteSpace($Database)) {
            throw "The provided -ConnectionString does not include a Database= clause and -Database was not specified."
        }
    }

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

    # --- Determine target labels ---
    $serverLabel = if (-not [string]::IsNullOrWhiteSpace($ConnectionString)) {
        $m = [System.Text.RegularExpressions.Regex]::Match($ConnectionString, '(?i)Server\s*=\s*([^;]+)')
        if ($m.Success) { $m.Groups[1].Value.Trim() } else { '(connection string)' }
    } elseif (-not [string]::IsNullOrWhiteSpace($Computer)) {
        $Computer.Trim()
    } else {
        'localhost'
    }

    $dbLabel = if (-not [string]::IsNullOrWhiteSpace($Database)) { $Database } else {
        $m = [System.Text.RegularExpressions.Regex]::Match($ConnectionString, '(?i)Database\s*=\s*([^;]+)')
        if ($m.Success) { $m.Groups[1].Value.Trim() } else { '(unknown)' }
    }
    $targetLabel = "$serverLabel\$dbLabel"

    # --- Establish SQL connections ---
    # Primary connection: targets the specified database
    # Master connection: for queries that need instance-level context (sys.databases, sys.server_principals, etc.)
    Write-Verbose "Connecting to SQL database: $targetLabel"
    $connDb = $null
    $connMaster = $null
    try {
        $connDb = Build-SqlConnection -ConnectionString $ConnectionString -ComputerName $Computer -Credential $Credential -Database $Database

        # Master connection: targets the same server/auth as the DB connection but uses the
        # master database for instance-level catalog queries.
        # When a ConnectionString was provided, mutate its Database= clause rather than
        # building from scratch (which would silently fall back to localhost).
        $masterConnStr = $null
        if (-not [string]::IsNullOrWhiteSpace($ConnectionString)) {
            if ($ConnectionString -match '(?i)database\s*=\s*[^;]+') {
                $masterConnStr = $ConnectionString -replace '(?i)database\s*=\s*[^;]+', 'Database=master'
            } else {
                $sep = if ($ConnectionString.TrimEnd().EndsWith(';')) { '' } else { ';' }
                $masterConnStr = "$ConnectionString${sep}Database=master"
            }
            $connMaster = Build-SqlConnection -ConnectionString $masterConnStr -ComputerName $null -Credential $null -Database $null
        } else {
            $connMaster = Build-SqlConnection -ConnectionString $null -ComputerName (if (-not [string]::IsNullOrWhiteSpace($Computer)) { $Computer } else { 'localhost' }) -Credential $Credential -Database 'master'
        }
    } catch {
        # If master connection fails, we can still proceed with DB-only connection
        if (-not $connDb) {
            throw "Failed to connect to SQL Server '$targetLabel'. Error: $($_.Exception.Message)"
        }
        Write-Verbose "Note: Could not open a separate master connection. Instance-level queries will run in the database context."
        $connMaster = $null
    }

    # --- Queries that should route to master context ---
    # These reference instance-level catalog views not available in user databases
    $instanceLevelPatterns = @(
        '(?i)\bsys\.databases\b',
        '(?i)\bsys\.server_principals\b',
        '(?i)\bsys\.server_permissions\b',
        '(?i)\bsys\.server_role_members\b',
        '(?i)\bsys\.server_audits\b',
        '(?i)\bsys\.server_audit_specifications\b',
        '(?i)\bmaster\.',
        '(?i)\bsp_configure\b',
        '(?i)\bsys\.configurations\b',
        '(?i)\bsys\.dm_server_',
        '(?i)\bsys\.linked_logins\b',
        '(?i)\bsys\.credentials\b',
        '(?i)\bsys\.endpoints\b',
        '(?i)\bsys\.sql_logins\b',
        '(?i)\bsys\.server_file_audits\b'
    )

    function Select-ConnectionForQuery {
        param([string]$Query)
        if (-not $connMaster) { return $connDb }
        foreach ($pat in $instanceLevelPatterns) {
            if ($Query -match $pat) { return $connMaster }
        }
        return $connDb
    }

    # --- Evaluate each rule ---
    $results = @()
    $evalCount = 0

    try {
        foreach ($rule in $rules) {
            $evalCount++
            $pct = [math]::Round(($evalCount / [double]$ruleCount) * 100, 2)
            Write-Progress -Activity "Scanning SQL Database: $targetLabel" `
                           -Status "Evaluating rule $evalCount of $ruleCount ($pct%)" `
                           -PercentComplete $pct

            # For database-level scanning, we need to handle query routing ourselves
            # rather than using Evaluate-SqlRule directly, because some queries need master context
            $evidence = @()
            $hasExecutableQuery = $false
            $anyQueryFailed = $false

            if ($rule.SqlQueries -and (Get-SafeCount $rule.SqlQueries) -gt 0) {
                foreach ($query in $rule.SqlQueries) {
                    $hasExecutableQuery = $true
                    $targetConn = Select-ConnectionForQuery -Query $query
                    $connLabel = if ([object]::ReferenceEquals($targetConn, $connMaster)) { '[master]' } else { "[$dbLabel]" }

                    $rows = Invoke-SqlQuery -Connection $targetConn -Query $query -CommandTimeout 60
                    $rowCount = (Get-SafeCount $rows)
                    $queryError = $script:SqlQueryError

                    $evidenceEntry = [PSCustomObject]@{
                        Type     = 'SqlQuery'
                        Context  = $connLabel
                        Query    = $query
                        RowCount = $rowCount
                        Pass     = $null
                        Evidence = ''
                    }

                    if ($queryError) {
                        $evidenceEntry.Pass = $false
                        $evidenceEntry.Evidence = "Query error ($connLabel): $queryError"
                        $anyQueryFailed = $true
                    } else {
                        $evidenceEntry.Pass = $true
                        if ($IncludePerTestDetails -and $rowCount -gt 0) {
                            $evidenceEntry | Add-Member -NotePropertyName Rows -NotePropertyValue ($rows | Select-Object -First 10)
                        }
                        $evidenceEntry.Evidence = "Returned $rowCount row(s) ($connLabel)"
                    }

                    $evidence += $evidenceEntry
                }
            }

            # --- Determine pass/fail using same heuristics as Evaluate-SqlRule ---
            $pass = $false
            $statusNote = ''

            if (-not $hasExecutableQuery) {
                $pass = $false
                $statusNote = 'Manual Review Required - no executable SQL queries could be extracted from this check.'
                $evidence += [PSCustomObject]@{
                    Type     = 'ManualReview'
                    Context  = '(none)'
                    Query    = '(none extracted)'
                    RowCount = 0
                    Pass     = $false
                    Evidence = $statusNote
                }
            } elseif ($anyQueryFailed) {
                $pass = $false
                $statusNote = 'One or more queries failed to execute.'
            } else {
                $checkLower = if ($rule.CheckContent) { $rule.CheckContent.ToLowerInvariant() } else { '' }

                $expectEmpty = $false
                $expectNonEmpty = $false

                if ($checkLower -match 'if\s+no\s+.{1,60}\s+(is|are)\s+returned.*this\s+is\s+not\s+a\s+finding') {
                    $expectEmpty = $true
                }
                if ($checkLower -match 'if\s+(no\s+)?[^.]{1,60}(is|are)\s+returned.*this\s+is\s+a\s+finding') {
                    if ($checkLower -match 'if\s+no\s+') {
                        $expectNonEmpty = $true
                    } else {
                        $expectEmpty = $true
                    }
                }
                if (-not $expectEmpty -and -not $expectNonEmpty) {
                    if ($checkLower -match 'this\s+is\s+a\s+finding') {
                        $expectEmpty = $true
                    }
                }

                $totalRows = 0
                foreach ($e in $evidence) {
                    if ($e.RowCount -is [int]) { $totalRows += $e.RowCount }
                }

                if ($expectEmpty) {
                    $pass = ($totalRows -eq 0)
                    $statusNote = if ($pass) { "PASS: No rows returned (compliant)." } else { "FAIL: $totalRows row(s) returned - indicates a finding." }
                } elseif ($expectNonEmpty) {
                    $pass = ($totalRows -gt 0)
                    $statusNote = if ($pass) { "PASS: $totalRows row(s) returned (compliant)." } else { "FAIL: No rows returned - indicates a finding." }
                } else {
                    $pass = $false
                    $statusNote = "Manual Review Required - query executed successfully ($totalRows row(s)) but pass/fail criteria could not be automatically determined."
                }
            }

            $obj = [PSCustomObject]@{
                RuleId    = $rule.RuleId
                RuleTitle = $rule.Title
                Severity  = $rule.Severity
                Pass      = [bool]$pass
            }

            if ($IncludePerTestDetails) {
                $obj | Add-Member -NotePropertyName Evidence   -NotePropertyValue $evidence
                $obj | Add-Member -NotePropertyName StatusNote -NotePropertyValue $statusNote
            }

            $results += $obj
        }
    } finally {
        # Always clean up connections
        if ($connDb)     { try { $connDb.Close();     $connDb.Dispose()     } catch {} }
        if ($connMaster) { try { $connMaster.Close(); $connMaster.Dispose() } catch {} }
        Write-Progress -Activity "Scanning SQL Database: $targetLabel" -Completed
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
        Write-Host "`n=== SQL Database STIG Compliance Summary ===" -ForegroundColor Cyan
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
                        $ctxLabel = if ($ev.PSObject.Properties['Context']) { " $($ev.Context)" } else { '' }
                        Write-Host "  Query$ctxLabel`: $($ev.Query)" -ForegroundColor Gray
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
