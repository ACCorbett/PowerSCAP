# === SQL SCAP Helpers ===
# Shared logic for Scan-SQLInstance and Scan-SQLDatabase

function Build-SqlConnection {
    <#
    .SYNOPSIS
        Builds and opens a System.Data.SqlClient.SqlConnection from the given parameters.
        Returns the open connection object. Caller is responsible for disposing.
    #>
    param(
        [string]$ConnectionString,
        [string]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential,
        [string]$Database
    )

    if (-not [string]::IsNullOrWhiteSpace($ConnectionString)) {
        # Append database if specified and not already in the connection string
        if (-not [string]::IsNullOrWhiteSpace($Database) -and $ConnectionString -notmatch '(?i)database\s*=') {
            $sep = if ($ConnectionString.TrimEnd().EndsWith(';')) { '' } else { ';' }
            $ConnectionString = "$ConnectionString${sep}Database=$Database"
        }
    } else {
        # Build from components
        $server = if ([string]::IsNullOrWhiteSpace($ComputerName)) { 'localhost' } else { $ComputerName.Trim() }
        $dbPart = if ([string]::IsNullOrWhiteSpace($Database)) { 'master' } else { $Database }

        if ($Credential) {
            $plainPass = $Credential.GetNetworkCredential().Password
            $user = $Credential.UserName
            $ConnectionString = "Server=$server;Database=$dbPart;User Id=$user;Password=$plainPass;TrustServerCertificate=true;"
        } else {
            $ConnectionString = "Server=$server;Database=$dbPart;Integrated Security=true;TrustServerCertificate=true;"
        }
    }

    $conn = New-Object System.Data.SqlClient.SqlConnection($ConnectionString)
    $conn.Open()
    return $conn
}

function Invoke-SqlQuery {
    <#
    .SYNOPSIS
        Executes a SQL query and returns rows as PSCustomObjects.
        Returns an empty array on failure; sets $script:SqlQueryError on error.
    #>
    param(
        [System.Data.SqlClient.SqlConnection]$Connection,
        [string]$Query,
        [int]$CommandTimeout = 30
    )

    $script:SqlQueryError = $null
    if ([string]::IsNullOrWhiteSpace($Query)) { return @() }

    try {
        $cmd = New-Object System.Data.SqlClient.SqlCommand($Query, $Connection)
        $cmd.CommandTimeout = $CommandTimeout
        $reader = $cmd.ExecuteReader()

        $results = @()
        $columns = @()
        for ($i = 0; $i -lt $reader.FieldCount; $i++) {
            $columns += $reader.GetName($i)
        }

        while ($reader.Read()) {
            $row = [ordered]@{}
            for ($i = 0; $i -lt $reader.FieldCount; $i++) {
                $val = $reader.GetValue($i)
                $row[$columns[$i]] = if ($val -is [System.DBNull]) { $null } else { $val }
            }
            $results += [PSCustomObject]$row
        }

        $reader.Close()
        $cmd.Dispose()
        return $results
    } catch {
        $script:SqlQueryError = $_.Exception.Message
        return @()
    }
}

function Extract-SqlQueries {
    <#
    .SYNOPSIS
        Extracts executable SQL statements from XCCDF check-content text.
        Returns an array of clean SQL strings found in the procedural text.
        Filters out commentary/instructions, keeping only actual T-SQL.
    #>
    param([string]$CheckText)

    if ([string]::IsNullOrWhiteSpace($CheckText)) { return @() }

    $queries = @()
    $lines = $CheckText -split "`n"
    $currentStatement = @()
    $inStatement = $false

    # SQL statement starters (case-insensitive)
    $starters = @('^SELECT\b', '^WITH\b', '^EXEC\b', '^EXECUTE\b', '^USE\b', '^IF\b.*BEGIN', '^SELECT\s+COUNT')

    foreach ($rawLine in $lines) {
        $line = $rawLine.Trim()

        # Skip empty lines when not in a statement
        if ([string]::IsNullOrWhiteSpace($line) -and -not $inStatement) { continue }

        # Detect start of SQL
        if (-not $inStatement) {
            $isStart = $false
            foreach ($pat in $starters) {
                if ($line -match "(?i)$pat") { $isStart = $true; break }
            }
            if ($isStart) {
                $inStatement = $true
                $currentStatement = @($line)
                continue
            }
            continue
        }

        # We are inside a statement - detect end
        # End on: empty line, line starting with "If ", "Note", "OR", non-SQL instruction prose
        if ([string]::IsNullOrWhiteSpace($line)) {
            # Empty line terminates statement
            $sql = ($currentStatement -join " ").Trim()
            if ($sql.Length -gt 5) { $queries += $sql }
            $currentStatement = @()
            $inStatement = $false
            continue
        }

        # Lines that signal end of SQL block
        if ($line -match '(?i)^(If |Note |OR$|Reference|Otherwise|This is|Review|Obtain|Determine|Run the|Execute the|Launch|In the|Navigate|Right-click|Expand|From the)') {
            $sql = ($currentStatement -join " ").Trim()
            if ($sql.Length -gt 5) { $queries += $sql }
            $currentStatement = @()
            $inStatement = $false

            # Check if this line itself starts a new statement
            $isStart = $false
            foreach ($pat in $starters) {
                if ($line -match "(?i)$pat") { $isStart = $true; break }
            }
            if ($isStart) {
                $inStatement = $true
                $currentStatement = @($line)
            }
            continue
        }

        # Continuation of current SQL statement
        $currentStatement += $line
    }

    # Flush any remaining statement
    if ($inStatement -and (Get-SafeCount $currentStatement) -gt 0) {
        $sql = ($currentStatement -join " ").Trim()
        if ($sql.Length -gt 5) { $queries += $sql }
    }

    # Post-process: strip trailing GO, clean up
    $cleaned = @()
    foreach ($q in $queries) {
        $q = $q -replace '\s*\bGO\b\s*$', '' | ForEach-Object { $_.Trim() }
        # Remove trailing semicolons that may cause issues with some queries
        # but keep them if they're mid-statement separators
        if ($q.Length -gt 3) { $cleaned += $q }
    }

    return $cleaned
}

function Parse-XccdfRules {
    <#
    .SYNOPSIS
        Parses an XCCDF Benchmark XML and returns an array of rule objects containing
        id, severity, title, check-content, and extracted SQL queries.
    #>
    param([xml]$Xml)

    $rules = @()

    # The root may be a <Benchmark> element directly (manual XCCDF) or wrapped in a data-stream-collection
    $benchmarkNode = $null

    # Try direct Benchmark root
    $direct = Select-XmlNodes -Xml $Xml -XPath "/*[local-name()='Benchmark']"
    if ($direct -and (Get-SafeCount $direct) -gt 0) {
        $benchmarkNode = $direct[0]
    }

    # Try inside data-stream-collection/component
    if (-not $benchmarkNode) {
        $wrapped = Select-XmlNodes -Xml $Xml -XPath "/*[local-name()='data-stream-collection']/*[local-name()='component']/*[local-name()='Benchmark']"
        if ($wrapped -and (Get-SafeCount $wrapped) -gt 0) {
            $benchmarkNode = $wrapped[0]
        }
    }

    if (-not $benchmarkNode) {
        throw "No XCCDF Benchmark element found in the provided SCAP/XCCDF file."
    }

    # Find all Group/Rule elements
    $groupNodes = Select-XmlNodes -Xml $benchmarkNode -XPath ".//*[local-name()='Group']"

    foreach ($group in $groupNodes) {
        $ruleNode = Select-XmlNode -Xml $group -XPath "./*[local-name()='Rule']"
        if (-not $ruleNode) { continue }

        $ruleId   = Get-AttrValue -Node $ruleNode -Name 'id'
        $severity = Get-AttrValue -Node $ruleNode -Name 'severity'
        $weight   = Get-AttrValue -Node $ruleNode -Name 'weight'
        $title    = Get-InnerText (Select-XmlNode -Xml $ruleNode -XPath "./*[local-name()='title']")
        $version  = Get-InnerText (Select-XmlNode -Xml $ruleNode -XPath "./*[local-name()='version']")

        # Get check-content (inline procedural text)
        $checkContent = Get-InnerText (Select-XmlNode -Xml $ruleNode -XPath ".//*[local-name()='check-content']")

        # Also grab the Group id (e.g., V-213929) for cross-reference
        $groupId = Get-AttrValue -Node $group -Name 'id'

        # Extract SQL queries from the check text
        $sqlQueries = @()
        if (-not [string]::IsNullOrWhiteSpace($checkContent)) {
            $sqlQueries = Extract-SqlQueries -CheckText $checkContent
        }

        $rules += [PSCustomObject]@{
            RuleId       = $ruleId
            GroupId      = $groupId
            Version      = $version
            Severity     = $severity
            Weight       = $weight
            Title        = $title
            CheckContent = $checkContent
            SqlQueries   = $sqlQueries
        }
    }

    return $rules
}

function Evaluate-SqlRule {
    <#
    .SYNOPSIS
        Evaluates a single parsed XCCDF rule against a live SQL connection.
        Executes extracted queries, collects results, and determines pass/fail.
        Rules with no extractable SQL are marked as "Manual Review Required".
    #>
    param(
        [PSCustomObject]$Rule,
        [System.Data.SqlClient.SqlConnection]$Connection,
        [bool]$IncludeDetails = $true
    )

    $evidence = @()
    $hasExecutableQuery = $false
    $anyQueryFailed = $false
    $anyQueryReturned = $false

    if ($Rule.SqlQueries -and (Get-SafeCount $Rule.SqlQueries) -gt 0) {
        foreach ($query in $Rule.SqlQueries) {
            $hasExecutableQuery = $true
            $rows = Invoke-SqlQuery -Connection $Connection -Query $query -CommandTimeout 60
            $rowCount = (Get-SafeCount $rows)
            $queryError = $script:SqlQueryError

            $evidenceEntry = [PSCustomObject]@{
                Type     = 'SqlQuery'
                Query    = $query
                RowCount = $rowCount
                Pass     = $null   # determined below
                Evidence = ''
            }

            if ($queryError) {
                $evidenceEntry.Pass = $false
                $evidenceEntry.Evidence = "Query error: $queryError"
                $anyQueryFailed = $true
            } else {
                $anyQueryReturned = $true
                $evidenceEntry.Pass = $true  # Query executed successfully
                if ($IncludeDetails -and $rowCount -gt 0) {
                    # Attach first 10 rows as detail
                    $evidenceEntry | Add-Member -NotePropertyName Rows -NotePropertyValue ($rows | Select-Object -First 10)
                }
                $evidenceEntry.Evidence = "Returned $rowCount row(s)"
            }

            $evidence += $evidenceEntry
        }
    }

    # Determine overall pass/fail
    # Logic: STIG checks are generally structured as "run query; if rows returned, this is a finding"
    # or "if no rows returned, this is a finding" depending on the check text.
    # We use heuristics from the check-content to determine the expected outcome:
    #   - "If no ... returned, this is not a finding" + rows returned => FAIL
    #   - "If ... returned, this is a finding" + rows returned => FAIL
    #   - "If no ... returned, this is a finding" + no rows => FAIL
    #   - Query errors => FAIL (cannot verify)
    #   - No executable queries => Manual Review Required (Pass = $null mapped to $false)

    $pass = $false
    $statusNote = ''

    if (-not $hasExecutableQuery) {
        $pass = $false
        $statusNote = 'Manual Review Required - no executable SQL queries could be extracted from this check.'
        $evidence += [PSCustomObject]@{
            Type     = 'ManualReview'
            Query    = '(none extracted)'
            RowCount = 0
            Pass     = $false
            Evidence = $statusNote
        }
    } elseif ($anyQueryFailed) {
        $pass = $false
        $statusNote = 'One or more queries failed to execute.'
    } else {
        # Heuristic: analyze check-content for pass/fail indicators
        $checkLower = if ($Rule.CheckContent) { $Rule.CheckContent.ToLowerInvariant() } else { '' }

        # Pattern: "if no [X] returned/are returned, this is not a finding"
        # => having results IS a finding (FAIL), having no results is NOT a finding (PASS)
        $expectEmpty = $false
        $expectNonEmpty = $false

        if ($checkLower -match 'if\s+no\s+.{1,60}\s+(is|are)\s+returned.*this\s+is\s+not\s+a\s+finding') {
            $expectEmpty = $true   # Rows = finding (FAIL); No rows = not finding (PASS)
        }
        if ($checkLower -match 'if\s+(no\s+)?[^.]{1,60}(is|are)\s+returned.*this\s+is\s+a\s+finding') {
            # "if [X] are returned, this is a finding" => rows = FAIL
            # "if no [X] are returned, this is a finding" => no rows = FAIL
            if ($checkLower -match 'if\s+no\s+') {
                $expectNonEmpty = $true  # Must have rows to pass
            } else {
                $expectEmpty = $true     # Must have NO rows to pass
            }
        }
        # Fallback: "this is a finding" without clear row-count context usually means rows = finding
        if (-not $expectEmpty -and -not $expectNonEmpty) {
            if ($checkLower -match 'this\s+is\s+a\s+finding') {
                $expectEmpty = $true  # Default: finding if rows exist
            }
        }

        # Count total rows returned across all queries
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
            # Cannot determine expected outcome; mark as manual review but include query results
            $pass = $false
            $statusNote = "Manual Review Required - query executed successfully ($totalRows row(s)) but pass/fail criteria could not be automatically determined."
        }
    }

    return [PSCustomObject]@{
        RuleId    = $Rule.RuleId
        GroupId   = $Rule.GroupId
        RuleTitle = $Rule.Title
        Severity  = $Rule.Severity
        Pass      = [bool]$pass
        StatusNote= $statusNote
        Evidence  = $evidence
    }
}
