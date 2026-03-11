# === SQL SCAP Helpers ===
# Shared logic for Scan-SQLInstance and Scan-SQLDatabase

function Build-SqlConnection {
    <#
    .SYNOPSIS
        Builds and opens a System.Data.SqlClient.SqlConnection from the given parameters.
        Returns the open connection object. Caller is responsible for disposing.
    .NOTES
        Requires System.Data.SqlClient, which ships with Windows PowerShell 5.1 but is NOT
        included in PowerShell 7+ (.NET 5+) by default. On PowerShell 7, install the SqlServer
        module first:  Install-Module -Name SqlServer -Force
        This registers Microsoft.Data.SqlClient which provides the SqlConnection type.
    #>
    param(
        [string]$ConnectionString,
        [string]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential,
        [string]$Database
    )

    # Verify SqlClient is available and provide actionable guidance if not
    $sqlClientAvailable = $false
    try {
        Add-Type -AssemblyName 'System.Data' -ErrorAction SilentlyContinue
        [void][System.Data.SqlClient.SqlConnection]
        $sqlClientAvailable = $true
    } catch {}
    if (-not $sqlClientAvailable) {
        throw ("System.Data.SqlClient is not available on this PowerShell version. " +
               "Install the SqlServer module to enable SQL scanning: " +
               "Install-Module -Name SqlServer -Force")
    }

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
        Returns an array of validated SQL strings. Prose instructions, UI steps,
        and finding-criteria text are filtered out.

    .NOTES
        Algorithm (validated against the MS SQL Server 2022 Instance and Database STIGs):

        SQL STARTERS — patterns that unambiguously begin a T-SQL statement:
          SELECT, WITH (CTE), EXEC/EXECUTE <proc>, USE <db>, IF <sql-condition>
          EXECUTE is tightened to exclude prose "Execute the following..." by requiring
          a SQL token (AS, sp_, xp_, schema.obj, or identifier followed by . or ()
          immediately after the keyword.
          IF is tightened to require a SQL-style condition opener: (, @@var, EXISTS, etc.
          USE is tightened to require a bracket or identifier (not English words).

        SQL EMBED — fallback for lines like:
          "If Mirroring is in use, run the following to check: SELECT name FROM ..."
          where the prose and SQL appear on the same line. The SQL keyword is located
          within the line and only the SQL suffix is collected. Starters are checked
        FIRST so that valid SQL lines (e.g. "EXEC sp_MSforeachdb '...; SELECT ...'")
          are never stripped of their prefix by the embed extractor.

        SQL VALIDITY FILTER — post-extraction gate that rejects anything lacking SQL
          hallmarks (FROM/WHERE/JOIN/sys./brackets/literals/variables/proc calls/etc.).
          This catches residual prose that slipped through a starter match.

        PROSE TERMINATORS — lines beginning with common English instruction phrases
          (If, Note, Run the, Execute the, Navigate, etc.) that close the current
          statement accumulator when encountered mid-block.
    #>
    param([string]$CheckText)

    if ([string]::IsNullOrWhiteSpace($CheckText)) { return @() }

    # SQL statement starters — ordered from most to least specific
    # EXEC/EXECUTE: requires a SQL token after the keyword, not English prose
    # USE:          lookahead placed BEFORE the character class so the full word
    #               is tested (not just the suffix after the first letter is consumed)
    # IF:           requires a SQL condition opener, not prose "If no records..."
    $starters = @(
        '^SELECT\b',
        '^WITH\b',
        '^DECLARE\b',
        '^INSERT\s+INTO\b',
        '^EXEC(?:UTE)?\s+(?:AS\b|sp_|xp_|master\.|msdb\.|[a-zA-Z_#@]\w*\s*[.(])',
        '^USE\s+(?:\[|(?!the\b|following\b|these\b|this\b|a\b|an\b)[a-zA-Z_#@]\w*)',
        '^IF\s*(?:\(|@@|EXISTS\s*\(|NOT\s+EXISTS\s*\(|OBJECT_ID\s*\()',
        '^SELECT\s+COUNT'
    )

    # Prose terminator prefixes that end a SQL accumulation block
    # "Use the " added to handle "Use the following query to..." intro lines
    $proseTermPattern = '(?i)^(If |Note |OR$|Reference|Otherwise|This is|Review|Obtain|Determine|Run the|Execute the|Launch|In the|Navigate|Right-click|Expand|From the|Use the )'

    # Fallback: detect SQL embedded after prose on the same line
    # e.g. "If Mirroring is in use, run the following: SELECT name FROM sys..."
    # Only fires when no starter matched (starters checked first to protect
    # lines like "EXEC sp_MSforeachdb '...; SELECT ...' from being truncated).
    $sqlEmbedPattern = '(?i).+?\b(SELECT|WITH|EXEC(?:UTE)?)\b\s+(?!the\b|following\b|these\b|this\b|all\b)'

    # Post-extraction validity: a query must contain at least one SQL hallmark
    # to filter out any residual prose that matched a starter pattern
    $sqlValidityPattern = '(?i)(\b(FROM|WHERE|JOIN|sys\.|INNER|LEFT|RIGHT|OUTER)\b' +
                          '|AS\s+LOGIN\b|\bsp_\w+|\bxp_\w+|=\s*[''"\[\w]|@\w+|\[.+?\]' +
                          "|'[^']*'" + '|\bEXEC(?:UTE)?\s+(?:AS|sp_|xp_|\w+\.)|\(\s*SELECT\b)'

    $queries        = @()
    $currentStatement = @()
    $inStatement    = $false

    foreach ($rawLine in ($CheckText -split "`n")) {
        $line = $rawLine.Trim()

        if ([string]::IsNullOrWhiteSpace($line) -and -not $inStatement) { continue }

        if (-not $inStatement) {
            # 1. Try SQL starters first — keeps full valid SQL lines intact
            $matched = $false
            foreach ($pat in $starters) {
                if ($line -match "(?i)$pat") {
                    $inStatement      = $true
                    $currentStatement = @($line)
                    $matched          = $true
                    break
                }
            }
            if ($matched) { continue }

            # 2. Fallback: prose line containing embedded SQL suffix
            if ($line -match $sqlEmbedPattern) {
                $sqlSuffix = $line.Substring($Matches[0].Length - $Matches[1].Length).Trim()
                if ($sqlSuffix.Length -gt 5 -and $sqlSuffix -match $sqlValidityPattern) {
                    $inStatement      = $true
                    $currentStatement = @($sqlSuffix)
                }
            }
            continue
        }

        # Inside a statement
        if ([string]::IsNullOrWhiteSpace($line)) {
            $sql = ($currentStatement -join ' ').Trim()
            if ($sql.Length -gt 5 -and $sql -match $sqlValidityPattern) { $queries += $sql }
            $currentStatement = @()
            $inStatement      = $false
            continue
        }

        if ($line -match $proseTermPattern) {
            $sql = ($currentStatement -join ' ').Trim()
            if ($sql.Length -gt 5 -and $sql -match $sqlValidityPattern) { $queries += $sql }
            $currentStatement = @()
            $inStatement      = $false

            # This prose line may itself start or embed SQL
            $matched = $false
            foreach ($pat in $starters) {
                if ($line -match "(?i)$pat") {
                    $inStatement      = $true
                    $currentStatement = @($line)
                    $matched          = $true
                    break
                }
            }
            if (-not $matched -and $line -match $sqlEmbedPattern) {
                $sqlSuffix = $line.Substring($Matches[0].Length - $Matches[1].Length).Trim()
                if ($sqlSuffix.Length -gt 5 -and $sqlSuffix -match $sqlValidityPattern) {
                    $inStatement      = $true
                    $currentStatement = @($sqlSuffix)
                }
            }
            continue
        }

        $currentStatement += $line
    }

    # Flush trailing statement
    if ($inStatement -and (Get-SafeCount $currentStatement) -gt 0) {
        $sql = ($currentStatement -join ' ').Trim()
        if ($sql.Length -gt 5 -and $sql -match $sqlValidityPattern) { $queries += $sql }
    }

    # Strip trailing GO statements, split on mid-statement GO batch separators,
    # and filter any resulting segments that no longer look like SQL
    $final = @()
    foreach ($q in $queries) {
        # Split on standalone GO batch separators (e.g. "USE master; GO SELECT ...")
        $batches = $q -split '(?i)\s+GO\b\s*;?\s*'
        foreach ($batch in $batches) {
            $batch = $batch.Trim().TrimEnd(';').Trim()
            if ($batch.Length -gt 3 -and $batch -match $sqlValidityPattern) {
                $final += $batch
            }
        }
    }
    return $final
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
