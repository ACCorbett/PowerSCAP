function Scan-Computer {
<#
.SYNOPSIS
  Scan a computer for SCAP/OVAL compliance using Windows checks.

.DESCRIPTION
  Loads a SCAP 1.3 data stream, builds OVAL lookups, evaluates supported test types,
  and outputs either JSON (-OutputJson) or streamlined text with progress. When -LegacyOutput
  is specified, reproduces the legacy/verbose output style.

.PARAMETER ScapFile
  Path to SCAP 1.3 data stream XML.

.PARAMETER UseCim
  Use CIM for WMI queries (default: $true). Set $false to use Get-WmiObject.

.PARAMETER IncludePerTestDetails
  Include per-test detailed evidence.

.PARAMETER OutputJson
  Emit JSON results to stdout.

.PARAMETER MaxWmiRows
  Limit WMI rows scanned per query (default: 1000).

.PARAMETER Prefer64BitRegistry
  Prefer 64-bit registry view (default: $true).

.PARAMETER ComputerName
  Optional target computer name. When provided (and UseCim), CIM queries run remotely via CimSession.

.PARAMETER Credential
  Optional credential used for remote CIM session creation.

.PARAMETER LegacyOutput
  Switch to produce the original/legacy console output.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ScapFile,

        [Parameter()]
        [bool]$UseCim = $true,

        [Parameter()]
        [bool]$IncludePerTestDetails = $true,

        [Parameter()]
        [bool]$OutputJson = $false,

        [Parameter()]
        [int]$MaxWmiRows = 1000,

        [Parameter()]
        [bool]$Prefer64BitRegistry = $true,

        [Parameter()]
        [string]$ComputerName,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [switch]$LegacyOutput
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    # Normalize path
    $ScapFile = ($ScapFile -replace '[""]', '"').Trim().Trim('"').Trim("'")
    try {
        $resolvedPath = (Resolve-Path -LiteralPath $ScapFile -ErrorAction Stop).Path
    } catch {
        throw "SCAP file not found. Checked path: $ScapFile. Error: $($_.Exception.Message)"
    }

    # Optional CimSession for remote CIM/WMI
    $script:CimSession = $null
    try {
        if ($UseCim -and $ComputerName -and $ComputerName.Trim().Length -gt 0 -and
            $ComputerName.Trim().ToLowerInvariant() -ne $env:COMPUTERNAME.Trim().ToLowerInvariant()) {
            if ($Credential) {
                $script:CimSession = New-CimSession -ComputerName $ComputerName -Credential $Credential
            } else {
                $script:CimSession = New-CimSession -ComputerName $ComputerName
            }
        }
    } catch {
        Write-Warning "Failed to create CimSession for '$ComputerName': $($_.Exception.Message). Queries will run locally."
        $script:CimSession = $null
    }

    # Load SCAP XML
    Write-Verbose "Loading SCAP data stream: $resolvedPath"
    try {
        [xml]$xml = Get-Content -LiteralPath $resolvedPath -Raw -ErrorAction Stop
    } catch {
        throw "Failed to load XML from '$resolvedPath'. Error: $($_.Exception.Message)"
    }

    # Locate OVAL definitions
    $ovalNodes = Select-XmlNodes -Xml $xml -XPath "/*[local-name()='data-stream-collection']/*[local-name()='component']/*[local-name()='oval_definitions']"
    if (-not $ovalNodes -or ((@($ovalNodes) | Measure-Object).Count) -eq 0) {
        Write-Error "No OVAL definitions found in SCAP file."
        return
    }
    $oval = $ovalNodes[0]

    # Build lookups
    $definitionNodes = Select-XmlNodes -Xml $oval -XPath "./*[local-name()='definitions']/*[local-name()='definition']"
    $script:definitions = @{}
    foreach ($def in $definitionNodes) {
        $attr = $def.Attributes["id"]
        if ($attr) { $script:definitions[$attr.Value] = $def }
    }

    $variableNodes = Select-XmlNodes -Xml $oval -XPath "./*[local-name()='variables']/*"
    $script:variables = @{}
    foreach ($var in $variableNodes) {
        $attr = $var.Attributes["id"]
        if ($attr) { $script:variables[$attr.Value] = $var }
    }

    $objectNodes = Select-XmlNodes -Xml $oval -XPath ".//*[contains(local-name(), '_object')]"
    $script:objects = @{}
    foreach ($obj in $objectNodes) {
        $attr = $obj.Attributes["id"]
        if ($attr) { $script:objects[$attr.Value] = $obj }
    }

    $stateNodes = Select-XmlNodes -Xml $oval -XPath ".//*[contains(local-name(), '_state')]"
    $script:states = @{}
    foreach ($st in $stateNodes) {
        $attr = $st.Attributes["id"]
        if ($attr) { $script:states[$attr.Value] = $st }
    }

    $testNodes = Select-XmlNodes -Xml $oval -XPath ".//*[contains(local-name(), '_test')]"
    $script:tests = @{}
    foreach ($t in $testNodes) {
        $attr = $t.Attributes["id"]
        if ($attr) { $script:tests[$attr.Value] = $t }
    }

    # Shared settings
    $script:MaxWmiRows = $MaxWmiRows
    $script:UseCim     = $UseCim
    $script:Prefer64BitRegistry = $Prefer64BitRegistry

    # Main evaluation
    $results = @()
    $evalCount = 0
    $definitionTotal = ((@($definitionNodes) | Measure-Object).Count)

    foreach ($def in $definitionNodes) {
        $evalCount++
        $pct = [math]::Round(($evalCount / [double]$definitionTotal) * 100, 2)
        Write-Progress -Activity "Scanning $([string]::IsNullOrWhiteSpace($ComputerName) ? $env:COMPUTERNAME : $ComputerName)" `
                       -Status "Evaluating $evalCount of $definitionTotal definitions ($pct%)" `
                       -PercentComplete $pct

        $defIdAttr = $def.Attributes['id']
        $defId = if ($defIdAttr) { $defIdAttr.Value } else { $null }

        $title = Get-InnerText (Select-XmlNode -Xml $def -XPath "./*[local-name()='metadata']/*[local-name()='title']")
        $severity = Get-InnerText (Select-XmlNode -Xml $def -XPath "./*[local-name()='metadata']/*[local-name()='severity']")
        $criteria = Select-XmlNode -Xml $def -XPath "./*[local-name()='criteria']"

        $eval = Evaluate-Criteria -criteriaNode $criteria -DefinitionId $defId

        $obj = [PSCustomObject]@{
            RuleId    = $defId
            RuleTitle = $title
            Severity  = $severity
            Pass      = [bool]$eval.Pass
        }

        if ($IncludePerTestDetails) {
            $evidenceData = if ($eval -and $eval.Details) { $eval.Details } else { @() }
            $obj | Add-Member -NotePropertyName Evidence -NotePropertyValue $evidenceData
        }

        $results += $obj
    }

    # Output
    $passResults = @($results | Where-Object { $_.Pass })
    $failResults = @($results | Where-Object { -not $_.Pass })
    $passCount = ((@($passResults) | Measure-Object).Count)
    $failCount = ((@($failResults) | Measure-Object).Count)
    $totalCount = ((@($results) | Measure-Object).Count)

    if ($OutputJson) {
        $results | ConvertTo-Json -Depth 6
    } elseif ($LegacyOutput) {
        Write-Host "`n=== OVAL Registry Test Summary ===" -ForegroundColor Cyan
        foreach ($test in $testNodes) {
            if ($test.LocalName -like "*registry_test") {
                $testIdAttr = $test.Attributes["id"]
                $testId = if ($testIdAttr) { $testIdAttr.Value } else { Get-AttrValue -Node $test -Name 'id' }
                $refs = Get-TestRefs -test $test
                $objectRefId = $refs.objectRefId
                $stateRefId  = $refs.stateRefId

                if (-not $objectRefId) {
                    Write-Host "Test ID: $testId" -ForegroundColor Yellow
                    Write-Host "  (skipped: registry test missing object_ref)" -ForegroundColor DarkGray
                    Write-Host ""
                    continue
                }

                $obj = $null
                if ($script:objects.ContainsKey($objectRefId)) { $obj = $script:objects[$objectRefId] }

                if (-not $obj) {
                    Write-Host "Test ID: $testId" -ForegroundColor Yellow
                    Write-Host "  (object not found: $objectRefId)" -ForegroundColor Red
                    Write-Host ""
                    continue
                }

                $stateNode = $null
                if ($stateRefId -and $script:states.ContainsKey($stateRefId)) { $stateNode = $script:states[$stateRefId] }

                $hive = Get-InnerText (Select-XmlNode -Xml $obj -XPath "./*[local-name()='hive']")
                $key  = Get-InnerText (Select-XmlNode -Xml $obj -XPath "./*[local-name()='key']")
                $name = Get-InnerText (Select-XmlNode -Xml $obj -XPath "./*[local-name()='name']")

                $valueNode = if ($stateNode) { Select-XmlNode -Xml $stateNode -XPath "./*[local-name()='value']" } else { $null }
                $expected  = if ($valueNode) { Get-InnerText $valueNode } else { $null }
                $operation = if ($valueNode) { Get-AttrValue -Node $valueNode -Name 'operation' } else { $null }
                $datatype  = if ($valueNode) { Get-AttrValue -Node $valueNode -Name 'datatype' } else { $null }

                if (-not $operation) { $operation = 'equals' }
                if (-not $datatype)  { $datatype  = 'string' }

                Write-Host "Test ID: $testId" -ForegroundColor Yellow
                Write-Host "  Hive:      $hive"
                Write-Host "  Key:       $key"
                Write-Host "  Name:      $name"
                Write-Host "  Expected:  $expected"
                Write-Host "  Operation: $operation"
                Write-Host "  Datatype:  $datatype"
                Write-Host ""
            }
        }

        Write-Host "`n=== SCAP Compliance Summary ===" -ForegroundColor Cyan
        $results |
          Select-Object RuleId, @{n='Status'; e={ if ($_.Pass) { 'PASS' } else { 'FAIL' } }}, RuleTitle |
          Format-Table -AutoSize

        Write-Host "`n=== Detailed Failure Information ===" -ForegroundColor Yellow
        foreach ($result in $failResults) {
            Write-Host "`nRule: $($result.RuleId)" -ForegroundColor Red
            Write-Host "Title: $($result.RuleTitle)" -ForegroundColor Blue
            if ($result.Severity) {
                Write-Host "Severity: $($result.Severity)" -ForegroundColor Red
            }
            if ($result.Evidence) { Print-EvidenceRecursive -Evidence $result.Evidence }
            else { Write-Host "  No detailed evidence available" -ForegroundColor DarkGray }
            Write-Host ("=" * 80) -ForegroundColor DarkGray
        }

        Write-Host "`n=== Final Summary ===" -ForegroundColor Cyan
        Write-Host "Total Rules Evaluated: $totalCount" -ForegroundColor White
        Write-Host "Compliant (PASS): $passCount" -ForegroundColor Green
        Write-Host "Non-Compliant (FAIL): $failCount" -ForegroundColor Red
        if ($failCount -gt 0 -and $totalCount -gt 0) {
            $failureRate = [math]::Round(($failCount / $totalCount) * 100, 2)
            Write-Host "Failure Rate: $failureRate%" -ForegroundColor Yellow
        }
    } else {
        Write-Host "`n=== SCAP Compliance Summary ===" -ForegroundColor Cyan
        $results |
          Select-Object RuleId, @{n='Status'; e={ if ($_.Pass) { 'PASS' } else { 'FAIL' } }} |
          Format-Table -AutoSize

        Write-Host "`nCompleted: $evalCount/$definitionTotal definitions" -ForegroundColor White
        Write-Host "PASS: $passCount, FAIL: $failCount" -ForegroundColor White

        if ($failCount -gt 0) {
            $failureRate = [math]::Round(($failCount / $totalCount) * 100, 2)
            Write-Host ("Failure Rate: {0}%" -f $failureRate) -ForegroundColor Yellow

            Write-Host "`nTop Failures (first 10):" -ForegroundColor Yellow
            $failResults | Select-Object -First 10 |
              Select-Object RuleId, RuleTitle, Severity |
              Format-Table -AutoSize
        }
    }

    if ($script:CimSession) {
        try { $script:CimSession | Remove-CimSession -ErrorAction SilentlyContinue } catch {}
        $script:CimSession = $null
    }
}
