
<#
.SYNOPSIS
  PowerSCAP - Robust SCAP/OVAL evaluator for common Windows checks (registry, WMI/CIM, file, service, process, QFE)
  Supports nested OVAL criteria (AND/OR), operations, datatypes, variable references, negation, and existence checks.

.DESCRIPTION
  Parses OVAL definitions from a SCAP 1.3 data stream and evaluates common Windows test types. 
  Designed to work with DISA STIG SCAP bundles. Outputs concise pass/fail summary and optional detailed evidence.

.PARAMETER ScapFile
  Path to SCAP 1.3 data stream XML (e.g., DISA Windows Server STIG SCAP benchmark).

.PARAMETER UseCim
  Use CIM for WMI queries (default: $true). Set to $false to use Get-WmiObject.

.PARAMETER IncludePerTestDetails
  Include per-test detailed evidence for each definition.

.PARAMETER OutputJson
  Emit JSON results to stdout (for ingestion/storage).

.PARAMETER MaxWmiRows
  Limit WMI rows scanned per query (default: 1000).

.PARAMETER Prefer64BitRegistry
  Prefer 64-bit registry view (default: $true). Set to $false to use process-default.

.NOTES
  PowerShell 5.1 compatible. No PS 7-only operators (??, ?:).

  KEY FIXES:
    - First Beta
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
    [bool]$Prefer64BitRegistry = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Normalize and validate ScapFile path ---
$ScapFile = ($ScapFile -replace '[""]', '"').Trim().Trim('"').Trim("'")
try {
    $resolvedPath = (Resolve-Path -LiteralPath $ScapFile -ErrorAction Stop).Path
} catch {
    throw "SCAP file not found. Checked path: $ScapFile. Error: $($_.Exception.Message)"
}

# --- Helpers: XML namespace-agnostic selection -------------------------------

function Select-XmlNodes {
    param(
        [System.Xml.XmlNode]$Xml,
        [string]$XPath
    )
    if ($null -eq $Xml -or [string]::IsNullOrWhiteSpace($XPath)) { return @() }
    try {
        $res = $Xml.SelectNodes($XPath)
        if ($res) { return @($res) } else { return @() }
    } catch {
        return @()
    }
}

function Select-XmlNode {
    param(
        [System.Xml.XmlNode]$Xml,
        [string]$XPath
    )
    if ($null -eq $Xml -or [string]::IsNullOrWhiteSpace($XPath)) { return $null }
    try {
        return $Xml.SelectSingleNode($XPath)
    } catch {
        return $null
    }
}

# Safe inner text reader for elements/attributes/text nodes
function Get-InnerText {
    param([System.Xml.XmlNode]$Node)
    if ($null -eq $Node) { return $null }
    if ($Node -is [System.Xml.XmlAttribute]) { return $Node.Value }
    return $Node.InnerText
}

# Safe attribute value accessor
function Get-AttrValue {
    param(
        [System.Xml.XmlNode]$Node,
        [string]$Name
    )
    if ($null -eq $Node) { return $null }
    $attr = $Node.Attributes[$Name]
    if ($attr) { return $attr.Value }
    return $null
}

# Helper: pick first non-null/non-empty value
function Get-FirstDefined {
    param([object[]]$Values)
    if ($null -eq $Values -or $Values.Count -eq 0) { return $null }
    foreach ($v in $Values) {
        if ($null -ne $v -and $v -ne '') { return $v }
    }
    return $null
}

# Robust boolean conversion
function To-Bool {
    param($Value)
    if ($null -eq $Value) { return $null }
    $s = ([string]$Value).Trim().ToLowerInvariant()
    switch ($s) {
        'true'  { return $true }
        '1'     { return $true }
        'false' { return $false }
        '0'     { return $false }
        default { 
            try { return [System.Convert]::ToBoolean($Value) } catch { return $null }
        }
    }
}

# --- Load SCAP ---------------------------------------------------------------

Write-Verbose "Loading SCAP data stream: $resolvedPath"
try {
    [xml]$xml = Get-Content -LiteralPath $resolvedPath -Raw -ErrorAction Stop
} catch {
    throw "Failed to load XML from '$resolvedPath'. Error: $($_.Exception.Message)"
}

# Locate OVAL definitions component (namespace-agnostic)
$ovalNodes = Select-XmlNodes -Xml $xml -XPath "/*[local-name()='data-stream-collection']/*[local-name()='component']/*[local-name()='oval_definitions']"
if (-not $ovalNodes -or $ovalNodes.Count -eq 0) {
    Write-Error "No OVAL definitions found in SCAP file."
    exit 1
}
$oval = $ovalNodes[0]

# --- Build lookups for definitions/objects/states/tests/variables ------------

# Definitions
$definitionNodes = Select-XmlNodes -Xml $oval -XPath "./*[local-name()='definitions']/*[local-name()='definition']"
$definitions = @{}
foreach ($def in $definitionNodes) {
    $attr = $def.Attributes["id"]
    if ($attr) { $definitions[$attr.Value] = $def }
}

# Variables (optional)
$variableNodes = Select-XmlNodes -Xml $oval -XPath "./*[local-name()='variables']/*"
$variables = @{}
foreach ($var in $variableNodes) {
    $attr = $var.Attributes["id"]
    if ($attr) { $variables[$attr.Value] = $var }
}

# Objects: all elements ending with "_object"
$objectNodes = Select-XmlNodes -Xml $oval -XPath ".//*[contains(local-name(), '_object')]"
$objects = @{}
foreach ($obj in $objectNodes) {
    $attr = $obj.Attributes["id"]
    if ($attr) { $objects[$attr.Value] = $obj }
}

# States: all elements ending with "_state"
$stateNodes = Select-XmlNodes -Xml $oval -XPath ".//*[contains(local-name(), '_state')]"
$states = @{}
foreach ($st in $stateNodes) {
    $attr = $st.Attributes["id"]
    if ($attr) { $states[$attr.Value] = $st }
}

# Tests: all elements ending with "_test"
$testNodes = Select-XmlNodes -Xml $oval -XPath ".//*[contains(local-name(), '_test')]"
$tests = @{}
foreach ($t in $testNodes) {
    $attr = $t.Attributes["id"]
    if ($attr) { 
        $tests[$attr.Value] = $t
    }
}

# --- Variable resolution -----------------------------------------------------

function Resolve-VarRef {
    param([string]$VarRef)
    if (-not $VarRef) { return $null }
    
    $v = $null
    if ($VarRef -and $variables.ContainsKey($VarRef)) {
        $v = $variables[$VarRef]
    }
    if (-not $v) { return $null }

    $lits = @()
    $lits += Select-XmlNodes -Xml $v -XPath "./*[local-name()='literal']"
    $lits += Select-XmlNodes -Xml $v -XPath ".//*[local-name()='literal_component']"
    if ($lits -and $lits.Count -gt 0) {
        return @($lits | ForEach-Object { Get-InnerText $_ } | Where-Object { $_ -ne $null -and $_ -ne '' })
    }

    $txt = Get-InnerText $v
    if ($txt) { return @($txt) }
    return $null
}

# --- Compare logic: operations & datatypes ----------------------------------

function Convert-ToDatatype {
    param(
        [object]$Value,
        [string]$Datatype
    )
    switch ($Datatype) {
        'boolean' {
            if ($Value -is [bool]) { return $Value }
            return To-Bool $Value
        }
        'integer' { try { return [int64]$Value } catch { return $null } }
        'int'     { try { return [int64]$Value } catch { return $null } }
        'float'   { try { return [double]$Value } catch { return $null } }
        'version' { try { return [version]$Value } catch { return [string]$Value } }
        'record'  { return $Value }
        default   { return [string]$Value }
    }
}

function Compare-Value {
    param(
        [string]$Actual,
        [string]$Expected,
        [Parameter(Mandatory=$true)][string]$Operation,
        [string]$Datatype = 'string',
        [bool]$CaseSensitive = $false
    )


    # Helper for list comparison (order-insensitive, exact match)
    function Compare-Lists($a, $b, $caseSensitive) {
        $aList = ($a -split ',') | ForEach-Object { $_.Trim() }
        $bList = ($b -split ',') | ForEach-Object { $_.Trim() }
        if (-not $caseSensitive) {
            $aList = $aList | ForEach-Object { $_.ToLower() }
            $bList = $bList | ForEach-Object { $_.ToLower() }
        }
        return (@($aList | Sort-Object) -eq @($bList | Sort-Object))
    }

    # Normalize for boolean
    if ($Datatype -eq 'boolean') {
        $Actual = if ($Actual -is [bool]) { $Actual } else { $Actual.ToString().ToLower() -in @('1','true','yes') }
        $Expected = if ($Expected -is [bool]) { $Expected } else { $Expected.ToString().ToLower() -in @('1','true','yes') }
    }

    # Normalize for int/float
    if ($Datatype -eq 'int' -or $Datatype -eq 'integer' -or $Datatype -eq 'float' -or $Datatype -eq 'double') {
        $Actual = [double]$Actual
        $Expected = [double]$Expected
    }

    switch ($Operation.ToLower()) {
        # String operations
        'equals' {
            if ($CaseSensitive) { return $Actual -eq $Expected }
            else { return $Actual.ToLower() -eq $Expected.ToLower() }
        }
        'not equal' {
            if ($CaseSensitive) { return $Actual -ne $Expected }
            else { return $Actual.ToLower() -ne $Expected.ToLower() }
        }
        'case insensitive equals' { return $Actual.ToLower() -eq $Expected.ToLower() }
        'case insensitive not equal' { return $Actual.ToLower() -ne $Expected.ToLower() }
        'pattern match' {
            if ($CaseSensitive) { return $Actual -match $Expected }
            else { return $Actual -imatch $Expected }
        }
        'case insensitive pattern match' { return $Actual -imatch $Expected }
        # Numeric
        'greater than' { return $Actual -gt $Expected }
        'greater than or equal' { return $Actual -ge $Expected }
        'less than' { return $Actual -lt $Expected }
        'less than or equal' { return $Actual -le $Expected }
        # List/set
        'set equals' { return Compare-Lists $Actual $Expected $CaseSensitive }
        'subset of' {
            $aList = ($Actual -split ',') | ForEach-Object { $_.Trim() }
            $bList = ($Expected -split ',') | ForEach-Object { $_.Trim() }
            if (-not $CaseSensitive) {
                $aList = $aList | ForEach-Object { $_.ToLower() }
                $bList = $bList | ForEach-Object { $_.ToLower() }
            }
            return ($aList | Where-Object { $_ -notin $bList }).Count -eq 0
        }
        'superset of' {
            $aList = ($Actual -split ',') | ForEach-Object { $_.Trim() }
            $bList = ($Expected -split ',') | ForEach-Object { $_.Trim() }
            if (-not $CaseSensitive) {
                $aList = $aList | ForEach-Object { $_.ToLower() }
                $bList = $bList | ForEach-Object { $_.ToLower() }
            }
            return ($bList | Where-Object { $_ -notin $aList }).Count -eq 0
        }
        # Boolean
        'boolean equals' { return $Actual -eq $Expected }
        'boolean not equal' { return $Actual -ne $Expected }
        # Default fallback
        default {
            if ($CaseSensitive) { return $Actual -eq $Expected }
            else { return $Actual.ToLower() -eq $Expected.ToLower() }
        }
    }
}


# --- Registry helpers --------------------------------------------------------

function Get-RegistryItemProperty {
    param(
        [string]$Hive,
        [string]$Key,
        [string]$Name
    )
    $mappedHive = $Hive -replace '^HKEY_LOCAL_MACHINE$', 'HKLM:' -replace '^HKEY_CURRENT_USER$', 'HKCU:' -replace '^HKEY_USERS$', 'HKU:' -replace '^HKEY_CLASSES_ROOT$', 'HKCR:'
    $regPath = "$mappedHive\$Key"

    $baseKey = $null
    $registryView = [Microsoft.Win32.RegistryView]::Default
    if ($Prefer64BitRegistry) { $registryView = [Microsoft.Win32.RegistryView]::Registry64 }

    try {
        if ($regPath.StartsWith('HKLM:')) {
            $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $registryView)
        } elseif ($regPath.StartsWith('HKCU:')) {
            $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser, $registryView)
        } elseif ($regPath.StartsWith('HKU:')) {
            $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users, $registryView)
        } elseif ($regPath.StartsWith('HKCR:')) {
            $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::ClassesRoot, $registryView)
        } else {
            return (Get-ItemProperty -Path $regPath -Name $Name -ErrorAction Stop).$Name
        }

        $subKey = $baseKey.OpenSubKey($Key)
        if (-not $subKey) { return $null }
        return $subKey.GetValue($Name, $null)
    } catch {
        return $null
    }
}

# --- Test ref resolver (supports both styles) --------------------------------

function Get-TestRefs {
    param([System.Xml.XmlNode]$test)

    if ($null -eq $test) { return @{ objectRefId = $null; stateRefId = $null } }

    # Try attributes on the test element first
    $objAttr   = Get-AttrValue -Node $test -Name 'object_ref'
    $stateAttr = Get-AttrValue -Node $test -Name 'state_ref'

    # Try child <object object_ref="..."/> and <state state_ref="..."/>
    $objNode    = Select-XmlNode -Xml $test -XPath "./*[local-name()='object']"
    $stateNode  = Select-XmlNode -Xml $test -XPath "./*[local-name()='state']"
    $objChild   = Get-AttrValue -Node $objNode -Name 'object_ref'
    $stateChild = Get-AttrValue -Node $stateNode -Name 'state_ref'

    $objectRefId = Get-FirstDefined @($objAttr, $objChild)
    $stateRefId  = Get-FirstDefined @($stateAttr, $stateChild)

    return @{ objectRefId = $objectRefId; stateRefId = $stateRefId }
}

# --- Evidence meta helper ----------------------------------------------------

function Add-ResultMeta {
    param(
        [pscustomobject]$Result,
        [string]$DefinitionId,
        [string]$Comment
    )
    if ($Result -and $DefinitionId) {
        $Result | Add-Member -NotePropertyName RuleId -NotePropertyValue $DefinitionId -Force
    }
    if ($Result -and $Comment) {
        $Result | Add-Member -NotePropertyName Comment -NotePropertyValue $Comment -Force
    }
    return $Result
}

# --- AuditPol cache & evaluators --------------------------------------------

$script:AuditSubcategoryCache = $null

function Build-AuditSubcategoryCache {
    if ($script:AuditSubcategoryCache -ne $null) { return $script:AuditSubcategoryCache }
    $cache = @{}

    function Add-CacheEntry([string]$name, [string]$setting) {
        if ([string]::IsNullOrWhiteSpace($name)) { return }
        if ([string]::IsNullOrWhiteSpace($setting)) { return }
        if (-not $cache.ContainsKey($name)) { $cache[$name] = $setting }
    }

    try {
        # Raw mode
        $outR = @(auditpol.exe /get /subcategory:* /r 2>$null)
        if ($outR.Count -gt 0) {
            $block = @()
            foreach ($line in $outR) {
                if ($line -match '(?i)^\s*Category/Subcategory\s*:') {
                    if ($block.Count -gt 0) {
                        $name    = ($block | Where-Object { $_ -match '(?i)^\s*Category/Subcategory\s*:\s*' } | ForEach-Object { ($_ -split ':',2)[1].Trim() } | Select-Object -First 1)
                        $setting = ($block | Where-Object { $_ -match '(?i)^\s*(Inclusion Setting|Setting)\s*:\s*' } | ForEach-Object { ($_ -split ':',2)[1].Trim() } | Select-Object -First 1)
                        if (-not $setting) {
                            $joined = ($block -join "`n")
                            if ($joined -match '(?i)\bSuccess\s+and\s+Failure\b') { $setting = 'Success and Failure' }
                            elseif ($joined -match '(?i)\bNo\s+Auditing\b')       { $setting = 'No Auditing' }
                            elseif ($joined -match '(?i)^\s*Success\b')            { $setting = 'Success' }
                            elseif ($joined -match '(?i)^\s*Failure\b')            { $setting = 'Failure' }
                        }
                        Add-CacheEntry $name $setting
                        $block = @()
                    }
                }
                $block += $line
            }
            if ($block.Count -gt 0) {
                $name    = ($block | Where-Object { $_ -match '(?i)^\s*Category/Subcategory\s*:\s*' } | ForEach-Object { ($_ -split ':',2)[1].Trim() } | Select-Object -First 1)
                $setting = ($block | Where-Object { $_ -match '(?i)^\s*(Inclusion Setting|Setting)\s*:\s*' } | ForEach-Object { ($_ -split ':',2)[1].Trim() } | Select-Object -First 1)
                if (-not $setting) {
                    $joined = ($block -join "`n")
                    if ($joined -match '(?i)\bSuccess\s+and\s+Failure\b') { $setting = 'Success and Failure' }
                    elseif ($joined -match '(?i)\bNo\s+Auditing\b')       { $setting = 'No Auditing' }
                    elseif ($joined -match '(?i)^\s*Success\b')            { $setting = 'Success' }
                    elseif ($joined -match '(?i)^\s*Failure\b')            { $setting = 'Failure' }
                }
                Add-CacheEntry $name $setting
            }
        }

        # Table mode fallback
        if ($cache.Keys.Count -eq 0) {
            $outT = @(auditpol.exe /get /subcategory:* 2>$null)
            foreach ($line in $outT) {
                $m = [regex]::Match($line, '(?i)(?<name>.+?)\s+(?<setting>Success\s+and\s+Failure|Success|Failure|No\s+Auditing)\s*$')
                if ($m.Success) {
                    $name = $m.Groups['name'].Value.Trim()
                    $setting = $m.Groups['setting'].Value.Trim()
                    $name = ($name -replace '^\s*Category/Subcategory\s*:','').Trim()
                    Add-CacheEntry $name $setting
                }
            }
        }
    } catch {
        $cache = @{}
    }

    $script:AuditSubcategoryCache = $cache
    return $cache
}

function Get-AuditSubcategorySetting {
    param([string]$Subcategory)

    $rawOutput = @()
    $setting = $null
    $successEnabled = $false
    $failureEnabled = $false

    try {
        $rawOutput = @(auditpol.exe /get /subcategory:"$Subcategory" /r 2>$null)
        if ($rawOutput.Count -eq 0) {
            $rawOutput = @(auditpol.exe /get /subcategory:"$Subcategory" 2>$null)
        }
    } catch {
        $rawOutput = @("Error invoking auditpol.exe: $($_.Exception.Message)")
    }

    $txt = ($rawOutput -join "`n")

    # "Inclusion Setting" or "Setting"
    $m = [regex]::Match($txt, '(?im)^\s*(Inclusion Setting|Setting)\s*:\s*(?<set>.+?)\s*$')
    if ($m.Success) {
        $setting = $m.Groups['set'].Value.Trim()
    } else {
        if ($txt -match '(?i)\bSuccess\s+and\s+Failure\b') { $setting = 'Success and Failure' }
        elseif ($txt -match '(?i)\bNo\s+Auditing\b')       { $setting = 'No Auditing' }
        elseif ($txt -match '(?i)^\s*Success\b' -or $txt -match '(?i)\bSetting\s*:\s*Success\b') { $setting = 'Success' }
        elseif ($txt -match '(?i)^\s*Failure\b' -or $txt -match '(?i)\bSetting\s*:\s*Failure\b') { $setting = 'Failure' }
    }

    # Fallback to full cache
    if (-not $setting) {
        $cache = Build-AuditSubcategoryCache
        $hitKey = ($cache.Keys | Where-Object { $_.Trim().ToLowerInvariant() -eq $Subcategory.Trim().ToLowerInvariant() } | Select-Object -First 1)
        if (-not $hitKey) {
            $norm = ($Subcategory -replace '[_\s]+','').Trim().ToLowerInvariant()
            $hitKey = ($cache.Keys | Where-Object { (($_ -replace '[_\s]+','').Trim().ToLowerInvariant()) -eq $norm } | Select-Object -First 1)
        }
        if ($hitKey) { $setting = $cache[$hitKey] }
    }

    if (-not $setting) { $setting = 'Unknown' }

    $norm = $setting.Trim().ToUpperInvariant()
    switch -Regex ($norm) {
        '^SUCCESS\s+AND\s+FAILURE$' { $successEnabled = $true; $failureEnabled = $true }
        '^SUCCESS$'                 { $successEnabled = $true; $failureEnabled = $false }
        '^FAILURE$'                 { $successEnabled = $false; $failureEnabled = $true }
        'NO\s+AUDITING'             { $successEnabled = $false; $failureEnabled = $false }
        default                     { $successEnabled = $false; $failureEnabled = $false }
    }

    return [pscustomobject]@{
        SettingString  = $setting
        SuccessEnabled = $successEnabled
        FailureEnabled = $failureEnabled
        Raw            = $txt
    }
}

function Map-OvalAuditExpectation {
    param([string]$OvalValue)
    if ([string]::IsNullOrWhiteSpace($OvalValue)) { return $null }
    $v = $OvalValue.Trim().ToUpperInvariant()
    switch ($v) {
        'AUDIT_SUCCESS_FAILURE' { return 'Success and Failure' }
        'AUDIT_SUCCESS'         { return 'Success' }
        'AUDIT_FAILURE'         { return 'Failure' }
        'NOT_AUDITED'           { return 'No Auditing' }
        'DISABLED'              { return 'No Auditing' }
        default                 { return ($OvalValue -replace '_',' ').Trim() }
    }
}

function Evaluate-AuditEventPolicySubcategoriesTest {
    param([System.Xml.XmlNode]$test)

    $refs = Get-TestRefs -test $test
    $objectRefId = $refs.objectRefId
    $stateRefId  = $refs.stateRefId

    $obj = $null
    if ($objectRefId -and $objects.ContainsKey($objectRefId)) { $obj = $objects[$objectRefId] }
    $stateNode = $null
    if ($stateRefId -and $states.ContainsKey($stateRefId)) { $stateNode = $states[$stateRefId] }

    if (-not $obj) { return [pscustomobject]@{ Type='AuditPolicy'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="Audit policy object not found: $objectRefId" } }
    if (-not $stateNode) { return [pscustomobject]@{ Type='AuditPolicy'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="Audit policy state not found: $stateRefId" } }

    $subcategoryMap = @{
        'sensitive_privilege_use'     = 'Sensitive Privilege Use'
        'logon'                       = 'Logon'
        'logoff'                      = 'Logoff'
        'account_lockout'             = 'Account Lockout'
        'special_logon'               = 'Special Logon'
        'other_object_access_events'  = 'Other Object Access Events'
        'handle_manipulation'         = 'Handle Manipulation'
        'registry'                    = 'Registry'
        'file_system'                 = 'File System'
        'process_creation'            = 'Process Creation'
        'security_state_change'       = 'Security State Change'
        'security_system_extension'   = 'Security System Extension'
        'system_integrity'            = 'System Integrity'
        'audit_policy_change'         = 'Audit Policy Change'
        'authentication_policy_change'= 'Authentication Policy Change'
        'authorization_policy_change' = 'Authorization Policy Change'
        'directory_service_access'    = 'Directory Service Access'
        'directory_service_changes'   = 'Directory Service Changes'
        'computer_account_management' = 'Computer Account Management'
        'user_account_management'     = 'User Account Management'
        'security_group_management'   = 'Security Group Management'
        'credential_validation'       = 'Credential Validation'
        'ipsec_driver'                = 'IPsec Driver'
        'other_system_events'         = 'Other System Events'
    }

    $results = @()
    foreach ($child in $stateNode.ChildNodes) {
        if (-not ($child -is [System.Xml.XmlElement])) { continue }
        $fieldName = $child.LocalName
        $expectedLiteral = (Get-InnerText $child)

        $expectedCanonical = Map-OvalAuditExpectation -OvalValue $expectedLiteral
        if (-not $expectedCanonical) { $expectedCanonical = ($expectedLiteral -replace '_',' ').Trim() }

        $subcategory = $subcategoryMap[$fieldName]
        if (-not $subcategory) { $subcategory = ($fieldName -replace '_',' ').Trim() }

        $actualInfo = Get-AuditSubcategorySetting -Subcategory $subcategory
        $actualCanonical = $actualInfo.SettingString
        $pass = ($actualCanonical.Trim().ToUpperInvariant() -eq $expectedCanonical.Trim().ToUpperInvariant())

        $results += [pscustomobject]@{
            Type        = 'AuditPolicy'
            Subcategory = $subcategory
            Expected    = $expectedCanonical
            Actual      = $actualCanonical
            Pass        = $pass
            Evidence    = "auditpol.exe /get /subcategory:`"$subcategory`" => $($actualInfo.SettingString); SuccessEnabled=$($actualInfo.SuccessEnabled); FailureEnabled=$($actualInfo.FailureEnabled)"
            RawOutput   = $actualInfo.Raw
        }
    }

    $overallPass = (($results | Where-Object { -not $_.Pass }) | Measure-Object).Count -eq 0
    return [pscustomobject]@{
        Type     = 'AuditPolicy'
        Pass     = $overallPass
        Details  = $results
    }
}

# --- WMI helpers -------------------------------------------------------------

function Invoke-WmiQuery {
    param(
        [string]$Namespace,
        [string]$Query,
        [int]$MaxRows = 1000,
        [bool]$UseCim = $true
    )
    if ([string]::IsNullOrWhiteSpace($Namespace) -or [string]::IsNullOrWhiteSpace($Query)) {
        return @()
    }
    try {
        if ($UseCim) {
            $res = Get-CimInstance -Namespace $Namespace -Query $Query -ErrorAction Stop
        } else {
            $res = Get-WmiObject -Namespace $Namespace -Query $Query -ErrorAction Stop
        }
        if ($null -eq $res) { return @() }
        $arr = @($res)
        if ($arr.Count -gt $MaxRows) { return $arr[0..($MaxRows-1)] }
        return $arr
    } catch {
        return @()
    }
}

# --- User account helpers ------------------------------------------------------
function Get-LocalAccountNameBySid {
    param([string]$sid)
    $actualName = $null

    # Try Get-LocalUser (PowerShell 5.1+)
    if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
        $user = Get-LocalUser | Where-Object { $_.SID -eq $sid }
        if ($user) { return $user.Name }
    }

    # Try net user as fallback
    try {
        $users = net user | Select-String -Pattern '^\s+\w' | ForEach-Object { $_.ToString().Trim() }
        foreach ($user in $users) {
            $info = net user "$user" | Out-String
            if ($info -match "SID\s+:\s+($sid)") {
                return $user
            }
        }
    } catch { }

    # Try CIM
    try {
        $cim = Get-CimInstance -ClassName Win32_UserAccount | Where-Object { $_.SID -eq $sid }
        if ($cim) { return $cim.Name }
    } catch { }

    return $null
}


# --- New: Account Lockout Policy evaluator ----------------------------------

function Get-SystemAccessPolicy {
    <#
      Exports Local Security Policy to a temp file and returns a hashtable of [System Access] settings:
        Keys: LockoutBadCount, ResetLockoutCount, LockoutDuration
    #>
    $temp = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "secpol_$([System.Guid]::NewGuid().ToString()).cfg")
    $ht = @{}
    try {
        # Export only security policy area for speed
        secedit.exe /export /areas SECURITYPOLICY /cfg "$temp" 2>$null | Out-Null
        if (Test-Path -LiteralPath $temp) {
            $lines = Get-Content -LiteralPath $temp -ErrorAction SilentlyContinue
            $inSystemAccess = $false
            foreach ($line in $lines) {
                if ($line -match '^\s*\[System Access\]\s*$') { $inSystemAccess = $true; continue }
                if ($line -match '^\s*\[.+\]\s*$') { if ($inSystemAccess) { $inSystemAccess = $false } }
                if ($inSystemAccess -and $line -match '^\s*([^=]+?)\s*=\s*(.*?)\s*$') {
                    $key = $matches[1].Trim()
                    $val = $matches[2].Trim()
                    $ht[$key] = $val
                }
            }
        }
    } catch {
        # no-op; return empty hashtable
    } finally {
        try { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue } } catch {}
    }
    return $ht
}

function Evaluate-LockoutPolicyTest {
    param([System.Xml.XmlNode]$test)

    # win-def:lockoutpolicy_test generally has an object (often empty) and a state with fields
    $refs = Get-TestRefs -test $test
    $stateNode = $null
    if ($refs.stateRefId -and $states.ContainsKey($refs.stateRefId)) { $stateNode = $states[$refs.stateRefId] }
    if (-not $stateNode) {
        return [pscustomobject]@{ Type='LockoutPolicy'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="Lockout policy state not found: $($refs.stateRefId)" }
    }

    # Map OVAL state fields to secedit keys
    $fieldMap = @{
        'lockout_threshold'   = 'LockoutBadCount'     # Number of invalid logon attempts
        'reset_lockout_count' = 'ResetLockoutCount'   # Observation window (minutes)
        'lockout_duration'    = 'LockoutDuration'     # Duration (minutes)
    }

    $policy = Get-SystemAccessPolicy
    $results = @()
    $allPass = $true

    foreach ($child in $stateNode.ChildNodes) {
        if (-not ($child -is [System.Xml.XmlElement])) { continue }
        $fieldName = $child.LocalName
        if (-not $fieldMap.ContainsKey($fieldName)) { continue }

        $expected = Get-InnerText $child
        $operation = Get-AttrValue -Node $child -Name 'operation'; if (-not $operation) { $operation = 'equals' }
        $datatype  = Get-AttrValue -Node $child -Name 'datatype';  if (-not $datatype)  { $datatype  = 'int' }

        $key = $fieldMap[$fieldName]
        $actual = $null
        if ($policy.ContainsKey($key)) { $actual = $policy[$key] }

        # Convert to integer when appropriate
        $pass = Compare-Value -Actual $actual -Expected $expected -Operation $operation -Datatype $datatype

        if (-not $pass) { $allPass = $false }
        $results += [pscustomobject]@{
            Type     = 'LockoutPolicy'
            Field    = $fieldName
            PolicyKey= $key
            Expected = $expected
            Actual   = if ($null -ne $actual) { $actual } else { '(null)' }
            Pass     = $pass
            Evidence = "op=$operation, datatype=$datatype"
        }
    }

    return [pscustomobject]@{
        Type    = 'LockoutPolicy'
        Pass    = $allPass
        Details = $results
    }
}

# --- Other test evaluators ---------------------------------------------------

function Evaluate-WMITest {
    param([System.Xml.XmlNode]$test)

    $refs = Get-TestRefs -test $test
    $objectRefId = $refs.objectRefId
    $stateRefId  = $refs.stateRefId
    
    $obj = $null
    if ($objectRefId -and $objects.ContainsKey($objectRefId)) { $obj = $objects[$objectRefId] }
    $stateNode = $null
    if ($stateRefId -and $states.ContainsKey($stateRefId)) { $stateNode = $states[$stateRefId] }
    
    if (-not $obj) { return [pscustomobject]@{ Type='WMI'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="WMI object not found: $objectRefId" } }

    $namespace = Get-InnerText (Select-XmlNode -Xml $obj -XPath "./*[local-name()='namespace']")
    $wql       = Get-InnerText (Select-XmlNode -Xml $obj -XPath "./*[local-name()='wql']")

    if ([string]::IsNullOrWhiteSpace($namespace) -or [string]::IsNullOrWhiteSpace($wql)) {
        return [pscustomobject]@{
            Type='WMI'; Namespace=$namespace; WQL=$wql
            Expected='N/A'; Actual='N/A'; Pass=$false
            Evidence='Missing namespace or WQL in WMI object.'
        }
    }

    # Existence-only if no state
    if (-not $stateNode) {
        $checkExistence = Get-AttrValue -Node $test -Name 'check_existence'
        $rows = @(Invoke-WmiQuery -Namespace $namespace -Query $wql -MaxRows $MaxWmiRows -UseCim $UseCim)
        $rowCount = ($rows | Measure-Object).Count
        
        $pass = $false
        switch ($checkExistence) {
            'all_exist' { $pass = ($rowCount -gt 0) }
            'any_exist' { $pass = ($rowCount -gt 0) }
            'at_least_one_exists' { $pass = ($rowCount -gt 0) }
            'none_exist' { $pass = ($rowCount -eq 0) }
            'only_one_exists' { $pass = ($rowCount -eq 1) }
            default { $pass = ($rowCount -gt 0) }
        }
        
        return [pscustomobject]@{
            Type='WMI'; Namespace=$namespace; WQL=$wql
            Expected="check_existence=$checkExistence"
            Actual="rows=$rowCount"
            Pass=$pass
            Evidence="Query returned $rowCount row(s), check_existence=$checkExistence"
        }
    }

    # Handle tests with states (value comparisons)
    $resultNode = Select-XmlNode -Xml $stateNode -XPath "./*[local-name()='result']"
    if (-not $resultNode) {
        return [pscustomobject]@{
            Type='WMI'; Namespace=$namespace; WQL=$wql
            Expected='N/A'; Actual='N/A'; Pass=$false
            Evidence='No result node in state'
        }
    }

    $fieldNodes = Select-XmlNodes -Xml $resultNode -XPath "./*[local-name()='field']"
    $rows = @(Invoke-WmiQuery -Namespace $namespace -Query $wql -MaxRows $MaxWmiRows -UseCim $UseCim)
    $rowsCount = ($rows | Measure-Object).Count
    
    if ($rowsCount -eq 0) {
        $checkExistence = Get-AttrValue -Node $test -Name 'check_existence'
        if ($checkExistence -eq 'none_exist') {
            return [pscustomobject]@{
                Type='WMI'; Namespace=$namespace; WQL=$wql
                Expected='No rows'; Actual='No rows'; Pass=$true
                Evidence='No rows returned (as expected)'
            }
        }
        return [pscustomobject]@{
            Type='WMI'; Namespace=$namespace; WQL=$wql
            Expected='Data rows'; Actual='No rows'; Pass=$false
            Evidence='No rows returned from WMI query'
        }
    }

    # Process field-based checks
    $allFieldsPass = $true
    $fieldResults = @()
    
    foreach ($fieldNode in $fieldNodes) {
        $fieldName = Get-AttrValue -Node $fieldNode -Name 'name'
        $expected = Get-InnerText $fieldNode
        $operation = Get-AttrValue -Node $fieldNode -Name 'operation'; if (-not $operation) { $operation = 'equals' }
        $datatype = Get-AttrValue -Node $fieldNode -Name 'datatype'; if (-not $datatype) { $datatype = 'string' }
        $entityCheck = Get-AttrValue -Node $fieldNode -Name 'entity_check'; if (-not $entityCheck) { $entityCheck = 'all' }
        
        $fieldPass = $false
        $actualValues = @()
        
        foreach ($row in $rows) {
            if ($row.PSObject.Properties.Match($fieldName).Count -gt 0) {
                $actualValues += $row.$fieldName
            }
        }
        
        switch ($entityCheck) {
            'all' {
                $fieldPass = $true
                foreach ($val in $actualValues) {
                    if (-not (Compare-Value -Actual $val -Expected $expected -Operation $operation -Datatype $datatype)) {
                        $fieldPass = $false
                        break
                    }
                }
            }
            'at least one' {
                $fieldPass = $false
                foreach ($val in $actualValues) {
                    if (Compare-Value -Actual $val -Expected $expected -Operation $operation -Datatype $datatype) {
                        $fieldPass = $true
                        break
                    }
                }
            }
            'none satisfy' {
                $fieldPass = $true
                foreach ($val in $actualValues) {
                    if (Compare-Value -Actual $val -Expected $expected -Operation $operation -Datatype $datatype) {
                        $fieldPass = $false
                        break
                    }
                }
            }
            'only one' {
                $matchCount = 0
                foreach ($val in $actualValues) {
                    if (Compare-Value -Actual $val -Expected $expected -Operation $operation -Datatype $datatype) {
                        $matchCount++
                    }
                }
                $fieldPass = ($matchCount -eq 1)
            }
            default {
                $fieldPass = $true
                foreach ($val in $actualValues) {
                    if (-not (Compare-Value -Actual $val -Expected $expected -Operation $operation -Datatype $datatype)) {
                        $fieldPass = $false
                        break
                    }
                }
            }
        }
        
        $fieldResults += "$fieldName=$($actualValues -join ',')"
        if (-not $fieldPass) { $allFieldsPass = $false }
    }

    return [pscustomobject]@{
        Type='WMI'; Namespace=$namespace; WQL=$wql
        Expected="Field checks per state"
        Actual=($fieldResults -join '; ')
        Pass=$allFieldsPass
        Evidence="Rows=$rowsCount, fields checked=$((@($fieldNodes) | Measure-Object).Count)"
    }
}

function Evaluate-RegistryTest {
    param([System.Xml.XmlNode]$test)

    $refs = Get-TestRefs -test $test
    $objectRefId = $refs.objectRefId
    $stateRefId  = $refs.stateRefId

    $obj = $null
    if ($objectRefId -and $objects.ContainsKey($objectRefId)) { $obj = $objects[$objectRefId] }
    $stateNode = $null
    if ($stateRefId -and $states.ContainsKey($stateRefId)) { $stateNode = $states[$stateRefId] }
    
    if (-not $obj) {
        return [pscustomobject]@{ Type='Registry'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="Registry object not found: $objectRefId" }
    }

    $hive = Get-InnerText (Select-XmlNode -Xml $obj -XPath "./*[local-name()='hive']")
    $key  = Get-InnerText (Select-XmlNode -Xml $obj -XPath "./*[local-name()='key']")
    $name = Get-InnerText (Select-XmlNode -Xml $obj -XPath "./*[local-name()='name']")

    # Existence-only if no state
    if (-not $stateNode) {
        $checkExistence = Get-AttrValue -Node $test -Name 'check_existence'
        $val = $null
        if ($name) { $val = Get-RegistryItemProperty -Hive $hive -Key $key -Name $name }
        else {
            $mappedHive = $hive -replace '^HKEY_LOCAL_MACHINE$', 'HKLM:' -replace '^HKEY_CURRENT_USER$', 'HKCU:' -replace '^HKEY_USERS$', 'HKU:' -replace '^HKEY_CLASSES_ROOT$', 'HKCR:'
            $regPath = "$mappedHive\$key"
            try { $val = if (Test-Path -LiteralPath $regPath) { 'key_exists' } else { $null } } catch { $val = $null }
        }
        $exists = ($null -ne $val)
        $pass = $false
        switch ($checkExistence) {
            'none_exist'       { $pass = (-not $exists) }
            'only_one_exists'  { $pass = $exists } # single entity context
            'at_least_one_exists' { $pass = $exists }
            'any_exist'        { $pass = $exists }
            default            { $pass = $exists } # default is existence is required
        }
        return [pscustomobject]@{
            Type     = 'Registry'
            Path     = "$hive\$key"
            Name     = $name
            Expected = "check_existence=$checkExistence"
            Actual   = "exists=$exists"
            Pass     = $pass
            Evidence = "existence check on registry entity"
        }
    }

    $valueNode = Select-XmlNode -Xml $stateNode -XPath "./*[local-name()='value']"
    $expected = Get-InnerText $valueNode

    $operation     = Get-AttrValue -Node $valueNode -Name 'operation';     if (-not $operation) { $operation = 'equals' }
    $datatype      = Get-AttrValue -Node $valueNode -Name 'datatype';      if (-not $datatype) { $datatype = 'string' }
    $caseSensitive = ((Get-AttrValue -Node $valueNode -Name 'case_sensitive') -eq 'true')

    $varRef = Get-AttrValue -Node $valueNode -Name 'var_ref'
    if ($varRef) {
        $vals = Resolve-VarRef -VarRef $varRef
        $actual = Get-RegistryItemProperty -Hive $hive -Key $key -Name $name
        $anyPass = $false
        if ($vals -and $vals.Count -gt 0) {
            foreach ($v in $vals) {
                if (Compare-Value -Actual $actual -Expected $v -Operation $operation -Datatype $datatype -CaseSensitive $caseSensitive) { $anyPass = $true; break }
            }
        }
        return [pscustomobject]@{
            Type     = 'Registry'
            Path     = "$hive\$key"
            Name     = $name
            Expected = ($vals -join ', ')
            Actual   = if ($null -ne $actual) { $actual } else { '(null)' }
            Pass     = $anyPass
            Evidence = if ($anyPass) { "Match found among variable values (op=$operation, datatype=$datatype)" } else { "No matches among variable values (op=$operation, datatype=$datatype)" }
        }
    }

    $actualValue = Get-RegistryItemProperty -Hive $hive -Key $key -Name $name
    $pass = Compare-Value -Actual $actualValue -Expected $expected -Operation $operation -Datatype $datatype -CaseSensitive $caseSensitive
    return [pscustomobject]@{
        Type     = 'Registry'
        Path     = "$hive\$key"
        Name     = $name
        Expected = if ($null -ne $expected) { $expected } else { '(null)' }
        Actual   = if ($null -ne $actualValue) { $actualValue } else { '(null)' }
        Pass     = $pass
        Evidence = "op=$operation, datatype=$datatype, caseSensitive=$caseSensitive"
    }
}

function Evaluate-FileTest {
    param([System.Xml.XmlNode]$test)

    $refs = Get-TestRefs -test $test
    $objectRefId = $refs.objectRefId
    $stateRefId  = $refs.stateRefId

    $obj = $null
    if ($objectRefId -and $objects.ContainsKey($objectRefId)) { $obj = $objects[$objectRefId] }
    $stateNode = $null
    if ($stateRefId -and $states.ContainsKey($stateRefId)) { $stateNode = $states[$stateRefId] }
    
    if (-not $obj) { return [pscustomobject]@{ Type='File'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="File object not found: $objectRefId" } }
    if (-not $stateNode) { return [pscustomobject]@{ Type='File'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="File state not found: $stateRefId" } }

    $path     = Get-InnerText (Select-XmlNode -Xml $obj -XPath "./*[local-name()='path']")
    $filename = Get-InnerText (Select-XmlNode -Xml $obj -XPath "./*[local-name()='filename']")
    $fullPath = if ($path -and $filename) { Join-Path $path $filename } elseif ($path) { $path } else { $filename }

    if ([string]::IsNullOrWhiteSpace($fullPath)) {
        return [pscustomobject]@{
            Type='File'; Path=$fullPath; Expected='N/A'; Actual='N/A'; Pass=$false
            Evidence='Missing path/filename in file object.'
        }
    }

    $existsNode  = Select-XmlNode -Xml $stateNode -XPath "./*[local-name()='exists']"
    $versionNode = Select-XmlNode -Xml $stateNode -XPath "./*[local-name()='version']"
    $sizeNode    = Select-XmlNode -Xml $stateNode -XPath "./*[local-name()='size']"

    $existsExpected = To-Bool (Get-InnerText $existsNode)
    $existsOp = Get-AttrValue -Node $existsNode -Name 'operation'; if (-not $existsOp) { $existsOp = 'equals' }

    $existsActual = $false
    try { $existsActual = Test-Path -LiteralPath $fullPath } catch { $existsActual = $false }
    $existsPass = $true
    if ($existsNode) {
        $existsPass = Compare-Value -Actual $existsActual -Expected $existsExpected -Operation $existsOp -Datatype 'boolean'
    }

    $versionPass = $true; $versionActual = $null; $versionExpected = Get-InnerText $versionNode
    if ($versionNode -and $existsActual) {
        try {
            $fi = Get-Item -LiteralPath $fullPath -ErrorAction Stop
            $versionActual = $fi.VersionInfo.FileVersion
            $versionOp = Get-AttrValue -Node $versionNode -Name 'operation'; if (-not $versionOp) { $versionOp = 'equals' }
            $versionPass = Compare-Value -Actual $versionActual -Expected $versionExpected -Operation $versionOp -Datatype 'version'
        } catch { $versionPass = $false }
    }

    $sizePass = $true; $sizeActual = $null; $sizeExpected = Get-InnerText $sizeNode
    if ($sizeNode -and $existsActual) {
        try {
            $fi = Get-Item -LiteralPath $fullPath -ErrorAction Stop
            $sizeActual = $fi.Length
            $sizeOp = Get-AttrValue -Node $sizeNode -Name 'operation'; if (-not $sizeOp) { $sizeOp = 'equals' }
            $sizePass = Compare-Value -Actual $sizeActual -Expected $sizeExpected -Operation $sizeOp -Datatype 'integer'
        } catch { $sizePass = $false }
    }

    $overallPass = ($existsPass -and $versionPass -and $sizePass)
    return [pscustomobject]@{
        Type     = 'File'
        Path     = $fullPath
        Expected = "exists=$existsExpected; version=$versionExpected; size=$sizeExpected"
        Actual   = "exists=$existsActual; version=$versionActual; size=$sizeActual"
        Pass     = $overallPass
        Evidence = "existsPass=$existsPass, versionPass=$versionPass, sizePass=$sizePass"
    }
}

function Evaluate-ServiceTest {
    param([System.Xml.XmlNode]$test)

    $refs = Get-TestRefs -test $test
    $objectRefId = $refs.objectRefId
    $stateRefId  = $refs.stateRefId

    $obj = $null
    if ($objectRefId -and $objects.ContainsKey($objectRefId)) { $obj = $objects[$objectRefId] }
    $stateNode = $null
    if ($stateRefId -and $states.ContainsKey($stateRefId)) { $stateNode = $states[$stateRefId] }
    
    if (-not $obj) { return [pscustomobject]@{ Type='Service'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="Service object not found: $objectRefId" } }
    if (-not $stateNode) { return [pscustomobject]@{ Type='Service'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="Service state not found: $stateRefId" } }

    $svcName = Get-InnerText (Select-XmlNode -Xml $obj -XPath "./*[local-name()='service_name']")
    if (-not $svcName) { return [pscustomobject]@{ Type = 'Service'; Pass = $false; Expected='N/A'; Actual='N/A'; Evidence = "service_name not provided" } }

    $expectedStartType = Get-InnerText (Select-XmlNode -Xml $stateNode -XPath "./*[local-name()='start_type']")
    $expectedStatus    = Get-InnerText (Select-XmlNode -Xml $stateNode -XPath "./*[local-name()='status']")

    $existsPass = $false
    $startTypePass = $true
    $statusPass = $true
    $actualStartType = $null
    $actualStatus = $null

    try {
        $svc = Get-Service -Name $svcName -ErrorAction Stop
        $existsPass = $true
        $actualStatus = $svc.Status.ToString()
        if ($expectedStartType) {
            $svcInfo = Get-CimInstance -ClassName Win32_Service -Filter "Name='$svcName'" -ErrorAction SilentlyContinue
            $actualStartType = if ($svcInfo) { $svcInfo.StartMode } else { $null }
            $startTypePass = Compare-Value -Actual $actualStartType -Expected $expectedStartType -Operation 'equals' -Datatype 'string'
        }
        if ($expectedStatus) {
            $statusPass = Compare-Value -Actual $actualStatus -Expected $expectedStatus -Operation 'equals' -Datatype 'string'
        }
    } catch {
        $existsPass = $false
        $startTypePass = $false
        $statusPass = $false
    }

    $overallPass = ($existsPass -and $startTypePass -and $statusPass)
    return [pscustomobject]@{
        Type     = 'Service'
        Name     = $svcName
        Expected = "exists=true; start_type=$expectedStartType; status=$expectedStatus"
        Actual   = "exists=$existsPass; start_type=$actualStartType; status=$actualStatus"
        Pass     = $overallPass
        Evidence = "existsPass=$existsPass, startTypePass=$startTypePass, statusPass=$statusPass"
    }
}

function Evaluate-ProcessTest {
    param([System.Xml.XmlNode]$test)

    $refs = Get-TestRefs -test $test
    $objectRefId = $refs.objectRefId
    $stateRefId  = $refs.stateRefId

    $obj = $null
    if ($objectRefId -and $objects.ContainsKey($objectRefId)) { $obj = $objects[$objectRefId] }
    $stateNode = $null
    if ($stateRefId -and $states.ContainsKey($stateRefId)) { $stateNode = $states[$stateRefId] }
    
    if (-not $obj) { return [pscustomobject]@{ Type='Process'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="Process object not found: $objectRefId" } }

    $name = Get-InnerText (Select-XmlNode -Xml $obj -XPath "./*[local-name()='name']")
    if (-not $name) { return [pscustomobject]@{ Type = 'Process'; Pass = $false; Expected='N/A'; Actual='N/A'; Evidence = 'Process name missing' } }

    $expectedExists = $true
    $existsOp = 'equals'
    if ($stateNode) {
        $existsNode = Select-XmlNode -Xml $stateNode -XPath "./*[local-name()='exists']"
        if ($existsNode) {
            $expectedExists = To-Bool (Get-InnerText $existsNode)
            $existsOp = Get-AttrValue -Node $existsNode -Name 'operation'; if (-not $existsOp) { $existsOp = 'equals' }
        }
    }

    $procs = @()
    try {
        $procs = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='$name'" -ErrorAction SilentlyContinue)
        if ($procs.Count -eq 0) {
            $procs = @(Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $name -or ($_.ExecutablePath -and $_.ExecutablePath -like "*\$name") })
        }
    } catch { $procs = @() }
    $procCount = ($procs | Measure-Object).Count
    $actualExists = ($procCount -gt 0)

    $pass = Compare-Value -Actual $actualExists -Expected $expectedExists -Operation $existsOp -Datatype 'boolean'
    return [pscustomobject]@{
        Type     = 'Process'
        Name     = $name
        Expected = "exists=$expectedExists"
        Actual   = "exists=$actualExists"
        Pass     = $pass
        Evidence = "count=$procCount"
    }
}

function Evaluate-QfeTest {
    param([System.Xml.XmlNode]$test)

    $refs = Get-TestRefs -test $test
    $objectRefId = $refs.objectRefId
    $stateRefId  = $refs.stateRefId

    $obj = $null
    if ($objectRefId -and $objects.ContainsKey($objectRefId)) { $obj = $objects[$objectRefId] }
    $stateNode = $null
    if ($stateRefId -and $states.ContainsKey($stateRefId)) { $stateNode = $states[$stateRefId] }
    
    if (-not $obj) { return [pscustomobject]@{ Type='QFE'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="QFE object not found: $objectRefId" } }

    $hotfixId = Get-InnerText (Select-XmlNode -Xml $obj -XPath "./*[local-name()='hotfix_id']")
    if (-not $hotfixId) { return [pscustomobject]@{ Type = 'QFE'; Pass = $false; Expected='N/A'; Actual='N/A'; Evidence = 'hotfix_id missing' } }

    $expectedInstalled = $true
    $installedOp = 'equals'
    if ($stateNode) {
        $installedNode = Select-XmlNode -Xml $stateNode -XPath "./*[local-name()='installed']"
        if ($installedNode) {
            $expectedInstalled = To-Bool (Get-InnerText $installedNode)
            $installedOp = Get-AttrValue -Node $installedNode -Name 'operation'; if (-not $installedOp) { $installedOp = 'equals' }
        }
    }

    $hf = $null
    try { $hf = Get-HotFix -Id $hotfixId -ErrorAction SilentlyContinue } catch { $hf = $null }
    $actualInstalled = ($null -ne $hf)
    $pass = Compare-Value -Actual $actualInstalled -Expected $expectedInstalled -Operation $installedOp -Datatype 'boolean'
    return [pscustomobject]@{
        Type     = 'QFE'
        HotfixId = $hotfixId
        Expected = "installed=$expectedInstalled"
        Actual   = "installed=$actualInstalled"
        Pass     = $pass
        Evidence = if ($hf) { "Installed On=$($hf.InstalledOn)" } else { "Not installed" }
    }
}



function Evaluate-SidSidTest {
    param([System.Xml.XmlNode]$test)

    $refs = Get-TestRefs -test $test
    $objectRefId = $refs.objectRefId
    $stateRefId  = $refs.stateRefId

    $obj = $null
    if ($objectRefId -and $objects.ContainsKey($objectRefId)) { $obj = $objects[$objectRefId] }
    $stateNode = $null
    if ($stateRefId -and $states.ContainsKey($stateRefId)) { $stateNode = $states[$stateRefId] }

    if (-not $obj) { return [pscustomobject]@{ Type='SidSid'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="SID object not found: $objectRefId" } }
    if (-not $stateNode) { return [pscustomobject]@{ Type='SidSid'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="SID state not found: $stateRefId" } }

    $sidNode = Select-XmlNode -Xml $obj -XPath "./*[local-name()='trustee_sid']"
    if ($sidNode -is [System.Collections.IEnumerable] -and -not ($sidNode -is [string])) { $sidNode = $sidNode | Select-Object -First 1 }
    $sid = Get-InnerText $sidNode
    $sid = $sid.Trim()

    # If $sid is a regex, extract the RID and find the actual SID
    if ($sid -match '^\^S-1-5-\[0-9-\]\+\-(\d+)\$$') {
        $rid = $Matches[1]
        $user = Get-LocalUser | Where-Object { $_.SID -match "-$rid$" }
        if ($user) { $sid = $user.SID }
    }

    $nameNode = Select-XmlNode -Xml $stateNode -XPath "./*[local-name()='trustee_name']"
    if ($nameNode -is [System.Collections.IEnumerable] -and -not ($nameNode -is [string])) { $nameNode = $nameNode | Select-Object -First 1 }
    $expectedName = Get-InnerText $nameNode
    $operation = Get-AttrValue -Node $nameNode -Name 'operation'
    if (-not $operation) { $operation = 'equals' }

    # Try Get-LocalUser first
    $actualName = $null
    if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
        $user = Get-LocalUser | Where-Object { $_.SID -eq $sid }
        if ($user) { $actualName = $user.Name }
    }
    # Fallback to CIM
    if (-not $actualName) {
        try {
            $cim = Get-CimInstance -ClassName Win32_UserAccount | Where-Object { $_.SID -eq $sid }
            if ($cim) { $actualName = $cim.Name }
        } catch { }
    }
    # Fallback to .NET
    if (-not $actualName) {
        try {
            $account = ([System.Security.Principal.SecurityIdentifier]$sid).Translate([System.Security.Principal.NTAccount])
            $actualName = $account.Value
        } catch { }
    }
    if (-not $actualName) { $actualName = "(unresolved)" }

    $pass = Compare-Value -Actual $actualName -Expected $expectedName -Operation $operation -Datatype 'string'
    return [pscustomobject]@{
        Type     = 'SidSid'
        SID      = $sid
        Expected = $expectedName
        Actual   = $actualName
        Pass     = $pass
        Evidence = "SID $sid resolved to '$actualName' (expected $expectedName, op=$operation)"
    }
}


function Evaluate-AccessTokenTest {
    param([System.Xml.XmlNode]$test)

    $refs = Get-TestRefs -test $test
    $objectRefId = $refs.objectRefId
    $stateRefId  = $refs.stateRefId

    $obj = $null
    if ($objectRefId -and $objects.ContainsKey($objectRefId)) { $obj = $objects[$objectRefId] }
    $stateNode = $null
    if ($stateRefId -and $states.ContainsKey($stateRefId)) { $stateNode = $states[$stateRefId] }

    if (-not $obj) { return [pscustomobject]@{ Type='AccessToken'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="AccessToken object not found: $objectRefId" } }
    if (-not $stateNode) { return [pscustomobject]@{ Type='AccessToken'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="AccessToken state not found: $stateRefId" } }

    # Find which privilege is being checked
    $privNode = $stateNode.ChildNodes | Where-Object { $_.LocalName -like '*privilege' }
    if ($privNode -is [System.Collections.IEnumerable] -and -not ($privNode -is [string])) { $privNode = $privNode | Select-Object -First 1 }
    if (-not $privNode) {
        return [pscustomobject]@{ Type='AccessToken'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="No privilege node found in state" }
    }
    $privilege = $privNode.LocalName

    # Map OVAL privilege names to secedit names and expected SIDs
    $privMap = @{
        'seprofilesingleprocessprivilege' = @{
            'secedit' = 'SeProfileSingleProcessPrivilege'
            'expected' = @('S-1-5-32-544') # Administrators
        }
        'seimpersonateprivilege' = @{
            'secedit' = 'SeImpersonatePrivilege'
            'expected' = @('S-1-5-32-544','S-1-5-19','S-1-5-20','S-1-5-6') # Admins, Local Service, Network Service, Service
        }
        # Add more mappings as needed
    }
    $privKey = $privilege.ToLower()
    $right = $privMap[$privKey]?.secedit
    $expectedSIDs = $privMap[$privKey]?.expected
    if (-not $right) { $right = $privilege }
    if (-not $expectedSIDs) { $expectedSIDs = @('S-1-5-32-544') } # Default to Administrators

    # Export user rights assignments
    $seceditFile = [System.IO.Path]::GetTempFileName()
    secedit.exe /export /cfg $seceditFile 2>$null | Out-Null
    $lines = Get-Content $seceditFile -ErrorAction SilentlyContinue
    Remove-Item $seceditFile -Force -ErrorAction SilentlyContinue

    $line = $lines | Where-Object { $_ -match "^$right\s*=" }
    $actual = if ($line) { ($line -split '=',2)[1].Trim() } else { '' }

    # Parse actual SIDs (may be in the form *S-1-5-32-544,*S-1-5-19, etc.)
    $actualSIDs = @()
    if ($actual) {
        $actualSIDs = $actual -split ',' | ForEach-Object { $_.Trim().TrimStart('*') }
    }

    # Compare: Pass if actual SIDs match expected SIDs (order-insensitive, exact match)
    $pass = @($actualSIDs | Sort-Object) -eq @($expectedSIDs | Sort-Object)

    return [pscustomobject]@{
        Type     = 'AccessToken'
        Privilege= $right
        Expected = ($expectedSIDs -join ', ')
        Actual   = ($actualSIDs -join ', ')
        Pass     = $pass
        Evidence = "Privilege $right assigned to: $($actualSIDs -join ', ') (expected $($expectedSIDs -join ', '))"
    }
}

# --- New: AccessToken test evaluator ----------------------------------------


function Evaluate-AccessTokenTest {
    param([System.Xml.XmlNode]$test)

    $refs = Get-TestRefs -test $test
    $objectRefId = $refs.objectRefId
    $stateRefId  = $refs.stateRefId

    $obj = $null
    if ($objectRefId -and $objects.ContainsKey($objectRefId)) { $obj = $objects[$objectRefId] }
    $stateNode = $null
    if ($stateRefId -and $states.ContainsKey($stateRefId)) { $stateNode = $states[$stateRefId] }

    if (-not $obj) { return [pscustomobject]@{ Type='AccessToken'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="AccessToken object not found: $objectRefId" } }
    if (-not $stateNode) { return [pscustomobject]@{ Type='AccessToken'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="AccessToken state not found: $stateRefId" } }

    $privNode = $stateNode.ChildNodes | Where-Object { $_.LocalName -like '*privilege' }
    if ($privNode -is [System.Collections.IEnumerable] -and -not ($privNode -is [string])) { $privNode = $privNode | Select-Object -First 1 }
    if (-not $privNode) {
        return [pscustomobject]@{ Type='AccessToken'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="No privilege node found in state" }
    }
    $privilege = $privNode.LocalName

    # Map privilege to expected SIDs
    $privMap = @{
        'seremoteshutdownprivilege' = @('S-1-5-32-544') # Administrators
        'seauditprivilege' = @('S-1-5-19','S-1-5-20')   # Local Service, Network Service
        # Add more as needed
    }
    $right = $privilege
    $expectedSIDs = $privMap[$right]
    if (-not $expectedSIDs) { $expectedSIDs = @('S-1-5-32-544') }

    # Export user rights assignments
    $seceditFile = [System.IO.Path]::GetTempFileName()
    secedit.exe /export /cfg $seceditFile 2>$null | Out-Null
    $lines = Get-Content $seceditFile -ErrorAction SilentlyContinue
    Remove-Item $seceditFile -Force -ErrorAction SilentlyContinue

    $line = $lines | Where-Object { $_ -match "^$right\s*=" }
    $actual = if ($line) { ($line -split '=',2)[1].Trim() } else { '' }

    # Parse actual SIDs (may be in the form *S-1-5-32-544,*S-1-5-19, etc.)
    $actualSIDs = @()
    if ($actual) {
        $actualSIDs = $actual -split ',' | ForEach-Object { $_.Trim().TrimStart('*') }
    }

    # Compare: Pass if actual SIDs match expected SIDs (order-insensitive, exact match)
    $pass = @($actualSIDs | Sort-Object) -eq @($expectedSIDs | Sort-Object)

    return [pscustomobject]@{
        Type     = 'AccessToken'
        Privilege= $right
        Expected = ($expectedSIDs -join ', ')
        Actual   = ($actualSIDs -join ', ')
        Pass     = $pass
        Evidence = "Privilege $right assigned to: $($actualSIDs -join ', ') (expected $($expectedSIDs -join ', '))"
    }
}


# --- New: FileEffectiveRights53 test evaluator ------------------------------

function Evaluate-FileEffectiveRights53Test {
    param([System.Xml.XmlNode]$test)

    $refs = Get-TestRefs -test $test
    $objectRefId = $refs.objectRefId
    $stateRefId  = $refs.stateRefId

    $obj = $null
    if ($objectRefId -and $objects.ContainsKey($objectRefId)) { $obj = $objects[$objectRefId] }
    $stateNode = $null
    if ($stateRefId -and $states.ContainsKey($stateRefId)) { $stateNode = $states[$stateRefId] }

    if (-not $obj) { return [pscustomobject]@{ Type='FileEffectiveRights53'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="FileEffectiveRights53 object not found: $objectRefId" } }
    if (-not $stateNode) { return [pscustomobject]@{ Type='FileEffectiveRights53'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="FileEffectiveRights53 state not found: $stateRefId" } }

    $pathNode = Select-XmlNode -Xml $obj -XPath "./*[local-name()='filepath']"
    if ($pathNode -is [System.Collections.IEnumerable] -and -not ($pathNode -is [string])) { $pathNode = $pathNode | Select-Object -First 1 }
    $path = Get-InnerText $pathNode

    $trusteeNode = Select-XmlNode -Xml $obj -XPath "./*[local-name()='trustee_sid']"
    if ($trusteeNode -is [System.Collections.IEnumerable] -and -not ($trusteeNode -is [string])) { $trusteeNode = $trusteeNode | Select-Object -First 1 }
    $trustee = Get-InnerText $trusteeNode

    # Find which right is being checked (look for any child node ending with '_control' or '_privilege' or boolean right)
    $rightNode = $stateNode.ChildNodes | Where-Object { $_.LocalName -like '*control' -or $_.LocalName -like '*privilege' -or $_.InnerText -match '^(true|false|0|1)$' }
    if (-not $rightNode) {
        $rightNode = $stateNode.ChildNodes | Where-Object { $_.LocalName -like '*' }
    }
    if ($rightNode -is [System.Collections.IEnumerable] -and -not ($rightNode -is [string])) { $rightNode = $rightNode | Select-Object -First 1 }
    $rightName = $rightNode.LocalName
    $expected = Get-InnerText $rightNode
    $operation = Get-AttrValue -Node $rightNode -Name 'operation'
    if (-not $operation) { $operation = 'equals' }

    # Get effective rights for the trustee
    $actual = $null
    $hasRight = $false
    try {
        $acl = Get-Acl -Path $path -ErrorAction Stop
        $access = $acl.Access | Where-Object { $_.IdentityReference -like "*$trustee" }
        if ($access) {
            # Map rightName to FileSystemRights
            $rightMap = @{
                'standard_delete' = 'Delete'
                'standard_read_control' = 'ReadPermissions'
                'standard_write_dac' = 'ChangePermissions'
                'standard_write_owner' = 'TakeOwnership'
                'standard_synchronize' = 'Synchronize'
                'generic_read' = 'Read'
                'generic_write' = 'Write'
                'generic_execute' = 'ExecuteFile'
                'file_read_data' = 'ReadData'
                'file_write_data' = 'WriteData'
                'file_append_data' = 'AppendData'
                'file_read_ea' = 'ReadExtendedAttributes'
                'file_write_ea' = 'WriteExtendedAttributes'
                'file_execute' = 'ExecuteFile'
                'file_delete_child' = 'DeleteSubdirectoriesAndFiles'
                'file_read_attributes' = 'ReadAttributes'
                'file_write_attributes' = 'WriteAttributes'
                # Add more as needed
            }
            $fsRight = $rightMap[$rightName]
            if (-not $fsRight) { $fsRight = $rightName }
            $hasRight = $access | Where-Object { $_.FileSystemRights.ToString() -match $fsRight }
            $actual = if ($hasRight) { 'true' } else { 'false' }
        } else {
            $actual = 'false'
        }
    } catch { $actual = 'false' }

    $pass = Compare-Value -Actual $actual -Expected $expected -Operation $operation -Datatype 'boolean'
    return [pscustomobject]@{
        Type     = 'FileEffectiveRights53'
        Path     = $path
        Trustee  = $trustee
        Right    = $rightName
        Expected = $expected
        Actual   = $actual
        Pass     = $pass
        Evidence = "Trustee $trustee has right ${rightName}: $actual (expected $expected, op=$operation)"
    }
}

# Dispatcher: decide which evaluator to call

function Evaluate-Test {
    param([System.Xml.XmlNode]$test)

    if (-not $test) {
        return [pscustomobject]@{ Type = 'Unknown'; Pass = $false; Expected='N/A'; Actual='N/A'; Evidence = 'Test reference not found in OVAL tests.' }
    }

    $name = $test.LocalName.ToLowerInvariant()

    switch ($name) {
        {$_ -eq 'registry_test'} { return Evaluate-RegistryTest -test $test }
        {$_ -eq 'wmi57_test' -or $_ -like '*wmi*_test'} { return Evaluate-WMITest -test $test }
        {$_ -eq 'file_test'} { return Evaluate-FileTest -test $test }
        {$_ -eq 'service_test'} { return Evaluate-ServiceTest -test $test }
        {$_ -eq 'process_test'} { return Evaluate-ProcessTest -test $test }
        {$_ -eq 'qfe_test' -or $_ -eq 'hotfix_test'} { return Evaluate-QfeTest -test $test }

        # Audit event policy subcategories
        { $_ -eq 'auditeventpolicysubcategories_test' } { return Evaluate-AuditEventPolicySubcategoriesTest -test $test }
        { $_ -eq 'audit_event_policy_subcategories_test' } { return Evaluate-AuditEventPolicySubcategoriesTest -test $test }
        { $_ -like '*auditeventpolicy*subcategories_test' } { return Evaluate-AuditEventPolicySubcategoriesTest -test $test }

        # Account lockout policy
        { $_ -eq 'lockoutpolicy_test' } { return Evaluate-LockoutPolicyTest -test $test }
        { $_ -eq 'lockout_policy_test' } { return Evaluate-LockoutPolicyTest -test $test }
        { $_ -like '*lockoutpolicy*_test' } { return Evaluate-LockoutPolicyTest -test $test }
        
        # --- NEW: SID/SID, AccessToken, FileEffectiveRights53 ---
        { $_ -eq 'sid_sid_test' } { return Evaluate-SidSidTest -test $test }
        { $_ -eq 'accesstoken_test' } { return Evaluate-AccessTokenTest -test $test }
        { $_ -eq 'fileeffectiverights53_test' } { return Evaluate-FileEffectiveRights53Test -test $test }


        default {
            return [pscustomobject]@{
                Type     = 'Unknown'
                Pass     = $true
                Expected = 'N/A'
                Actual   = 'N/A'
                Evidence = "Unsupported test type: $name"
            }
        }
    }
}

# --- Criteria evaluation (recursive) ----------------------------------------

function Evaluate-Criteria {
    param(
        [System.Xml.XmlNode]$criteriaNode,
        [string]$DefinitionId
    )

    if ($null -eq $criteriaNode) {
        return [pscustomobject]@{
            Operator = 'AND'
            Pass     = $false
            Details  = @([pscustomobject]@{
                Type     = 'Criteria'
                RuleId   = $DefinitionId
                Pass     = $false
                Expected = 'N/A'
                Actual   = 'N/A'
                Evidence = 'No <criteria> node found for this definition.'
            })
        }
    }

    $operatorAttr = Get-AttrValue -Node $criteriaNode -Name 'operator'
    if (-not $operatorAttr) { $operatorAttr = 'AND' }
    $operator = $operatorAttr.ToUpperInvariant()
    $criteriaNegate = To-Bool (Get-AttrValue -Node $criteriaNode -Name 'negate')

    $criterionNodes        = Select-XmlNodes -Xml $criteriaNode -XPath "./*[local-name()='criterion']"
    $nestedCriteriaNodes   = Select-XmlNodes -Xml $criteriaNode -XPath "./*[local-name()='criteria']"
    $extendNodes           = Select-XmlNodes -Xml $criteriaNode -XPath "./*[local-name()='extend_definition']"

    $childDetails = @()
    $childPasses  = @()

    foreach ($c in $criterionNodes) {
        $testRef = Get-AttrValue -Node $c -Name 'test_ref'
        $comment = Get-AttrValue -Node $c -Name 'comment'
        $negate  = To-Bool (Get-AttrValue -Node $c -Name 'negate')

        $t = $null
        if ($testRef -and $tests.ContainsKey($testRef)) { $t = $tests[$testRef] }
        
        $res = Evaluate-Test -test $t
        $res = Add-ResultMeta -Result $res -DefinitionId $DefinitionId -Comment $comment
        if ($negate) {
            $res | Add-Member -NotePropertyName Evidence -NotePropertyValue ("NEGATED: " + $res.Evidence) -Force
            $res | Add-Member -NotePropertyName Pass -NotePropertyValue (-not $res.Pass) -Force
        }
        $childDetails += $res
        $childPasses  += $res.Pass
    }

    foreach ($nc in $nestedCriteriaNodes) {
        $sub = Evaluate-Criteria -criteriaNode $nc -DefinitionId $DefinitionId
        $subNegate = To-Bool (Get-AttrValue -Node $nc -Name 'negate')
        $subPass = $sub.Pass
        if ($subNegate) { $subPass = -not $subPass }
        $childPasses += $subPass

        if ($sub -and $sub.Details) { $childDetails += $sub.Details }
    }

    foreach ($ex in $extendNodes) {
        $refId  = Get-AttrValue -Node $ex -Name 'definition_ref'
        $negate = To-Bool (Get-AttrValue -Node $ex -Name 'negate')

        $refDef = $null
        if ($refId -and $definitions.ContainsKey($refId)) { $refDef = $definitions[$refId] }
        
        if ($refDef) {
            $subCrit = Select-XmlNode -Xml $refDef -XPath "./*[local-name()='criteria']"
            $subEval = Evaluate-Criteria -criteriaNode $subCrit -DefinitionId $refId
            $subPass = $subEval.Pass
            if ($negate) { $subPass = -not $subPass }
            $childPasses += $subPass

            if ($subEval -and $subEval.Details) { $childDetails += $subEval.Details }
        } else {
            $missing = [pscustomobject]@{ Type = 'DefinitionRef'; RuleId=$DefinitionId; Pass = $false; Expected='N/A'; Actual='N/A'; Evidence = "Referenced definition not found: $refId" }
            $childDetails += $missing
            $childPasses  += $false
        }
    }

    $overall = $false
    $childCount = ($childPasses | Measure-Object).Count
    if ($childCount -gt 0) {
        if ($operator -eq 'AND') {
            $overall = ($childPasses -notcontains $false)
        } elseif ($operator -eq 'OR') {
            $overall = ($childPasses -contains $true)
        } else {
            $overall = ($childPasses -notcontains $false)
        }
    }

    if ($criteriaNegate) { $overall = -not $overall }

    return [pscustomobject]@{
        Operator = $operator
        Pass     = $overall
        Details  = $childDetails
    }
}

#####################################################################################
# === OVAL Registry Test Summary (optional, for visibility) ===

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
        if ($objects.ContainsKey($objectRefId)) { $obj = $objects[$objectRefId] }

        if (-not $obj) {
            Write-Host "Test ID: $testId" -ForegroundColor Yellow
            Write-Host "  (object not found: $objectRefId)" -ForegroundColor Red
            Write-Host ""
            continue
        }

        $stateNode = $null
        if ($stateRefId -and $states.ContainsKey($stateRefId)) { $stateNode = $states[$stateRefId] }

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

# --- Main evaluation loop ----------------------------------------------------

$results = @()
$evalCount = 0
$definitionTotal = ($definitionNodes | Measure-Object).Count

foreach ($def in $definitionNodes) {
    $defIdAttr = $def.Attributes['id']
    $defId = if ($defIdAttr) { $defIdAttr.Value } else { $null }
    $evalCount++

    $title = Get-InnerText (Select-XmlNode -Xml $def -XPath "./*[local-name()='metadata']/*[local-name()='title']")
    $severity = Get-InnerText (Select-XmlNode -Xml $def -XPath "./*[local-name()='metadata']/*[local-name()='severity']")
    $criteria = Select-XmlNode -Xml $def -XPath "./*[local-name()='criteria']"

    Write-Verbose "Evaluating [$evalCount/$definitionTotal]: $defId"
    $eval = Evaluate-Criteria -criteriaNode $criteria -DefinitionId $defId
    $detailCount = if ($eval -and $eval.Details -and ($eval.Details -is [System.Collections.IEnumerable]) -and -not ($eval.Details -is [string])) { (@($eval.Details) | Measure-Object).Count } else { 0 }
    Write-Verbose "  Result: $($eval.Pass) (Operator: $($eval.Operator), Details: $detailCount)"

    $obj = [PSCustomObject]@{
        RuleId    = $defId
        RuleTitle = $title
        Severity  = $severity
        Pass      = $eval.Pass
    }

    if ($IncludePerTestDetails) {
        $evidenceData = if ($eval -and $eval.Details) { $eval.Details } else { @() }
        $obj | Add-Member -NotePropertyName Evidence -NotePropertyValue $evidenceData
    }

    $results += $obj
}

# --- Output ------------------------------------------------------------------

function Print-EvidenceRecursive {
    param(
        [object]$Evidence,
        [int]$Level = 1
    )
    if ($null -eq $Evidence) { return }
    if ($Evidence -is [System.Collections.IEnumerable] -and -not ($Evidence -is [string])) {
        foreach ($item in $Evidence) {
            Print-EvidenceRecursive -Evidence $item -Level $Level
        }
        return
    }
    $pass = $null
    try { $pass = $Evidence.Pass } catch {}
    if ($pass -eq $false -and $Evidence.Type -ne 'Criteria' -and $Evidence.Type -ne 'DefinitionRef') {
        $indent = ('  ' * $Level)
        $type = $Evidence.Type
        Write-Host "$indent Test Type: $type" -ForegroundColor White
        foreach ($prop in @('Path','Name','Namespace','WQL','HotfixId','Comment','Subcategory','Field','PolicyKey')) {
            if ($Evidence -is [psobject] -and $Evidence.PSObject.Properties[$prop]) {
                $val = $Evidence.$prop
                if ($val) { Write-Host ("$indent   ${prop}: $val") -ForegroundColor Gray }
            }
        }
        if ($Evidence -is [psobject] -and $Evidence.PSObject.Properties['Expected'] -and $Evidence.Expected -ne $null) {
            Write-Host "$indent   Expected: $($Evidence.Expected)" -ForegroundColor Cyan
        }
        if ($Evidence -is [psobject] -and $Evidence.PSObject.Properties['Actual'] -and $Evidence.Actual -ne $null) {
            Write-Host "$indent   Actual:   $($Evidence.Actual)" -ForegroundColor Magenta
        }
        if ($Evidence -is [psobject] -and $Evidence.PSObject.Properties['Evidence'] -and $Evidence.Evidence) {
            Write-Host "$indent   Details: $($Evidence.Evidence)" -ForegroundColor DarkGray
        }
        Write-Host ""
    }
    if ($Evidence -is [psobject] -and $Evidence.PSObject.Properties['Details'] -and $Evidence.Details) {
        Print-EvidenceRecursive -Evidence $Evidence.Details -Level ($Level + 1)
    }
}

# Summary counters
$passResults = @($results | Where-Object { $_.Pass })
$failResults = @($results | Where-Object { -not $_.Pass })
$passCount = ($passResults | Measure-Object).Count
$failCount = ($failResults | Measure-Object).Count
$totalCount = ($results | Measure-Object).Count

if ($OutputJson) {
    $results | ConvertTo-Json -Depth 6
} else {
    Write-Host "`n=== SCAP Compliance Summary ===" -ForegroundColor Cyan
    $results |
        Select-Object RuleId, 
            @{n='Status'; e={ if ($_.Pass) { 'PASS' } else { 'FAIL' } }},
            RuleTitle |
        Format-Table -AutoSize
     
    Write-Host "`n=== Detailed Failure Information ===" -ForegroundColor Yellow
    foreach ($result in $failResults) {
        Write-Host "`nRule: $($result.RuleId)" -ForegroundColor Red
        Write-Host "Title: $($result.RuleTitle)" -ForegroundColor Blue
        if ($result.Severity) {
            Write-Host "Severity: $($result.Severity)" -ForegroundColor Red
        }
        if ($result.Evidence) {
            Print-EvidenceRecursive -Evidence $result.Evidence
        } else {
            Write-Host "  No detailed evidence available" -ForegroundColor DarkGray
        }
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
}
