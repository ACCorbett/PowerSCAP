# === OVAL Core ===
# Auto-generated from original script on 2026-01-30 14:48:45

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
    if ($lits -and (Get-SafeCount $lits) -gt 0) {
        return @($lits | ForEach-Object { Get-InnerText $_ } | Where-Object { $_ -ne $null -and $_ -ne '' })
    }

    $txt = Get-InnerText $v
    if ($txt) { return @($txt) }
    return $null
}

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
        [object]$Actual,
        [object]$Expected,
        [Parameter(Mandatory=$true)][string]$Operation,
        [string]$Datatype = 'string',
        [bool]$CaseSensitive = $false
    )

    # Helper: normalize lists
    function Normalize-List([object]$v, [bool]$caseSensitive) {
        $arr = @( As-Array ($v -split ',') | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -ne '' } )
        if (-not $caseSensitive) { $arr = @($arr | ForEach-Object { $_.ToLowerInvariant() }) }
        return $arr
    }

    # Helper: set equals (order-insensitive, exact match)
    function Compare-Lists([object]$a, [object]$b, [bool]$caseSensitive) {
        $aList = Normalize-List $a $caseSensitive
        $bList = Normalize-List $b $caseSensitive
        if ((Get-SafeCount $aList) -ne (Get-SafeCount $bList)) { return $false }
        $diffA = @($aList | Where-Object { $_ -notin $bList })
        $diffB = @($bList | Where-Object { $_ -notin $aList })
        return ((Get-SafeCount $diffA) -eq 0 -and (Get-SafeCount $diffB) -eq 0)
    }

    # Normalize boolean
    if ($Datatype -eq 'boolean') {
        $Actual   = To-Bool $Actual
        $Expected = To-Bool $Expected
    }

    # Normalize numeric (null-safe)
    if ($Datatype -in @('int','integer','float','double')) {
        try { $Actual   = [double]$Actual }   catch { $Actual   = $null }
        try { $Expected = [double]$Expected } catch { $Expected = $null }
    }

    switch ($Operation.ToLowerInvariant()) {
        # String operations (null-safe, optional case sensitivity)
        'equals' {
            if ($null -eq $Actual -and $null -eq $Expected) { return $true }
            if ($null -eq $Actual -or  $null -eq $Expected) { return $false }
            $a = [string]$Actual; $e = [string]$Expected
            if ($CaseSensitive) { return $a -eq $e }
            else { return $a.ToLowerInvariant() -eq $e.ToLowerInvariant() }
        }
        'not equal' {
            if ($null -eq $Actual -and $null -eq $Expected) { return $false }
            if ($null -eq $Actual -or  $null -eq $Expected) { return $true }
            $a = [string]$Actual; $e = [string]$Expected
            if ($CaseSensitive) { return $a -ne $e }
            else { return $a.ToLowerInvariant() -ne $e.ToLowerInvariant() }
        }
        'case insensitive equals'        { return ([string]$Actual).ToLowerInvariant() -eq ([string]$Expected).ToLowerInvariant() }
        'case insensitive not equal'     { return ([string]$Actual).ToLowerInvariant() -ne ([string]$Expected).ToLowerInvariant() }
        'pattern match'                  { if ($CaseSensitive) { return $Actual -match $Expected } else { return $Actual -imatch $Expected } }
        'case insensitive pattern match' { return $Actual -imatch $Expected }

        # Numeric
        'greater than'            { return $Actual -gt $Expected }
        'greater than or equal'   { return $Actual -ge $Expected }
        'less than'               { return $Actual -lt $Expected }
        'less than or equal'      { return $Actual -le $Expected }

        # List/set (StrictMode-safe)
        'set equals' { return Compare-Lists $Actual $Expected $CaseSensitive }
        'subset of' {
            $aList = Normalize-List $Actual $CaseSensitive
            $bList = Normalize-List $Expected $CaseSensitive
            $diff = @($aList | Where-Object { $_ -notin $bList })
            return ((Get-SafeCount $diff) -eq 0)
        }
        'superset of' {
            $aList = Normalize-List $Actual $CaseSensitive
            $bList = Normalize-List $Expected $CaseSensitive
            $diff = @($bList | Where-Object { $_ -notin $aList })
            return ((Get-SafeCount $diff) -eq 0)
        }

        # Boolean (already normalized)
        'boolean equals'    { return $Actual -eq $Expected }
        'boolean not equal' { return $Actual -ne $Expected }

        # Default fallback
        default {
            if ($null -eq $Actual -and $null -eq $Expected) { return $true }
            if ($null -eq $Actual -or  $null -eq $Expected) { return $false }
            $a = [string]$Actual; $e = [string]$Expected
            if ($CaseSensitive) { return $a -eq $e }
            else { return $a.ToLowerInvariant() -eq $e.ToLowerInvariant() }
        }
    }
}

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


