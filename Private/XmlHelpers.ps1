# === XML Helpers ===
# Auto-generated from original script on 2026-01-30 14:48:45

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

function Get-InnerText {
    param([System.Xml.XmlNode]$Node)
    if ($null -eq $Node) { return $null }
    if ($Node -is [System.Xml.XmlAttribute]) { return $Node.Value }
    return $Node.InnerText
}

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

function Get-FirstDefined {
    param([object[]]$Values)
    if ($null -eq $Values -or (@($Values) | Measure-Object).Count -eq 0) { return $null }
    foreach ($v in $Values) {
        if ($null -ne $v -and $v -ne '') { return $v }
    }
    return $null
}

function To-Bool {
    param($Value)
    if ($null -eq $Value) { return $null }
    $s = ([string]$Value).Trim().ToLowerInvariant()
    switch ($s) {
        'true'  { return $true }
        '1'     { return $true }
        'yes'   { return $true }
        'false' { return $false }
        '0'     { return $false }
        'no'    { return $false }
        default { 
            try { return [System.Convert]::ToBoolean($Value) } catch { return $null }
        }
    }
}

function As-Array { param($x) return @($x) }

function Get-SafeCount { param($x) return ((@($x) | Measure-Object).Count) }

function ToLowerSafe { param($x) if ($null -eq $x) { return $null } return ([string]$x).ToLowerInvariant() }


