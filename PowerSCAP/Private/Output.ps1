# === Output Helpers ===
# Auto-generated from original script on 2026-01-30 14:48:45

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
    try { $pass = [bool]$Evidence.Pass } catch {}
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


