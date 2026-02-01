# === Output Helpers ===
# Fixed version with proper AccessToken test result display

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
        
        # For AccessToken tests, show Privilege and Principal first
        if ($type -eq 'AccessToken') {
            if ($Evidence -is [psobject] -and $Evidence.PSObject.Properties['Privilege'] -and $Evidence.Privilege) {
                Write-Host "$indent   Privilege: $($Evidence.Privilege)" -ForegroundColor Gray
            }
            if ($Evidence -is [psobject] -and $Evidence.PSObject.Properties['Principal'] -and $Evidence.Principal) {
                $principalText = $Evidence.Principal
                
                # Detect and prettify common regex patterns
                if ($principalText -match '[\^$.*+?{}\[\]\\|()]') {
                    # Extract the meaningful part from common OVAL regex patterns
                    $cleaned = $principalText
                    
                    # Pattern: ^(?i)(.+\\)?GroupName$ -> "GroupName (any domain)"
                    if ($cleaned -match '^\^?\(\?i\)\(\.?\+\\\\\)\?(.+?)\$?$') {
                        $groupName = $matches[1]
                        $principalText = "$groupName (any domain) [pattern match]"
                    }
                    # Pattern: ^GroupName$ -> "GroupName (exact match)"
                    elseif ($cleaned -match '^\^(.+?)\$$') {
                        $groupName = $matches[1]
                        $principalText = "$groupName (exact) [pattern match]"
                    }
                    # Any other regex -> show as pattern
                    else {
                        $principalText = "Pattern: $principalText"
                    }
                }
                
                Write-Host "$indent   Principal: $principalText" -ForegroundColor Gray
            }
        }
        
        # Show standard properties for all test types
        foreach ($prop in @('Path','Name','Namespace','WQL','HotfixId','Comment','Subcategory','Field','PolicyKey')) {
            if ($Evidence -is [psobject] -and $Evidence.PSObject.Properties[$prop]) {
                $val = $Evidence.$prop
                if ($val) { Write-Host ("$indent   ${prop}: $val") -ForegroundColor Gray }
            }
        }
        
        # For AccessToken, Expected shows 0 or 1, but we want to clarify what that means
        if ($Evidence -is [psobject] -and $Evidence.PSObject.Properties['Expected'] -and $Evidence.Expected -ne $null) {
            if ($type -eq 'AccessToken') {
                $expectedMeaning = if ($Evidence.Expected -eq '1') { "should have privilege" } else { "should NOT have privilege" }
                Write-Host "$indent   Expected: $($Evidence.Expected) ($expectedMeaning)" -ForegroundColor Cyan
            } else {
                Write-Host "$indent   Expected: $($Evidence.Expected)" -ForegroundColor Cyan
            }
        }
        
        # For AccessToken, Actual contains the list of users/groups with SIDs
        if ($Evidence -is [psobject] -and $Evidence.PSObject.Properties['Actual'] -and $Evidence.Actual -ne $null) {
            if ($type -eq 'AccessToken') {
                $actualValue = $Evidence.Actual
                if ([string]::IsNullOrWhiteSpace($actualValue)) {
                    Write-Host "$indent   Actual:   (No users/groups assigned)" -ForegroundColor Magenta
                } else {
                    Write-Host "$indent   Actual:   Users/Groups with this privilege:" -ForegroundColor Magenta
                    # Split the comma-separated SIDs/names and display each on its own line
                    $entries = $actualValue -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                    foreach ($entry in $entries) {
                        Write-Host "$indent              $entry" -ForegroundColor Yellow
                    }
                }
            } else {
                Write-Host "$indent   Actual:   $($Evidence.Actual)" -ForegroundColor Magenta
            }
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
