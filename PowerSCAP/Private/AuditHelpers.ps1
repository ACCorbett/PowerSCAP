# === Audit Helpers ===
# Auto-generated from original script on 2026-01-30 14:48:45

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
        if ((Get-SafeCount $outR) -gt 0) {
            $block = @()
            foreach ($line in $outR) {
                if ($line -match '(?i)^\s*Category/Subcategory\s*:') {
                    if ((Get-SafeCount $block) -gt 0) {
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
            if ((Get-SafeCount $block) -gt 0) {
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
        if ((Get-SafeCount $cache.Keys) -eq 0) {
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
        if ((Get-SafeCount $rawOutput) -eq 0) {
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

