# === Registry and WMI ===
# Auto-generated from original script on 2026-01-30 14:48:45

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
    if ($script:CimSession) {
        $res = Get-CimInstance -Namespace $Namespace -Query $Query -CimSession $script:CimSession -ErrorAction Stop
    } else {
        $res = Get-CimInstance -Namespace $Namespace -Query $Query -ErrorAction Stop
    }
} else {
            $res = Get-WmiObject -Namespace $Namespace -Query $Query -ErrorAction Stop
        }
        if ($null -eq $res) { return @() }
        $arr = @($res)
        if ((Get-SafeCount $arr) -gt $MaxRows) { return $arr[0..($MaxRows-1)] }
        return $arr
    } catch {
        return @()
    }
}


