# === Registry and WMI ===

function Get-RegistryItemProperty {
    param(
        [string]$Hive,
        [string]$Key,
        [string]$Name
    )
    
    # Check if running on Linux - registry operations not supported
    $isLinux = ($PSVersionTable.Platform -eq 'Unix' -or $PSVersionTable.OS -like '*Linux*' -or $IsLinux)
    if ($isLinux) {
        Write-Verbose "Registry operations not supported on Linux"
        return $null
    }

    # --- Remote path: use StdRegProv via CimSession ---
    if ($script:CimSession) {
        # StdRegProv hKey constants (DWORD)
        $hiveConst = @{
            'HKEY_LOCAL_MACHINE' = 2147483650   # 0x80000002
            'HKEY_CURRENT_USER'  = 2147483649   # 0x80000001
            'HKEY_USERS'         = 2147483652   # 0x80000004
            'HKEY_CLASSES_ROOT'  = 2147483648   # 0x80000000
        }

        $hKey = $null
        if ($hiveConst.ContainsKey($Hive)) { $hKey = $hiveConst[$Hive] }
        if ($null -eq $hKey) { return $null }

        try {
            $regProv = Get-CimInstance -ClassName StdRegProv -Namespace root\default -CimSession $script:CimSession -ErrorAction Stop

            # Try each typed getter in order; first successful non-null wins
            $getters = @(
                @{ Method = 'GetStringValue';      DataProp = 'sValue' },
                @{ Method = 'GetDWordValue';       DataProp = 'uValue' },
                @{ Method = 'GetBinaryValue';      DataProp = 'uValue' },
                @{ Method = 'GetMultiStringValue'; DataProp = 'sValue' },
                @{ Method = 'GetExpandStringValue';DataProp = 'sValue' }
            )
            foreach ($g in $getters) {
                try {
                    $result = Invoke-CimMethod -InputObject $regProv -MethodName $g.Method `
                        -Arguments @{ hKey = $hKey; sKeyName = $Key; sValueName = $Name } -ErrorAction Stop
                    if ($result -and $result.ReturnValue -eq 0) {
                        return $result.$($g.DataProp)
                    }
                } catch { continue }
            }
            return $null
        } catch {
            return $null
        }
    }

    # --- Local path: direct .NET registry access ---
    $mappedHive = $Hive -replace '^HKEY_LOCAL_MACHINE$', 'HKLM:' -replace '^HKEY_CURRENT_USER$', 'HKCU:' -replace '^HKEY_USERS$', 'HKU:' -replace '^HKEY_CLASSES_ROOT$', 'HKCR:'
    $regPath = "$mappedHive\$Key"

    $baseKey = $null
    $registryView = [Microsoft.Win32.RegistryView]::Default
    if ($script:Prefer64BitRegistry) { $registryView = [Microsoft.Win32.RegistryView]::Registry64 }

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
    
    # Check if running on Linux - WMI operations not supported
    $isLinux = ($PSVersionTable.Platform -eq 'Unix' -or $PSVersionTable.OS -like '*Linux*' -or $IsLinux)
    if ($isLinux) {
        Write-Verbose "WMI operations not supported on Linux"
        return @()
    }
    
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
