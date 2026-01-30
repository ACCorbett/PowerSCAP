# === Local Accounts ===
# Auto-generated from original script on 2026-01-30 14:48:45

function Get-LocalGroupMembers {
    param([Parameter(Mandatory=$true)][string]$GroupName)

    # Prefer built-in cmdlet (PS 5.1+, Windows 10+/Server 2016+)
    if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
        try {
            $members = @(Get-LocalGroupMember -Group $GroupName -ErrorAction Stop)
            return $members | ForEach-Object {
                [pscustomobject]@{
                    Name            = $_.Name
                    SID             = $_.SID
                    PrincipalSource = $_.PrincipalSource
                }
            }
        } catch {
            # fall through to ADSI
        }
    }

    # Fallback: WinNT ADSI provider
    try {
        $ads = [ADSI]"WinNT://$env:COMPUTERNAME/$GroupName,group"
        $list = @()
        foreach ($m in $ads.psbase.Invoke('Members')) {
            $name    = $m.GetType().InvokeMember('Name', 'GetProperty', $null, $m, $null)
            $adsPath = $m.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $m, $null)
            # Best-effort SID resolution
            $sid = $null
            try {
                $nt = New-Object System.Security.Principal.NTAccount($name)
                $sid = $nt.Translate([System.Security.Principal.SecurityIdentifier]).Value
            } catch { }
            $list += [pscustomobject]@{
                Name = $name
                SID  = $sid
                ADsPath = $adsPath
            }
        }
        return $list
    } catch {
        return @()
    }
}

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


