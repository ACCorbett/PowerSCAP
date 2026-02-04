# === Linux Helpers ===
# Platform detection and Linux-specific operations

function Test-IsLinux {
    <#
    .SYNOPSIS
        Detects if the current or remote system is Linux
    #>
    param(
        [string]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential
    )
    
    if ($ComputerName -and $ComputerName.Trim().Length -gt 0) {
        # Remote system - test via PowerShell remoting
        try {
            $scriptBlock = {
                $PSVersionTable.Platform -eq 'Unix' -or $PSVersionTable.OS -like '*Linux*' -or $IsLinux
            }
            
            $params = @{
                ComputerName = $ComputerName
                ScriptBlock = $scriptBlock
                ErrorAction = 'Stop'
            }
            if ($Credential) {
                $params['Credential'] = $Credential
            }
            
            return Invoke-Command @params
        } catch {
            Write-Verbose "Failed to detect Linux on remote system $ComputerName : $($_.Exception.Message)"
            return $false
        }
    } else {
        # Local system
        return ($PSVersionTable.Platform -eq 'Unix' -or $PSVersionTable.OS -like '*Linux*' -or $IsLinux)
    }
}

function Get-LinuxOSInfo {
    <#
    .SYNOPSIS
        Gets Linux OS information (distribution, version, etc.)
    #>
    param(
        [string]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential
    )
    
    $scriptBlock = {
        $osInfo = @{
            IsLinux = $true
            Distribution = 'Unknown'
            Version = 'Unknown'
            Kernel = 'Unknown'
            Architecture = 'Unknown'
        }
        
        # Get kernel version
        if (Test-Path '/proc/version') {
            $osInfo.Kernel = (Get-Content '/proc/version' -Raw).Trim()
        } elseif (Get-Command uname -ErrorAction SilentlyContinue) {
            $osInfo.Kernel = (uname -r 2>$null)
        }
        
        # Get distribution info from /etc/os-release (standard on modern Linux)
        if (Test-Path '/etc/os-release') {
            $releaseContent = Get-Content '/etc/os-release' -Raw
            if ($releaseContent -match 'ID="?([^"\n]+)"?') {
                $osInfo.Distribution = $matches[1]
            }
            if ($releaseContent -match 'VERSION_ID="?([^"\n]+)"?') {
                $osInfo.Version = $matches[1]
            }
        }
        # Fallback to other methods
        elseif (Test-Path '/etc/redhat-release') {
            $osInfo.Distribution = (Get-Content '/etc/redhat-release').Trim()
        } elseif (Test-Path '/etc/debian_version') {
            $osInfo.Distribution = "Debian"
            $osInfo.Version = (Get-Content '/etc/debian_version').Trim()
        }
        
        # Get architecture
        if (Get-Command uname -ErrorAction SilentlyContinue) {
            $osInfo.Architecture = (uname -m 2>$null)
        }
        
        return $osInfo
    }
    
    if ($ComputerName -and $ComputerName.Trim().Length -gt 0) {
        try {
            $params = @{
                ComputerName = $ComputerName
                ScriptBlock = $scriptBlock
                ErrorAction = 'Stop'
            }
            if ($Credential) {
                $params['Credential'] = $Credential
            }
            
            return Invoke-Command @params
        } catch {
            Write-Verbose "Failed to get Linux OS info from $ComputerName : $($_.Exception.Message)"
            return $null
        }
    } else {
        return & $scriptBlock
    }
}

function Get-LinuxFileContent {
    <#
    .SYNOPSIS
        Reads a file on Linux system (local or remote)
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        
        [string]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential,
        [switch]$AsString
    )
    
    $scriptBlock = {
        param($FilePath, $ReadAsString)
        
        if (-not (Test-Path $FilePath)) {
            return $null
        }
        
        if ($ReadAsString) {
            return (Get-Content $FilePath -Raw)
        } else {
            return (Get-Content $FilePath)
        }
    }
    
    if ($ComputerName -and $ComputerName.Trim().Length -gt 0) {
        try {
            $params = @{
                ComputerName = $ComputerName
                ScriptBlock = $scriptBlock
                ArgumentList = $Path, $AsString.IsPresent
                ErrorAction = 'Stop'
            }
            if ($Credential) {
                $params['Credential'] = $Credential
            }
            
            return Invoke-Command @params
        } catch {
            Write-Verbose "Failed to read file $Path from $ComputerName : $($_.Exception.Message)"
            return $null
        }
    } else {
        if (-not (Test-Path $Path)) {
            return $null
        }
        
        if ($AsString) {
            return (Get-Content $Path -Raw)
        } else {
            return (Get-Content $Path)
        }
    }
}

function Invoke-LinuxCommand {
    <#
    .SYNOPSIS
        Executes a command on Linux system (local or remote)
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Command,
        
        [string]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential
    )
    
    $scriptBlock = {
        param($Cmd)
        
        try {
            $output = Invoke-Expression $Cmd 2>&1
            return @{
                Success = $true
                Output = $output
                ExitCode = $LASTEXITCODE
            }
        } catch {
            return @{
                Success = $false
                Output = $_.Exception.Message
                ExitCode = -1
            }
        }
    }
    
    if ($ComputerName -and $ComputerName.Trim().Length -gt 0) {
        try {
            $params = @{
                ComputerName = $ComputerName
                ScriptBlock = $scriptBlock
                ArgumentList = $Command
                ErrorAction = 'Stop'
            }
            if ($Credential) {
                $params['Credential'] = $Credential
            }
            
            return Invoke-Command @params
        } catch {
            Write-Verbose "Failed to execute command on $ComputerName : $($_.Exception.Message)"
            return @{
                Success = $false
                Output = $_.Exception.Message
                ExitCode = -1
            }
        }
    } else {
        try {
            $output = Invoke-Expression $Command 2>&1
            return @{
                Success = $true
                Output = $output
                ExitCode = $LASTEXITCODE
            }
        } catch {
            return @{
                Success = $false
                Output = $_.Exception.Message
                ExitCode = -1
            }
        }
    }
}

function Get-LinuxPackageInfo {
    <#
    .SYNOPSIS
        Gets installed package information on Linux
    #>
    param(
        [string]$PackageName,
        [string]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential
    )
    
    $scriptBlock = {
        param($PkgName)
        
        $packages = @()
        
        # Try different package managers
        # dpkg (Debian/Ubuntu)
        if (Get-Command dpkg -ErrorAction SilentlyContinue) {
            if ($PkgName) {
                $output = dpkg -l $PkgName 2>$null
            } else {
                $output = dpkg -l 2>$null
            }
            
            if ($output) {
                $lines = $output -split "`n" | Where-Object { $_ -match '^ii\s+' }
                foreach ($line in $lines) {
                    if ($line -match '^ii\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$') {
                        $packages += @{
                            Name = $matches[1]
                            Version = $matches[2]
                            Architecture = $matches[3]
                            Description = $matches[4]
                            PackageManager = 'dpkg'
                        }
                    }
                }
            }
        }
        # rpm (RHEL/CentOS/Fedora)
        elseif (Get-Command rpm -ErrorAction SilentlyContinue) {
            if ($PkgName) {
                $output = rpm -qa $PkgName 2>$null
            } else {
                $output = rpm -qa 2>$null
            }
            
            if ($output) {
                foreach ($pkg in $output) {
                    if ($pkg -match '(.+)-([^-]+)-([^-]+)\.(.+)') {
                        $packages += @{
                            Name = $matches[1]
                            Version = "$($matches[2])-$($matches[3])"
                            Architecture = $matches[4]
                            Description = ''
                            PackageManager = 'rpm'
                        }
                    }
                }
            }
        }
        
        return $packages
    }
    
    if ($ComputerName -and $ComputerName.Trim().Length -gt 0) {
        try {
            $params = @{
                ComputerName = $ComputerName
                ScriptBlock = $scriptBlock
                ArgumentList = $PackageName
                ErrorAction = 'Stop'
            }
            if ($Credential) {
                $params['Credential'] = $Credential
            }
            
            return Invoke-Command @params
        } catch {
            Write-Verbose "Failed to get package info from $ComputerName : $($_.Exception.Message)"
            return @()
        }
    } else {
        return & $scriptBlock -PkgName $PackageName
    }
}

function Test-LinuxServiceStatus {
    <#
    .SYNOPSIS
        Checks if a service is running on Linux
    #>
    param(
        [Parameter(Mandatory)]
        [string]$ServiceName,
        
        [string]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential
    )
    
    $scriptBlock = {
        param($SvcName)
        
        # Try systemctl (systemd)
        if (Get-Command systemctl -ErrorAction SilentlyContinue) {
            $status = systemctl is-active $SvcName 2>$null
            $enabled = systemctl is-enabled $SvcName 2>$null
            
            return @{
                Name = $SvcName
                Status = $status
                Enabled = $enabled
                Running = ($status -eq 'active')
            }
        }
        # Try service command
        elseif (Get-Command service -ErrorAction SilentlyContinue) {
            $status = service $SvcName status 2>&1
            $running = $status -match 'running|active'
            
            return @{
                Name = $SvcName
                Status = if ($running) { 'running' } else { 'stopped' }
                Enabled = 'unknown'
                Running = $running
            }
        }
        
        return @{
            Name = $SvcName
            Status = 'unknown'
            Enabled = 'unknown'
            Running = $false
        }
    }
    
    if ($ComputerName -and $ComputerName.Trim().Length -gt 0) {
        try {
            $params = @{
                ComputerName = $ComputerName
                ScriptBlock = $scriptBlock
                ArgumentList = $ServiceName
                ErrorAction = 'Stop'
            }
            if ($Credential) {
                $params['Credential'] = $Credential
            }
            
            return Invoke-Command @params
        } catch {
            Write-Verbose "Failed to check service $ServiceName on $ComputerName : $($_.Exception.Message)"
            return @{
                Name = $ServiceName
                Status = 'error'
                Enabled = 'unknown'
                Running = $false
            }
        }
    } else {
        return & $scriptBlock -SvcName $ServiceName
    }
}

function Get-LinuxUserInfo {
    <#
    .SYNOPSIS
        Gets user account information on Linux
    #>
    param(
        [string]$UserName,
        [string]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential
    )
    
    $scriptBlock = {
        param($User)
        
        $users = @()
        
        if (Test-Path '/etc/passwd') {
            $passwdContent = Get-Content '/etc/passwd'
            
            foreach ($line in $passwdContent) {
                if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) {
                    continue
                }
                
                $parts = $line -split ':'
                if ((Get-SafeCount $parts) -ge 7) {
                    $userName = $parts[0]
                    
                    if ($User -and $userName -ne $User) {
                        continue
                    }
                    
                    $users += @{
                        UserName = $userName
                        UID = $parts[2]
                        GID = $parts[3]
                        HomeDirectory = $parts[5]
                        Shell = $parts[6]
                    }
                }
            }
        }
        
        return $users
    }
    
    if ($ComputerName -and $ComputerName.Trim().Length -gt 0) {
        try {
            $params = @{
                ComputerName = $ComputerName
                ScriptBlock = $scriptBlock
                ArgumentList = $UserName
                ErrorAction = 'Stop'
            }
            if ($Credential) {
                $params['Credential'] = $Credential
            }
            
            return Invoke-Command @params
        } catch {
            Write-Verbose "Failed to get user info from $ComputerName : $($_.Exception.Message)"
            return @()
        }
    } else {
        return & $scriptBlock -User $UserName
    }
}
