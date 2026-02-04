# Remote PowerSCAP Installation Management Functions

function Test-RemotePowerSCAPInstalled {
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        
        [System.Management.Automation.PSCredential]$Credential
    )
    
    $scriptBlock = {
        $module = Get-Module -ListAvailable -Name PowerSCAP | Select-Object -First 1
        if ($module) {
            return @{
                Installed = $true
                Version = $module.Version.ToString()
                Path = $module.ModuleBase
            }
        }
        return @{ Installed = $false }
    }
    
    try {
        $params = @{
            ComputerName = $ComputerName
            ScriptBlock = $scriptBlock
            ErrorAction = 'Stop'
        }
        if ($Credential) {
            $params['Credential'] = $Credential
        }
        
        $result = Invoke-Command @params
        return $result
    } catch {
        Write-Verbose "Failed to check PowerSCAP installation on $ComputerName : $($_.Exception.Message)"
        return @{ Installed = $false; Error = $_.Exception.Message }
    }
}

function Install-RemotePowerSCAP {
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        
        [System.Management.Automation.PSCredential]$Credential,
        
        [Parameter(Mandatory)]
        [string]$SourceModulePath,
        
        [ValidateSet('System', 'User')]
        [string]$Scope = 'System',
        
        [switch]$Force
    )
    
    Write-Verbose "Installing PowerSCAP on $ComputerName (Scope: $Scope)"
    
    $scriptBlock = {
        param($ModuleContent, $Scope, $Force)
        
        # Detect if Linux or Windows
        $isLinux = ($PSVersionTable.Platform -eq 'Unix' -or $PSVersionTable.OS -like '*Linux*' -or $IsLinux)
        
        # Determine target path based on OS
        if ($isLinux) {
            if ($Scope -eq 'System') {
                $targetBase = "/usr/local/share/powershell/Modules"
            } else {
                $homeDir = $env:HOME
                $targetBase = "$homeDir/.local/share/powershell/Modules"
            }
        } else {
            if ($Scope -eq 'System') {
                $targetBase = "$env:ProgramFiles\WindowsPowerShell\Modules"
            } else {
                $targetBase = "$env:USERPROFILE\Documents\WindowsPowerShell\Modules"
            }
        }
        
        $targetPath = Join-Path $targetBase "PowerSCAP"
        
        # Remove existing if Force
        if ($Force -and (Test-Path $targetPath)) {
            Remove-Item -Path $targetPath -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        # Create module directory
        if (-not (Test-Path $targetPath)) {
            New-Item -Path $targetPath -ItemType Directory -Force | Out-Null
        }
        
        # Extract and write files
        foreach ($file in $ModuleContent.GetEnumerator()) {
            $filePath = Join-Path $targetPath $file.Key
            $fileDir = Split-Path $filePath -Parent
            
            if (-not (Test-Path $fileDir)) {
                New-Item -Path $fileDir -ItemType Directory -Force | Out-Null
            }
            
            # Decode and write file
            $bytes = [System.Convert]::FromBase64String($file.Value)
            [System.IO.File]::WriteAllBytes($filePath, $bytes)
        }
        
        return @{
            Success = $true
            Path = $targetPath
            FileCount = $ModuleContent.Count
        }
    }
    
    try {
        # Gather all module files and encode them
        Write-Verbose "Collecting module files from $SourceModulePath"
        $moduleFiles = Get-ChildItem -Path $SourceModulePath -Recurse -File
        $moduleContent = @{}
        
        foreach ($file in $moduleFiles) {
            $relativePath = $file.FullName.Substring($SourceModulePath.Length + 1)
            $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
            $moduleContent[$relativePath] = [System.Convert]::ToBase64String($bytes)
        }
        
        Write-Verbose "Collected $($moduleContent.Count) files, total size: $([math]::Round(($moduleFiles | Measure-Object -Property Length -Sum).Sum / 1MB, 2)) MB"
        
        # Copy to remote system
        $params = @{
            ComputerName = $ComputerName
            ScriptBlock = $scriptBlock
            ArgumentList = $moduleContent, $Scope, $Force
            ErrorAction = 'Stop'
        }
        if ($Credential) {
            $params['Credential'] = $Credential
        }
        
        $result = Invoke-Command @params
        
        if ($result.Success) {
            Write-Verbose "PowerSCAP installed successfully on $ComputerName at $($result.Path)"
        }
        
        return $result
    } catch {
        Write-Warning "Failed to install PowerSCAP on $ComputerName : $($_.Exception.Message)"
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Remove-RemotePowerSCAP {
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        
        [System.Management.Automation.PSCredential]$Credential,
        
        [ValidateSet('System', 'User')]
        [string]$Scope = 'User'
    )
    
    Write-Verbose "Removing PowerSCAP from $ComputerName (Scope: $Scope)"
    
    $scriptBlock = {
        param($Scope)
        
        # Detect if Linux or Windows
        $isLinux = ($PSVersionTable.Platform -eq 'Unix' -or $PSVersionTable.OS -like '*Linux*' -or $IsLinux)
        
        # Determine target path based on OS
        if ($isLinux) {
            if ($Scope -eq 'System') {
                $targetPath = "/usr/local/share/powershell/Modules/PowerSCAP"
            } else {
                $homeDir = $env:HOME
                $targetPath = "$homeDir/.local/share/powershell/Modules/PowerSCAP"
            }
        } else {
            if ($Scope -eq 'System') {
                $targetPath = "$env:ProgramFiles\WindowsPowerShell\Modules\PowerSCAP"
            } else {
                $targetPath = "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\PowerSCAP"
            }
        }
        
        if (Test-Path $targetPath) {
            # Unload module if loaded
            Remove-Module -Name PowerSCAP -Force -ErrorAction SilentlyContinue
            
            # Remove files
            Remove-Item -Path $targetPath -Recurse -Force -ErrorAction Stop
            
            return @{ Success = $true; Removed = $targetPath }
        } else {
            return @{ Success = $true; Removed = $null; Message = "PowerSCAP not found at $targetPath" }
        }
    }
    
    try {
        $params = @{
            ComputerName = $ComputerName
            ScriptBlock = $scriptBlock
            ArgumentList = $Scope
            ErrorAction = 'Stop'
        }
        if ($Credential) {
            $params['Credential'] = $Credential
        }
        
        $result = Invoke-Command @params
        
        if ($result.Success) {
            if ($result.Removed) {
                Write-Verbose "PowerSCAP removed from $ComputerName at $($result.Removed)"
            } else {
                Write-Verbose $result.Message
            }
        }
        
        return $result
    } catch {
        Write-Warning "Failed to remove PowerSCAP from $ComputerName : $($_.Exception.Message)"
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Invoke-RemotePowerSCAPScan {
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        
        [System.Management.Automation.PSCredential]$Credential,
        
        [Parameter(Mandatory)]
        [hashtable]$ScanParameters
    )
    
    Write-Verbose "Invoking PowerSCAP scan on $ComputerName"
    
    $scriptBlock = {
        param($Params)
        
        # Import PowerSCAP
        Import-Module PowerSCAP -ErrorAction Stop
        
        # Build parameter splat
        $scanParams = @{}
        foreach ($key in $Params.Keys) {
            $scanParams[$key] = $Params[$key]
        }
        
        # Always output JSON for remote scans
        $scanParams['OutputJson'] = $true
        
        # Execute scan
        $jsonResults = Scan-Computer @scanParams
        
        return $jsonResults
    }
    
    try {
        $params = @{
            ComputerName = $ComputerName
            ScriptBlock = $scriptBlock
            ArgumentList = $ScanParameters
            ErrorAction = 'Stop'
        }
        if ($Credential) {
            $params['Credential'] = $Credential
        }
        
        $jsonResults = Invoke-Command @params
        
        # Parse JSON results
        if ($jsonResults) {
            $results = $jsonResults | ConvertFrom-Json
            return $results
        }
        
        return $null
    } catch {
        Write-Error "Failed to execute scan on $ComputerName : $($_.Exception.Message)"
        throw
    }
}
