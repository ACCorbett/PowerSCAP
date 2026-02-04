function Scan-Computer {
<#
.SYNOPSIS
  Scans a Windows or Linux system for security compliance, vulnerabilities, patches, or inventory using OVAL/SCAP definitions.

.DESCRIPTION
  PowerSCAP v2.6.0 - Cross-platform security scanning with automatic role detection, platform filtering,
  and intelligent remote scanning capabilities. Supports SCAP/STIG compliance scanning and OVAL vulnerability scanning
  on both Windows and Linux systems. Requires PowerShell 7.0+ for Linux support.

.PARAMETER Computer
  Remote computer to scan. If not specified, scans the local system. Supports both Windows and Linux targets.

.PARAMETER ScanType
  Type of scan to perform:
  - Vulnerability: Security vulnerabilities (CVE-based)
  - Compliance: SCAP/STIG compliance checking  
  - Patch: Patch compliance verification
  - Inventory: System inventory and configuration
  If not specified, inferred from ScanSource content.

.PARAMETER ScanSourceType
  How to obtain scan definitions (REQUIRED):
  - File: Single OVAL/SCAP file
  - Directory: Directory containing OVAL/SCAP files
  - Download: Download from vulnerability feed

.PARAMETER ScanSource
  Source for scan definitions (REQUIRED, format depends on ScanSourceType):
  - For File: Path to OVAL/SCAP file (e.g., "C:\SCAP\stig.xml")
  - For Directory: Path to directory (e.g., "C:\OVAL")
  - For Download: Feed name (NVD, MSRC, OVAL, All)

.PARAMETER Output
  Output format:
  - Console: Formatted console output with color coding (default)
  - JSON: JSON format
  - CSV: Comma-separated values
  - TSV: Tab-separated values
  - Legacy: Original PowerSCAP console output

.PARAMETER VulnerabilityDaysBack
  When downloading from NVD or MSRC, how many days back to retrieve (default: 90).

.PARAMETER MaxVulnerabilities
  Maximum number of vulnerabilities to download (default: 100, max: 2000 for NVD).

.PARAMETER NVDApiKey
  API key for NVD downloads (increases rate limit from 5 to 50 requests per 30 seconds).
  Get free key: https://nvd.nist.gov/developers/request-an-api-key

.PARAMETER DownloadDirectory
  Directory to save downloaded vulnerability definitions (default: temp directory with date).

.PARAMETER UseCim
  Use CIM for WMI queries (default: $true). Set $false to use Get-WmiObject.

.PARAMETER IncludePerTestDetails
  Include per-test detailed evidence in results (default: $true).

.PARAMETER MaxWmiRows
  Limit WMI rows scanned per query (default: 1000).

.PARAMETER Prefer64BitRegistry
  Prefer 64-bit registry view (default: $true).

.PARAMETER Credential
  Optional credential used for remote CIM session creation and PowerShell remoting.

.PARAMETER InstallPowerSCAP
  Controls PowerSCAP installation for remote scanning:
  - No (default): Uses CIM/WMI (no installation)
  - Yes: Installs if needed, then runs locally (5-10x faster)
  - Upgrade: Always installs/upgrades, then runs locally
  - WhileScanning: Temporarily installs, scans, then removes

.PARAMETER SkipPlatformFilter
  Skip platform/OS filtering for vulnerability scans. By default, vulnerability definitions are filtered to only
  evaluate those applicable to the current OS (e.g., only Windows vulnerabilities on Windows systems).

.PARAMETER SkipRoleFilter
  Skip role-based filtering for SCAP/STIG compliance scans. By default, compliance checks are filtered based on
  system role (Domain Controller, Member Server, Standalone Server, Workstation).

.PARAMETER ForceRole
  Override automatic role detection. Valid values: DomainController, MemberServer, StandaloneServer,
  DomainWorkstation, StandaloneWorkstation.

.EXAMPLE
  Scan-Computer -ScanSourceType File -ScanSource "U_MS_Windows_11_V2R7_STIG.xml"
  
  Scans local system for compliance using Windows 11 STIG file.

.EXAMPLE
  Scan-Computer -Computer SERVER01 -ScanSourceType File -ScanSource "stig.xml" -InstallPowerSCAP Yes
  
  Scans remote server, installing PowerSCAP for faster execution.

.EXAMPLE
  Scan-Computer -ScanSourceType Download -ScanSource NVD -VulnerabilityDaysBack 30 -Output JSON
  
  Downloads NVD vulnerabilities from last 30 days, outputs as JSON.

.EXAMPLE
  Scan-Computer -ScanSourceType Directory -ScanSource "C:\OVAL" -Output CSV
  
  Scans all OVAL files in directory, outputs as CSV.

.EXAMPLE
  Scan-Computer -Computer WEB01 -ScanSourceType Download -ScanSource OVAL -InstallPowerSCAP WhileScanning
  
  Downloads OVAL definitions, scans remote server with temporary PowerSCAP installation.

.NOTES
  PowerSCAP v2.6.0 - Cross-platform parameter interface with full Linux support
#>
    [CmdletBinding()]
    param(
        # Target System
        [Parameter()]
        [Alias('ComputerName')]
        [string]$Computer,

        # Scan Configuration
        [Parameter()]
        [ValidateSet('Vulnerability', 'Compliance', 'Patch', 'Inventory')]
        [string]$ScanType,

        [Parameter(Mandatory)]
        [ValidateSet('File', 'Directory', 'Download')]
        [string]$ScanSourceType,

        [Parameter(Mandatory)]
        [string]$ScanSource,

        # Output Configuration
        [Parameter()]
        [ValidateSet('Console', 'JSON', 'CSV', 'TSV', 'Legacy')]
        [string]$Output = 'Console',

        # Download Parameters
        [Parameter()]
        [string]$NVDApiKey,

        [Parameter()]
        [string]$DownloadDirectory,

        [Parameter()]
        [ValidateRange(1, 3650)]
        [int]$VulnerabilityDaysBack = 90,

        [Parameter()]
        [ValidateRange(1, 2000)]
        [int]$MaxVulnerabilities = 100,

        # Execution Parameters
        [Parameter()]
        [bool]$UseCim = $true,

        [Parameter()]
        [bool]$IncludePerTestDetails = $true,

        [Parameter()]
        [ValidateRange(1, 100000)]
        [int]$MaxWmiRows = 1000,

        [Parameter()]
        [bool]$Prefer64BitRegistry = $true,

        # Remote Scanning Parameters
        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [ValidateSet('Yes', 'Upgrade', 'WhileScanning', 'No')]
        [string]$InstallPowerSCAP = 'No',

        # Filtering Parameters
        [Parameter()]
        [switch]$SkipPlatformFilter,

        [Parameter()]
        [switch]$SkipRoleFilter,

        [Parameter()]
        [ValidateSet('DomainController', 'MemberServer', 'StandaloneServer', 'DomainWorkstation', 'StandaloneWorkstation')]
        [string]$ForceRole
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    
    #region Parameter Mapping - New Clean Interface to Old Internal Structure
    # This section maps the new clean parameters to the old internal parameter structure
    # to maintain compatibility with existing code while providing better UX
    
    Write-Verbose "=== Parameter Mapping ==="
    Write-Verbose "ScanSourceType: $ScanSourceType"
    Write-Verbose "ScanSource: $ScanSource"
    Write-Verbose "Output: $Output"
    
    # Initialize all old internal variables to prevent "variable not set" errors
    $ComputerName = $null
    $ScapFile = $null
    $VulnerabilityFile = $null
    $VulnerabilityDirectory = $null
    $DownloadVulnerabilities = $false
    $VulnerabilitySource = $null
    $OutputJson = $false
    $LegacyOutput = $false
    $scanMode = $null
    
    # Validate ScanSource based on ScanSourceType
    switch ($ScanSourceType) {
        'File' {
            if (-not (Test-Path -LiteralPath $ScanSource -PathType Leaf -ErrorAction SilentlyContinue)) {
                Write-Error "Scan source file not found: $ScanSource"
                return
            }
        }
        'Directory' {
            if (-not (Test-Path -LiteralPath $ScanSource -PathType Container -ErrorAction SilentlyContinue)) {
                Write-Error "Scan source directory not found: $ScanSource"
                return
            }
        }
        'Download' {
            $validSources = @('NVD', 'MSRC', 'OVAL', 'All')
            if ($ScanSource -notin $validSources) {
                Write-Error "Invalid download source '$ScanSource'. Valid values: $($validSources -join ', ')"
                return
            }
        }
    }
    
    # Map Computer to ComputerName (used internally)
    if ($Computer) {
        $ComputerName = $Computer
    }
    
    # Map ScanSourceType and ScanSource to old parameter structure
    switch ($ScanSourceType) {
        'File' {
            # Infer scan type from filename if not specified
            if (-not $ScanType) {
                $fileName = Split-Path -Leaf $ScanSource
                if ($fileName -match 'STIG|SCAP|Benchmark') {
                    $ScanType = 'Compliance'
                    Write-Verbose "Inferred ScanType: Compliance (from filename)"
                } elseif ($fileName -match 'CVE|vulnerability|vuln') {
                    $ScanType = 'Vulnerability'
                    Write-Verbose "Inferred ScanType: Vulnerability (from filename)"
                } else {
                    # Default to compliance for XML files
                    $ScanType = 'Compliance'
                    Write-Verbose "Inferred ScanType: Compliance (default)"
                }
            }
            
            # Map to old parameters based on ScanType
            if ($ScanType -eq 'Compliance') {
                $ScapFile = $ScanSource
                $scanMode = 'SCAP'
            } else {
                $VulnerabilityFile = $ScanSource
                $scanMode = 'VulnFile'
            }
        }
        
        'Directory' {
            if (-not $ScanType) {
                # Directories are typically vulnerability scans
                $ScanType = 'Vulnerability'
                Write-Verbose "Inferred ScanType: Vulnerability (directory scan)"
            }
            $VulnerabilityDirectory = $ScanSource
            $scanMode = 'VulnDir'
        }
        
        'Download' {
            if (-not $ScanType) {
                # Downloads are always vulnerabilities
                $ScanType = 'Vulnerability'
                Write-Verbose "Inferred ScanType: Vulnerability (download)"
            }
            
            $DownloadVulnerabilities = $true
            $scanMode = 'Download'
            
            # Detect OS version for OVAL download
            # If scanning remote system, detect its OS; otherwise detect local OS
            $targetSystem = if ($Computer) { $Computer } else { "localhost" }
            
            try {
                if ($Computer) {
                    # Remote system - detect its OS
                    Write-Verbose "Detecting remote system OS: $Computer"
                    
                    # Check if it's Linux first
                    if ($isLinux) {
                        $linuxInfo = Get-LinuxOSInfo -ComputerName $Computer -Credential $Credential
                        $osCaption = "Linux - $($linuxInfo.Distribution) $($linuxInfo.Version)"
                        $productType = 3  # Treat as server
                        Write-Verbose "Remote OS detected: $osCaption"
                    } else {
                        # Windows system
                        $cimParams = @{
                            ClassName = 'Win32_OperatingSystem'
                            ComputerName = $Computer
                            ErrorAction = 'Stop'
                        }
                        if ($Credential) {
                            $cimParams['Credential'] = $Credential
                        }
                        $osInfo = Get-CimInstance @cimParams
                        $osCaption = $osInfo.Caption
                        $productType = $osInfo.ProductType
                        Write-Verbose "Remote OS detected: $osCaption"
                    }
                } else {
                    # Local system
                    if ($isLinux) {
                        $linuxInfo = Get-LinuxOSInfo
                        $osCaption = "Linux - $($linuxInfo.Distribution) $($linuxInfo.Version)"
                        $productType = 3  # Treat as server
                    } else {
                        $osCaption = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
                        $productType = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).ProductType
                    }
                }
            } catch {
                Write-Warning "Could not detect OS for $targetSystem : $($_.Exception.Message)"
                Write-Warning "Defaulting to Windows 10 OVAL definitions"
                $osCaption = "Windows 10"
                $productType = 1
            }
            
            # ProductType: 1=Workstation, 2=Domain Controller, 3=Server
            $isServer = ($productType -in @(2, 3))
            $isWindows11 = $osCaption -match 'Windows 11'
            $isWindows10 = $osCaption -match 'Windows 10'
            $isServer2025 = $osCaption -match 'Server 2025'
            $isServer2022 = $osCaption -match 'Server 2022'
            $isServer2019 = $osCaption -match 'Server 2019'
            $isServer2016 = $osCaption -match 'Server 2016'
            $isServerAny = $isServer2025 -or $isServer2022 -or $isServer2019 -or $isServer2016
            
            # Map download source names (user-friendly -> internal names)
            $VulnerabilitySource = switch ($ScanSource.ToUpper()) {
                'NVD' { 'NVD' }
                'MSRC' { 'MSRC' }
                'OVAL' { 
                    # Smart OVAL selection based on OS
                    # OVAL archives only have Windows 10 definitions
                    # Windows 11, Server 2016+, and Windows 10 share similar codebases but need different handling
                    
                    $targetLabel = if ($Computer) { "Target: $Computer" } else { "Local system" }
                    
                    if ($isWindows11) {
                        Write-Host "`n${targetLabel} detected: Windows 11" -ForegroundColor Cyan
                        Write-Host "OVAL Source: Downloading Windows 10 OVAL definitions (compatible codebase)" -ForegroundColor Yellow
                        Write-Host "`nIMPORTANT: Platform filtering will exclude all definitions (Windows 11 ≠ Windows 10)" -ForegroundColor Yellow
                        Write-Host "Recommended options:" -ForegroundColor White
                        Write-Host "  1. Use MSRC (best for Windows 11):" -ForegroundColor Gray
                        Write-Host "     Scan-Computer -ScanSourceType Download -ScanSource MSRC" -ForegroundColor DarkGray
                        Write-Host "  2. Skip platform filter to use OVAL:" -ForegroundColor Gray
                        Write-Host "     Scan-Computer -ScanSourceType Download -ScanSource OVAL -SkipPlatformFilter" -ForegroundColor DarkGray
                        Write-Host ""
                    } elseif ($isServerAny) {
                        $serverVersion = if ($isServer2025) { "2025" } 
                                       elseif ($isServer2022) { "2022" }
                                       elseif ($isServer2019) { "2019" }
                                       elseif ($isServer2016) { "2016" }
                                       else { "Unknown" }
                        Write-Host "`n${targetLabel} detected: Windows Server $serverVersion" -ForegroundColor Cyan
                        Write-Host "OVAL Source: Downloading Windows 10 OVAL definitions" -ForegroundColor Yellow
                        Write-Host "`nIMPORTANT: Platform filtering will exclude all definitions (Server $serverVersion ≠ Windows 10)" -ForegroundColor Yellow
                        Write-Host "Recommended options for Windows Server:" -ForegroundColor White
                        Write-Host "  1. Use MSRC (best for all Windows Server versions):" -ForegroundColor Gray
                        Write-Host "     Scan-Computer -ScanSourceType Download -ScanSource MSRC" -ForegroundColor DarkGray
                        Write-Host "  2. Use NVD with API key (most comprehensive):" -ForegroundColor Gray
                        Write-Host "     Scan-Computer -ScanSourceType Download -ScanSource NVD -NVDApiKey 'your-key'" -ForegroundColor DarkGray
                        Write-Host "  3. Skip platform filter to use OVAL (may have false positives):" -ForegroundColor Gray
                        Write-Host "     Scan-Computer -ScanSourceType Download -ScanSource OVAL -SkipPlatformFilter" -ForegroundColor DarkGray
                        Write-Host ""
                    } elseif ($isWindows10) {
                        Write-Verbose "${targetLabel}: Windows 10 detected - downloading Windows 10 OVAL definitions"
                    } else {
                        Write-Host "`n${targetLabel} detected: $osCaption" -ForegroundColor Cyan
                        Write-Host "OVAL Source: Downloading Windows 10 OVAL definitions" -ForegroundColor Yellow
                        Write-Host "Note: Platform filtering may exclude definitions if OS doesn't match Windows 10 exactly" -ForegroundColor Gray
                        Write-Host ""
                    }
                    'Windows10OVAL'
                }
                'All' { 'All' }
                default { $ScanSource }
            }
            
            Write-Verbose "Mapped download source: $ScanSource -> $VulnerabilitySource"
        }
    }
    
    # Map Output to old OutputJson/LegacyOutput flags
    $OutputJson = ($Output -eq 'JSON')
    $LegacyOutput = ($Output -eq 'Legacy')
    
    # Flag for post-processing (CSV/TSV need conversion after results)
    $outputNeedsConversion = ($Output -in @('CSV', 'TSV'))
    
    Write-Verbose "Mapped to internal scan mode: $scanMode"
    Write-Verbose "OutputJson: $OutputJson, LegacyOutput: $LegacyOutput"
    Write-Verbose "ComputerName: $ComputerName"
    
    #endregion
    
    #region Platform Detection
    # Detect if target system is Windows or Linux
    # This affects how we gather system information and which tests can be run
    
    $isLinux = $false
    $isWindows = $false
    
    if ($Computer -and $Computer.Trim().Length -gt 0) {
        # Remote system - detect platform
        Write-Verbose "Detecting platform for remote system: $Computer"
        $isLinux = Test-IsLinux -ComputerName $Computer -Credential $Credential
        $isWindows = -not $isLinux
        
        if ($isLinux) {
            Write-Verbose "Remote platform detected: Linux"
            $linuxInfo = Get-LinuxOSInfo -ComputerName $Computer -Credential $Credential
            if ($linuxInfo) {
                Write-Verbose "Linux Distribution: $($linuxInfo.Distribution) $($linuxInfo.Version)"
            }
        } else {
            Write-Verbose "Remote platform detected: Windows"
        }
    } else {
        # Local system
        $isLinux = ($PSVersionTable.Platform -eq 'Unix' -or $PSVersionTable.OS -like '*Linux*' -or $IsLinux)
        $isWindows = -not $isLinux
        
        if ($isLinux) {
            Write-Verbose "Local platform detected: Linux"
            $linuxInfo = Get-LinuxOSInfo
            if ($linuxInfo) {
                Write-Verbose "Linux Distribution: $($linuxInfo.Distribution) $($linuxInfo.Version)"
            }
        } else {
            Write-Verbose "Local platform detected: Windows"
        }
    }
    
    # Warn if scanning Linux with Windows-specific scan types
    if ($isLinux -and $scanMode -eq 'SCAP') {
        Write-Warning "Scanning Linux system with SCAP/STIG file. Note: Windows-specific tests (Registry, WMI, Windows services) will be skipped."
    }
    
    #endregion
    
    #region System Role Detection
    # Detect system role BEFORE file processing (needed for role-based filtering during XCCDF parsing)
    
    # Get current system information for role detection
    # Handle CimSession - only pass if not null (for remote scanning)
    $cimParams = @{
        ErrorAction = 'SilentlyContinue'
    }
    if ($Computer -and $Computer.Trim().Length -gt 0) {
        # For remote scanning, we'll detect role later after CimSession is established
        # For now, set a default
        if ($isLinux) {
            # Linux systems - use a simplified role model
            $systemRole = "LinuxServer"  # Default for Linux
        } else {
            $systemRole = "Unknown"
        }
    } else {
        # Local scanning - detect role now
        if ($isLinux) {
            # Linux role detection
            # For simplicity, we'll treat all Linux systems as "LinuxServer"
            # Could be enhanced to detect specific roles in the future
            $systemRole = "LinuxServer"
            Write-Verbose "System Role: $systemRole (Linux system)"
        } else {
            # Windows role detection
            $osInfo = Get-CimInstance Win32_OperatingSystem @cimParams
            if (-not $osInfo) {
                $osInfo = Get-WmiObject Win32_OperatingSystem
            }
            
            $csInfo = Get-CimInstance Win32_ComputerSystem @cimParams
            if (-not $csInfo) {
                $csInfo = Get-WmiObject Win32_ComputerSystem
            }
            
            # Determine system role
            # ProductType: 1=Workstation, 2=Domain Controller, 3=Server
            $productType = $osInfo.ProductType
            $isDomainJoined = $csInfo.PartOfDomain
            
            if ($ForceRole) {
                $systemRole = $ForceRole
                Write-Verbose "System Role: $systemRole (FORCED via -ForceRole parameter)"
            } else {
                if ($productType -eq 2) {
                    $systemRole = "DomainController"
                } elseif ($productType -eq 3) {
                    if ($isDomainJoined) {
                        $systemRole = "MemberServer"
                    } else {
                        $systemRole = "StandaloneServer"
                    }
                } else {
                    if ($isDomainJoined) {
                        $systemRole = "DomainWorkstation"
                    } else {
                        $systemRole = "StandaloneWorkstation"
                    }
                }
                
                Write-Verbose "System Role: $systemRole (ProductType=$productType, DomainJoined=$isDomainJoined)"
            }
        }
    }
    
    #endregion
    
    
    # Handle remote scanning with PowerSCAP installation
    if ($ComputerName -and $ComputerName.Trim().Length -gt 0 -and
        $ComputerName.Trim().ToLowerInvariant() -ne $env:COMPUTERNAME.Trim().ToLowerInvariant() -and
        $InstallPowerSCAP -ne 'No') {
        
        Write-Host "`n=== Remote Scanning with PowerSCAP Installation ===" -ForegroundColor Cyan
        Write-Host "Target: $ComputerName" -ForegroundColor White
        Write-Host "Mode: $InstallPowerSCAP" -ForegroundColor White
        
        # Check PowerShell remoting
        try {
            Write-Verbose "Testing PowerShell remoting to $ComputerName"
            $testParams = @{
                ComputerName = $ComputerName
                ScriptBlock = { $env:COMPUTERNAME }
                ErrorAction = 'Stop'
            }
            if ($Credential) {
                $testParams['Credential'] = $Credential
            }
            $remoteName = Invoke-Command @testParams
            Write-Verbose "PowerShell remoting successful (connected to: $remoteName)"
        } catch {
            Write-Error "PowerShell remoting is not available to $ComputerName. Error: $($_.Exception.Message)`n`nTo use InstallPowerSCAP modes, ensure:`n1. PowerShell remoting is enabled on $ComputerName (Enable-PSRemoting)`n2. Firewall allows WinRM traffic`n3. You have appropriate permissions`n`nOr use -InstallPowerSCAP No to scan without installation."
            return
        }
        
        # Determine module source path (current loaded module)
        $currentModule = Get-Module -Name PowerSCAP
        if (-not $currentModule) {
            Write-Error "PowerSCAP module is not loaded in the current session. Please import the module first."
            return
        }
        $sourceModulePath = $currentModule.ModuleBase
        Write-Verbose "Source module path: $sourceModulePath"
        
        # Check if PowerSCAP is already installed on remote system
        Write-Host "Checking PowerSCAP installation on $ComputerName..." -ForegroundColor Gray
        $remoteInstallInfo = Test-RemotePowerSCAPInstalled -ComputerName $ComputerName -Credential $Credential
        
        $needsInstall = $false
        $installScope = if ($InstallPowerSCAP -eq 'WhileScanning') { 'User' } else { 'System' }
        
        if ($InstallPowerSCAP -eq 'Upgrade') {
            Write-Host "Upgrade mode: Installing/upgrading PowerSCAP..." -ForegroundColor Yellow
            $needsInstall = $true
        } elseif ($InstallPowerSCAP -eq 'WhileScanning') {
            Write-Host "WhileScanning mode: Temporarily installing PowerSCAP in user context..." -ForegroundColor Yellow
            $needsInstall = $true
        } elseif ($InstallPowerSCAP -eq 'Yes') {
            if ($remoteInstallInfo.Installed) {
                Write-Host "PowerSCAP already installed on $ComputerName (Version: $($remoteInstallInfo.Version))" -ForegroundColor Green
                $needsInstall = $false
            } else {
                Write-Host "PowerSCAP not found on $ComputerName. Installing..." -ForegroundColor Yellow
                $needsInstall = $true
            }
        }
        
        # Install if needed
        if ($needsInstall) {
            $installResult = Install-RemotePowerSCAP `
                -ComputerName $ComputerName `
                -Credential $Credential `
                -SourceModulePath $sourceModulePath `
                -Scope $installScope `
                -Force:($InstallPowerSCAP -eq 'Upgrade')
            
            if (-not $installResult.Success) {
                Write-Error "Failed to install PowerSCAP on $ComputerName : $($installResult.Error)"
                return
            }
            
            Write-Host "PowerSCAP installed successfully ($($installResult.FileCount) files)" -ForegroundColor Green
        }
        
        # Build scan parameters to send to remote system
        $remoteScanParams = @{}
        
        # Copy relevant parameters (excluding remote-specific ones)
        if ($ScapFile) { $remoteScanParams['ScapFile'] = $ScapFile }
        if ($VulnerabilityFile) { $remoteScanParams['VulnerabilityFile'] = $VulnerabilityFile }
        if ($VulnerabilityDirectory) { $remoteScanParams['VulnerabilityDirectory'] = $VulnerabilityDirectory }
        if ($PSBoundParameters.ContainsKey('UseCim')) { $remoteScanParams['UseCim'] = $UseCim }
        if ($PSBoundParameters.ContainsKey('IncludePerTestDetails')) { $remoteScanParams['IncludePerTestDetails'] = $IncludePerTestDetails }
        if ($PSBoundParameters.ContainsKey('MaxWmiRows')) { $remoteScanParams['MaxWmiRows'] = $MaxWmiRows }
        if ($PSBoundParameters.ContainsKey('Prefer64BitRegistry')) { $remoteScanParams['Prefer64BitRegistry'] = $Prefer64BitRegistry }
        if ($SkipPlatformFilter) { $remoteScanParams['SkipPlatformFilter'] = $true }
        if ($SkipRoleFilter) { $remoteScanParams['SkipRoleFilter'] = $true }
        if ($ForceRole) { $remoteScanParams['ForceRole'] = $ForceRole }
        
        # Note: ComputerName and Credential are NOT passed - we want local execution on the remote system
        # Note: InstallPowerSCAP is NOT passed - we're already on the remote system
        
        try {
            Write-Host "Executing scan on $ComputerName..." -ForegroundColor Cyan
            
            # Execute scan on remote system
            $results = Invoke-RemotePowerSCAPScan `
                -ComputerName $ComputerName `
                -Credential $Credential `
                -ScanParameters $remoteScanParams
            
            Write-Host "Scan completed on $ComputerName" -ForegroundColor Green
            
            # Clean up if WhileScanning mode
            if ($InstallPowerSCAP -eq 'WhileScanning') {
                Write-Host "Removing temporary PowerSCAP installation..." -ForegroundColor Gray
                $removeResult = Remove-RemotePowerSCAP -ComputerName $ComputerName -Credential $Credential -Scope User
                if ($removeResult.Success) {
                    Write-Host "Temporary installation removed" -ForegroundColor Green
                }
            }
            
            # Output results based on format requested
            if ($OutputJson) {
                return ($results | ConvertTo-Json -Depth 10)
            } else {
                # Display results
                Write-Host "`n=== Scan Results from $ComputerName ===" -ForegroundColor Cyan
                Write-Host "Total Checks: $($results.Count)" -ForegroundColor White
                
                $passCount = ($results | Where-Object { $_.Pass }).Count
                $failCount = ($results | Where-Object { -not $_.Pass }).Count
                $passRate = if ($results.Count -gt 0) { [math]::Round(($passCount / $results.Count) * 100, 2) } else { 0 }
                
                Write-Host "Pass: $passCount ($passRate%)" -ForegroundColor Green
                Write-Host "Fail: $failCount" -ForegroundColor Red
                
                # Return results object
                return $results
            }
            
        } catch {
            Write-Error "Failed to execute scan on $ComputerName : $($_.Exception.Message)"
            
            # Clean up on error if WhileScanning mode
            if ($InstallPowerSCAP -eq 'WhileScanning') {
                Write-Host "Cleaning up after error..." -ForegroundColor Gray
                Remove-RemotePowerSCAP -ComputerName $ComputerName -Credential $Credential -Scope User | Out-Null
            }
            
            return
        }
    }

    # Handle vulnerability download if requested
    if ($DownloadVulnerabilities) {
        Write-Host "`n=== Downloading Vulnerability Definitions ===" -ForegroundColor Cyan
        
        # Determine download directory
        if (-not $DownloadDirectory) {
            # Include source name in directory to prevent cache collision between sources
            $DownloadDirectory = Join-Path $env:TEMP "PowerSCAP_Vulnerabilities_$($VulnerabilitySource)_$(Get-Date -Format 'yyyyMMdd')"
        }

        # Check if we already have today's download (and it actually has files)
        $todayDownload = $false
        if (Test-Path $DownloadDirectory) {
            # Check if directory has XML files
            $xmlFiles = @(Get-ChildItem -Path $DownloadDirectory -Filter "*.xml" -File -ErrorAction SilentlyContinue)
            if ($xmlFiles.Count -gt 0) {
                $todayDownload = $true
                Write-Host "Using cached vulnerability definitions from: $DownloadDirectory" -ForegroundColor Yellow
                Write-Host "  Found $($xmlFiles.Count) cached file(s)" -ForegroundColor Gray
                Write-Host "  To force re-download, delete this directory or specify a different -DownloadDirectory" -ForegroundColor Gray
            } else {
                # Directory exists but is empty - clean it up and re-download
                Write-Host "Cached directory exists but is empty. Cleaning up and downloading fresh..." -ForegroundColor Yellow
                try {
                    Remove-Item -Path $DownloadDirectory -Recurse -Force -ErrorAction Stop
                } catch {
                    Write-Warning "Could not clean up empty cache directory: $_"
                }
                $todayDownload = $false
            }
        }
        
        if (-not $todayDownload) {
            Write-Host "Downloading to: $DownloadDirectory" -ForegroundColor White
            
            # Prepare download parameters
            $downloadParams = @{
                Source = $VulnerabilitySource
                OutputDirectory = $DownloadDirectory
                Platform = 'Windows'
            }

            if ($NVDApiKey) {
                $downloadParams['NVDApiKey'] = $NVDApiKey
            }
            if ($VulnerabilityDaysBack) {
                $downloadParams['DaysBack'] = $VulnerabilityDaysBack
            }
            if ($MaxVulnerabilities) {
                $downloadParams['MaxResults'] = $MaxVulnerabilities
            }

            # Download vulnerabilities
            try {
                $downloadResults = Get-VulnerabilityFeed @downloadParams
                
                Write-Host "`nDownload Summary:" -ForegroundColor Cyan
                Write-Host "  Source: $($downloadResults.Source)" -ForegroundColor White
                Write-Host "  Files Downloaded: $($downloadResults.FilesDownloaded.Count)" -ForegroundColor White
                Write-Host "  Total Vulnerabilities: $($downloadResults.TotalVulnerabilities)" -ForegroundColor White
                
                if ($downloadResults.FilesDownloaded.Count -gt 0) {
                    Write-Host "`n  Downloaded Files:" -ForegroundColor Gray
                    foreach ($file in $downloadResults.FilesDownloaded) {
                        Write-Host "    - $(Split-Path -Leaf $file)" -ForegroundColor Gray
                    }
                }

                if ($downloadResults.Errors.Count -gt 0) {
                    Write-Warning "`nDownload Warnings/Errors:"
                    foreach ($error in $downloadResults.Errors) {
                        Write-Warning "  $error"
                    }
                }
                
                # Verify we actually got files
                if ($downloadResults.FilesDownloaded.Count -eq 0) {
                    Write-Error "Download completed but no vulnerability files were retrieved. Check errors above or try a different source (OVAL, MSRC, or use -NVDApiKey for NVD)."
                    return
                }

            } catch {
                Write-Error "Failed to download vulnerability definitions: $_"
                return
            }
        }

        # Now switch to VulnDir mode with the downloaded directory
        $VulnerabilityDirectory = $DownloadDirectory
        $scanMode = 'VulnDir'
        
        # Verify the directory has XML files before proceeding
        # For 'All' downloads, files are in subdirectories, so search recursively
        if ($VulnerabilitySource -eq 'All') {
            $xmlFiles = @(Get-ChildItem -Path $VulnerabilityDirectory -Filter "*.xml" -File -Recurse -ErrorAction SilentlyContinue)
        } else {
            $xmlFiles = @(Get-ChildItem -Path $VulnerabilityDirectory -Filter "*.xml" -File -ErrorAction SilentlyContinue)
        }
        
        if ($xmlFiles.Count -eq 0) {
            Write-Error "Download directory exists but contains no XML files. The download may have failed. Directory: $VulnerabilityDirectory"
            return
        }
        
        Write-Verbose "Found $($xmlFiles.Count) XML files to process"
        
        Write-Host "`n=== Starting Vulnerability Scan ===" -ForegroundColor Cyan
    }
    
    # Note: scanMode is already set by parameter mapping at the beginning of function
    # Do NOT overwrite it here (old code used $PSCmdlet.ParameterSetName which no longer applies)
    
    Write-Verbose "Current scanMode: $scanMode"
    Write-Verbose "ScapFile: $ScapFile"
    Write-Verbose "VulnerabilityFile: $VulnerabilityFile"
    Write-Verbose "VulnerabilityDirectory: $VulnerabilityDirectory"
    Write-Verbose "DownloadVulnerabilities: $DownloadVulnerabilities"
    
    if ([string]::IsNullOrEmpty($scanMode)) {
        Write-Error "scanMode is not set! This should not happen. Parameter mapping failed."
        return
    }

    # Determine file paths based on scan mode
    $filesToProcess = @()
    
    Write-Verbose "Processing scanMode: $scanMode"
    
    switch ($scanMode) {
        'SCAP' {
            # Normalize path
            $ScapFile = ($ScapFile -replace '[""]', '"').Trim().Trim('"').Trim("'")
            try {
                $resolvedPath = (Resolve-Path -LiteralPath $ScapFile -ErrorAction Stop).Path
                $filesToProcess += $resolvedPath
                
                # Validate role compatibility with SCAP/STIG file
                # Note: Modern STIGs often combine multiple roles (DC, MS, standalone) in one file
                # with platform tags on individual rules. Only warn for clearly role-specific files.
                if (-not $SkipRoleFilter) {
                    $stigFileName = Split-Path -Leaf $resolvedPath
                    $roleWarning = $null
                    
                    # Only warn for explicitly role-specific STIG files
                    # General "Windows Server" STIGs contain multiple roles with platform tags
                    if ($stigFileName -match "Active.*Directory.*Domain|AD.*Domain.*Controller" -and $systemRole -ne "DomainController") {
                        $roleWarning = "NOTE: This appears to be a Domain Controller-specific STIG, but system role is '$systemRole'. Role-specific checks will be automatically filtered."
                    }
                    elseif ($stigFileName -match "Member.*Server.*Only" -and $systemRole -ne "MemberServer") {
                        $roleWarning = "NOTE: This appears to be a Member Server-specific STIG, but system role is '$systemRole'. Role-specific checks will be automatically filtered."
                    }
                    elseif ($stigFileName -match "Windows\s+(10|11)" -and $systemRole -notmatch "Workstation") {
                        $roleWarning = "NOTE: This appears to be a Workstation STIG, but system role is '$systemRole'. Role-specific checks will be automatically filtered."
                    }
                    
                    if ($roleWarning) {
                        Write-Host $roleWarning -ForegroundColor Yellow
                    }
                }
            } catch {
                throw "SCAP file not found. Checked path: $ScapFile. Error: $($_.Exception.Message)"
            }
        }
        'VulnFile' {
            # Normalize path
            $VulnerabilityFile = ($VulnerabilityFile -replace '[""]', '"').Trim().Trim('"').Trim("'")
            try {
                $resolvedPath = (Resolve-Path -LiteralPath $VulnerabilityFile -ErrorAction Stop).Path
                $filesToProcess += $resolvedPath
            } catch {
                throw "Vulnerability file not found. Checked path: $VulnerabilityFile. Error: $($_.Exception.Message)"
            }
        }
        'VulnDir' {
            # Normalize path
            $VulnerabilityDirectory = ($VulnerabilityDirectory -replace '[""]', '"').Trim().Trim('"').Trim("'")
            try {
                $resolvedDir = (Resolve-Path -LiteralPath $VulnerabilityDirectory -ErrorAction Stop).Path
                # Wrap in @() to ensure it's always an array (PowerShell returns single objects without .Count)
                # Search recursively to support subdirectories (e.g., when downloading from 'All' sources)
                $ovalFiles = @(Get-ChildItem -LiteralPath $resolvedDir -Filter "*.xml" -File -Recurse -ErrorAction Stop)
                if ($ovalFiles.Count -eq 0) {
                    throw "No XML files found in directory: $resolvedDir"
                }
                $filesToProcess = @($ovalFiles | ForEach-Object { $_.FullName })
                Write-Verbose "Found $($filesToProcess.Count) OVAL vulnerability files in directory (searched recursively)"
            } catch {
                throw "Error accessing vulnerability directory. Checked path: $VulnerabilityDirectory. Error: $($_.Exception.Message)"
            }
        }
    }
    
    Write-Verbose "filesToProcess count: $($filesToProcess.Count)"
    if ($filesToProcess.Count -gt 0) {
        Write-Verbose "Files to process:"
        foreach ($f in $filesToProcess) {
            Write-Verbose "  - $f"
        }
    } else {
        Write-Error "No files to process! scanMode was '$scanMode' but no files were added to filesToProcess."
        return
    }

    # Optional CimSession for remote CIM/WMI
    $script:CimSession = $null
    try {
        if ($UseCim -and $ComputerName -and $ComputerName.Trim().Length -gt 0 -and
            $ComputerName.Trim().ToLowerInvariant() -ne $env:COMPUTERNAME.Trim().ToLowerInvariant()) {
            if ($Credential) {
                $script:CimSession = New-CimSession -ComputerName $ComputerName -Credential $Credential
            } else {
                $script:CimSession = New-CimSession -ComputerName $ComputerName
            }
        }
    } catch {
        Write-Warning "Failed to create CimSession for '$ComputerName': $($_.Exception.Message). Queries will run locally."
        $script:CimSession = $null
    }

    # Initialize consolidated lookups
    $script:definitions = @{}
    $script:variables = @{}
    $script:objects = @{}
    $script:states = @{}
    $script:tests = @{}
    $script:xccdfRules = @{}
    
    # Track which definitions came from which files (for reporting)
    $definitionSources = @{}

    # Process each file
    foreach ($filePath in $filesToProcess) {
        Write-Verbose "Loading file: $filePath"
        
        try {
            [xml]$xml = Get-Content -LiteralPath $filePath -Raw -ErrorAction Stop
        } catch {
            Write-Warning "Failed to load XML from '$filePath'. Error: $($_.Exception.Message). Skipping."
            continue
        }

        # Determine file type and extract OVAL content
        $ovalNodes = $null
        $xccdfNodes = $null
        
        if ($scanMode -eq 'SCAP') {
            # SCAP data stream format
            $ovalNodes = Select-XmlNodes -Xml $xml -XPath "/*[local-name()='data-stream-collection']/*[local-name()='component']/*[local-name()='oval_definitions']"
            $xccdfNodes = Select-XmlNodes -Xml $xml -XPath "/*[local-name()='data-stream-collection']/*[local-name()='component']/*[local-name()='Benchmark']"
        } else {
            # Standalone OVAL definition format (vulnerability files)
            # Check if root is a definition element
            $rootDef = Select-XmlNodes -Xml $xml -XPath "/*[local-name()='definition']"
            if ($rootDef -and ((@($rootDef) | Measure-Object).Count) -gt 0) {
                # Single definition file - wrap in a pseudo oval_definitions structure
                $ovalNodes = @($xml.DocumentElement)
            } else {
                # Check for oval_definitions root
                $ovalNodes = Select-XmlNodes -Xml $xml -XPath "/*[local-name()='oval_definitions']"
            }
        }

        if (-not $ovalNodes -or ((@($ovalNodes) | Measure-Object).Count) -eq 0) {
            Write-Warning "No OVAL definitions found in file: $filePath. Skipping."
            continue
        }

        # Process XCCDF if present (SCAP files only)
        if ($xccdfNodes -and ((@($xccdfNodes) | Measure-Object).Count) -gt 0) {
            $xccdf = @($xccdfNodes)[0]
            Write-Verbose "Parsing XCCDF Benchmark for severity mappings and role filtering..."
            $ruleNodes = Select-XmlNodes -Xml $xccdf -XPath ".//*[local-name()='Rule']"
            Write-Verbose "Found $(@($ruleNodes).Count) XCCDF Rule nodes"
            
            # Map system roles to CPE platform IDs for filtering
            # Rules can have multiple platform tags - we match if ANY platform matches
            # Rules with no platform apply to all roles
            $roleToPlatformMap = @{
                'DomainController' = @('#xccdf_mil.disa.stig_platform_Windows_DomainController')
                'MemberServer' = @('#xccdf_mil.disa.stig_platform_Windows_MemberServer')
                'StandaloneServer' = @('#xccdf_mil.disa.stig_platform_Windows_StandaloneServer')
                'DomainWorkstation' = @()  # Workstation platforms typically don't exist in server STIGs
                'StandaloneWorkstation' = @()
            }
            
            # Ensure applicablePlatforms is always an array (PowerShell gotcha - hashtable values aren't always arrays)
            $applicablePlatforms = @(if ($roleToPlatformMap.ContainsKey($systemRole)) {
                $roleToPlatformMap[$systemRole]
            } else {
                @()
            })
            
            Write-Verbose "Applicable platforms for role '$systemRole': $($applicablePlatforms.Count) platform(s)"
            
            $mappingCount = 0
            $roleFilteredCount = 0
            foreach ($rule in $ruleNodes) {
                # Check if rule has a platform restriction (role-specific)
                if (-not $SkipRoleFilter -and $applicablePlatforms.Count -gt 0) {
                    $platformNodes = Select-XmlNodes -Xml $rule -XPath "./*[local-name()='platform']"
                    if ($platformNodes -and ((@($platformNodes) | Measure-Object).Count) -gt 0) {
                        # Rule has platform restriction - check if it matches our role
                        $platformMatches = $false
                        foreach ($platformNode in $platformNodes) {
                            $platformIdref = Get-AttrValue -Node $platformNode -Name 'idref'
                            if ($platformIdref -and $platformIdref -in $applicablePlatforms) {
                                $platformMatches = $true
                                break
                            }
                        }
                        
                        if (-not $platformMatches) {
                            # Rule doesn't apply to this system role - skip it
                            $roleFilteredCount++
                            continue
                        }
                    }
                    # If rule has no platform restriction, it applies to all roles
                }
                
                $severityAttr = $rule.Attributes["severity"]
                $severity = if ($severityAttr) { $severityAttr.Value } else { $null }
                
                $weightAttr = $rule.Attributes["weight"]
                $weight = if ($weightAttr) { $weightAttr.Value } else { $null }
                
                $ruleIdAttr = $rule.Attributes["id"]
                $ruleId = if ($ruleIdAttr) { $ruleIdAttr.Value } else { "unknown" }
                
                $checkRefs = Select-XmlNodes -Xml $rule -XPath ".//*[local-name()='check-content-ref']"
                foreach ($checkRef in $checkRefs) {
                    $nameAttr = $checkRef.Attributes["name"]
                    if ($nameAttr) {
                        $ovalDefId = $nameAttr.Value
                        if (-not $script:xccdfRules.ContainsKey($ovalDefId)) {
                            $script:xccdfRules[$ovalDefId] = @{
                                Severity = $severity
                                Weight   = $weight
                                RuleId   = $ruleId
                                CVE      = $null  # SCAP files typically don't have CVE in XCCDF rules
                            }
                            $mappingCount++
                        }
                    }
                }
            }
            Write-Verbose "Created $mappingCount XCCDF->OVAL severity mappings from $filePath"
            if ($roleFilteredCount -gt 0) {
                Write-Verbose "Filtered out $roleFilteredCount rules not applicable to role '$systemRole'"
            }
        }

        # Process OVAL content
        foreach ($ovalRoot in $ovalNodes) {
            # Handle standalone definition vs oval_definitions wrapper
            $definitionNodes = $null
            if ($ovalRoot.LocalName -eq 'definition') {
                # Single definition file
                $definitionNodes = @($ovalRoot)
            } else {
                # Standard oval_definitions structure
                $definitionNodes = Select-XmlNodes -Xml $ovalRoot -XPath "./*[local-name()='definitions']/*[local-name()='definition']"
            }
            
            foreach ($def in $definitionNodes) {
                $attr = $def.Attributes["id"]
                if ($attr) {
                    $defId = $attr.Value
                    if (-not $script:definitions.ContainsKey($defId)) {
                        $script:definitions[$defId] = $def
                        $definitionSources[$defId] = $filePath
                        
                        # Extract severity from metadata if not from XCCDF
                        if (-not $script:xccdfRules.ContainsKey($defId)) {
                            $severityNode = Select-XmlNode -Xml $def -XPath "./*[local-name()='metadata']/*[local-name()='severity']"
                            $severity = if ($severityNode) { Get-InnerText $severityNode } else { $null }
                            
                            # Extract CVE reference
                            $refNode = Select-XmlNode -Xml $def -XPath "./*[local-name()='metadata']/*[local-name()='reference'][@source='CVE']"
                            $cveId = if ($refNode) { Get-AttrValue -Node $refNode -Name 'ref_id' } else { $null }
                            
                            # Only add to xccdfRules if we actually found severity or CVE metadata
                            # This prevents blocking the numeric suffix fallback matching later
                            if ($severity -or $cveId) {
                                $script:xccdfRules[$defId] = @{
                                    Severity = $severity
                                    CVE      = $cveId
                                    RuleId   = $defId
                                }
                            }
                        }
                    }
                }
            }

            # Process variables
            $variableNodes = Select-XmlNodes -Xml $ovalRoot -XPath "./*[local-name()='variables']/*"
            foreach ($var in $variableNodes) {
                $attr = $var.Attributes["id"]
                if ($attr -and -not $script:variables.ContainsKey($attr.Value)) {
                    $script:variables[$attr.Value] = $var
                }
            }

            # Process objects
            $objectNodes = Select-XmlNodes -Xml $ovalRoot -XPath ".//*[contains(local-name(), '_object')]"
            foreach ($obj in $objectNodes) {
                $attr = $obj.Attributes["id"]
                if ($attr -and -not $script:objects.ContainsKey($attr.Value)) {
                    $script:objects[$attr.Value] = $obj
                }
            }

            # Process states
            $stateNodes = Select-XmlNodes -Xml $ovalRoot -XPath ".//*[contains(local-name(), '_state')]"
            foreach ($st in $stateNodes) {
                $attr = $st.Attributes["id"]
                if ($attr -and -not $script:states.ContainsKey($attr.Value)) {
                    $script:states[$attr.Value] = $st
                }
            }

            # Process tests
            $testNodes = Select-XmlNodes -Xml $ovalRoot -XPath ".//*[contains(local-name(), '_test')]"
            foreach ($tst in $testNodes) {
                $attr = $tst.Attributes["id"]
                if ($attr -and -not $script:tests.ContainsKey($attr.Value)) {
                    $script:tests[$attr.Value] = $tst
                }
            }
        }
    }

    # Verify we have definitions to evaluate
    if ($script:definitions.Count -eq 0) {
        Write-Error "No OVAL definitions loaded. Cannot proceed with scan."
        if ($script:CimSession) {
            try { $script:CimSession | Remove-CimSession -ErrorAction SilentlyContinue } catch {}
        }
        return
    }
    
    Write-Verbose "Loaded $($script:definitions.Count) definitions, $($script:tests.Count) tests, $($script:objects.Count) objects, $($script:states.Count) states"

    # Shared settings
    $script:MaxWmiRows = $MaxWmiRows
    $script:UseCim     = $UseCim
    $script:Prefer64BitRegistry = $Prefer64BitRegistry

    # Main evaluation
    $results = @()
    $evalCount = 0
    $allDefinitions = @($script:definitions.Values)
    $definitionTotal = $allDefinitions.Count

    # Get current system information for platform filtering (vulnerabilities)
    # Handle CimSession - only pass if not null
    $cimParams = @{
        ErrorAction = 'SilentlyContinue'
    }
    if ($script:CimSession) {
        $cimParams['CimSession'] = $script:CimSession
    }
    
    $osInfo = Get-CimInstance Win32_OperatingSystem @cimParams
    if (-not $osInfo) {
        # Fallback if CIM fails
        $osInfo = @{
            Caption = (Get-WmiObject Win32_OperatingSystem).Caption
            Version = [System.Environment]::OSVersion.Version.ToString()
            ProductType = (Get-WmiObject Win32_OperatingSystem).ProductType
        }
    }
    $currentOS = $osInfo.Caption
    Write-Verbose "Current OS: $currentOS"
    
    # Note: System role was already detected earlier (before file processing)
    # If remote scanning and role wasn't detected earlier, detect it now
    if ($systemRole -eq "Unknown" -or -not $systemRole) {
        $csInfo = Get-CimInstance Win32_ComputerSystem @cimParams
        if (-not $csInfo) {
            $csInfo = Get-WmiObject Win32_ComputerSystem
        }
        
        $productType = $osInfo.ProductType
        $isDomainJoined = $csInfo.PartOfDomain
        
        if ($ForceRole) {
            $systemRole = $ForceRole
            Write-Verbose "System Role: $systemRole (FORCED via -ForceRole parameter)"
        } else {
            if ($productType -eq 2) {
                $systemRole = "DomainController"
            } elseif ($productType -eq 3) {
                if ($isDomainJoined) {
                    $systemRole = "MemberServer"
                } else {
                    $systemRole = "StandaloneServer"
                }
            } else {
                if ($isDomainJoined) {
                    $systemRole = "DomainWorkstation"
                } else {
                    $systemRole = "StandaloneWorkstation"
                }
            }
            
            Write-Verbose "System Role: $systemRole (detected for remote system - ProductType=$productType, DomainJoined=$isDomainJoined)"
        }
    }

    # Filter definitions by applicability if scanning vulnerabilities
    $applicableDefinitions = @()
    if ($scanMode -ne 'SCAP' -and -not $SkipPlatformFilter) {
        Write-Verbose "Filtering vulnerability definitions for platform applicability..."
        foreach ($def in $allDefinitions) {
            $affectedNode = Select-XmlNode -Xml $def -XPath "./*[local-name()='metadata']/*[local-name()='affected']"
            
            if (-not $affectedNode) {
                # No affected metadata - include it (may be broadly applicable)
                $applicableDefinitions += $def
                continue
            }
            
            # Check family attribute (windows, unix, macos, etc.)
            $familyAttr = Get-AttrValue -Node $affectedNode -Name 'family'
            if ($familyAttr -and $familyAttr -ne 'windows') {
                # Wrong OS family - skip this definition
                continue
            }
            
            # Check platform elements
            $platformNodes = Select-XmlNodes -Xml $affectedNode -XPath "./*[local-name()='platform']"
            if ($platformNodes -and ((@($platformNodes) | Measure-Object).Count) -gt 0) {
                $platformMatch = $false
                foreach ($platformNode in $platformNodes) {
                    $platform = Get-InnerText $platformNode
                    
                    # Check if current OS matches this platform
                    # Handle various platform naming patterns
                    if ($currentOS -match [regex]::Escape($platform)) {
                        $platformMatch = $true
                        break
                    }
                    
                    # Check for version-agnostic matches (e.g., "Microsoft Windows" matches all Windows)
                    if ($platform -eq "Microsoft Windows" -and $currentOS -match "Microsoft Windows") {
                        $platformMatch = $true
                        break
                    }
                    
                    # Handle Windows 10/11 version-specific checks
                    if ($platform -match "Windows 10" -and $currentOS -match "Windows 10") {
                        $platformMatch = $true
                        break
                    }
                    if ($platform -match "Windows 11" -and $currentOS -match "Windows 11") {
                        $platformMatch = $true
                        break
                    }
                    
                    # Handle Windows Server
                    if ($platform -match "Windows Server" -and $currentOS -match "Windows Server") {
                        # Check specific versions if specified
                        if ($platform -match "2016|2019|2022|2025") {
                            if ($currentOS -match $platform) {
                                $platformMatch = $true
                                break
                            }
                        } else {
                            # Generic "Windows Server" matches any server
                            $platformMatch = $true
                            break
                        }
                    }
                }
                
                if ($platformMatch) {
                    $applicableDefinitions += $def
                }
            } else {
                # No specific platforms listed, check product
                $productNodes = Select-XmlNodes -Xml $affectedNode -XPath "./*[local-name()='product']"
                if ($productNodes -and ((@($productNodes) | Measure-Object).Count) -gt 0) {
                    foreach ($productNode in $productNodes) {
                        $product = Get-InnerText $productNode
                        if ($currentOS -match [regex]::Escape($product)) {
                            $applicableDefinitions += $def
                            break
                        }
                    }
                } else {
                    # No platforms or products - include if family matched or wasn't specified
                    if (-not $familyAttr -or $familyAttr -eq 'windows') {
                        $applicableDefinitions += $def
                    }
                }
            }
        }
        
        $filteredCount = $definitionTotal - $applicableDefinitions.Count
        Write-Verbose "Filtered out $filteredCount non-applicable definitions (OS mismatch)"
        Write-Verbose "Evaluating $($applicableDefinitions.Count) applicable definitions"
        
        # Warn if all definitions were filtered out
        if ($applicableDefinitions.Count -eq 0 -and $definitionTotal -gt 0) {
            # Try to detect what platforms are actually in the definitions
            $detectedPlatforms = @()
            foreach ($def in $allDefinitions | Select-Object -First 20) {
                $affectedNode = Select-XmlNode -Xml $def -XPath "./*[local-name()='metadata']/*[local-name()='affected']"
                if ($affectedNode) {
                    $platformNodes = Select-XmlNodes -Xml $affectedNode -XPath "./*[local-name()='platform']"
                    foreach ($platformNode in $platformNodes) {
                        $platform = Get-InnerText $platformNode
                        if ($platform -and $platform -notin $detectedPlatforms) {
                            $detectedPlatforms += $platform
                        }
                    }
                }
            }
            
            $platformsDescription = if ($detectedPlatforms.Count -gt 0) {
                ($detectedPlatforms | Select-Object -First 3) -join ", "
            } else {
                "Unknown/Multiple platforms"
            }
            
            Write-Host "`n===============================================================================" -ForegroundColor Yellow
            Write-Host "WARNING: All $definitionTotal vulnerability definitions were filtered out" -ForegroundColor Yellow
            Write-Host "===============================================================================" -ForegroundColor Yellow
            Write-Host "Your OS: $currentOS" -ForegroundColor White
            Write-Host "Downloaded definitions target: $platformsDescription" -ForegroundColor White
            Write-Host "`nThis is expected behavior if you're on:" -ForegroundColor Cyan
            Write-Host "  • Windows 11" -ForegroundColor White
            Write-Host "  • Windows Server 2025, 2022, 2019, or 2016" -ForegroundColor White
            Write-Host "  • Any OS version that doesn't exactly match the definition's target platform" -ForegroundColor White
            
            Write-Host "`nRECOMMENDED SOLUTIONS:" -ForegroundColor Cyan
            Write-Host "`n1. Use MSRC (Best for Windows 11 and all Windows Server versions):" -ForegroundColor Green
            Write-Host "   Scan-Computer -ScanSourceType Download -ScanSource MSRC" -ForegroundColor Gray
            
            Write-Host "`n2. Use NVD with API key (Most comprehensive for all platforms):" -ForegroundColor Green
            Write-Host "   Scan-Computer -ScanSourceType Download -ScanSource NVD -NVDApiKey 'your-key'" -ForegroundColor Gray
            Write-Host "   Get free key: https://nvd.nist.gov/developers/request-an-api-key" -ForegroundColor DarkGray
            
            Write-Host "`n3. Skip platform filter (evaluate all definitions regardless of OS):" -ForegroundColor Green
            Write-Host "   Scan-Computer -ScanSourceType Download -ScanSource <source> -SkipPlatformFilter" -ForegroundColor Gray
            Write-Host "   Note: May have false positives if definitions target different OS" -ForegroundColor DarkGray
            
            Write-Host "`n4. Clear cache and retry (if using wrong cached source):" -ForegroundColor Green
            Write-Host "   Remove-Item `"$env:TEMP\PowerSCAP_Vulnerabilities_*`" -Recurse -Force" -ForegroundColor Gray
            
            Write-Host "`n===============================================================================" -ForegroundColor Yellow
        }
    } else {
        # SCAP mode - evaluate all definitions (SCAP files are already platform-specific)
        # Or SkipPlatformFilter specified - evaluate all definitions
        $applicableDefinitions = $allDefinitions
        if ($SkipPlatformFilter) {
            Write-Verbose "Platform filtering disabled - evaluating all $($allDefinitions.Count) definitions"
        }
    }
    
    $definitionTotal = $applicableDefinitions.Count

    foreach ($def in $applicableDefinitions) {
        $evalCount++
        $pct = [math]::Round(($evalCount / [double]$definitionTotal) * 100, 2)
        
        $targetName = if ([string]::IsNullOrWhiteSpace($ComputerName)) { $env:COMPUTERNAME } else { $ComputerName }
        $scanTypeLabel = if ($scanMode -eq 'SCAP') { "SCAP Compliance" } else { "Vulnerability" }
        
        Write-Progress -Activity "Scanning $targetName - $scanTypeLabel" `
                       -Status "Evaluating $evalCount of $definitionTotal definitions ($pct%)" `
                       -PercentComplete $pct

        $defIdAttr = $def.Attributes['id']
        $defId = if ($defIdAttr) { $defIdAttr.Value } else { $null }

        $title = Get-InnerText (Select-XmlNode -Xml $def -XPath "./*[local-name()='metadata']/*[local-name()='title']")
        $description = Get-InnerText (Select-XmlNode -Xml $def -XPath "./*[local-name()='metadata']/*[local-name()='description']")
        
        # Get definition class (compliance, vulnerability, patch, inventory)
        $classAttr = $def.Attributes['class']
        $defClass = if ($classAttr) { $classAttr.Value } else { 'unknown' }
        
        # Try to get severity from XCCDF first (more accurate), fallback to OVAL metadata
        $severity = $null
        $cveId = $null
        if ($defId -and $script:xccdfRules.ContainsKey($defId)) {
            $severity = $script:xccdfRules[$defId].Severity
            $cveId = if ($script:xccdfRules[$defId].ContainsKey('CVE')) { $script:xccdfRules[$defId].CVE } else { $null }
            if ($evalCount -le 3) {
                Write-Verbose "  DefID: $defId -> Severity from rules: $severity"
            }
        }
        # Fallback 1: match by numeric suffix (handles oval:mil.disa.stig.defs:def:NNNN
        # -> oval:mil.disa.stig.windows11:def:NNNN namespace mismatch)
        if (-not $severity -and $defId) {
            # Try multiple patterns to handle edge cases:
            # Pattern 1: :NNNN$ (e.g., oval:mil.disa.stig.defs:def:253254)
            # Pattern 2: :def:NNNN$ (e.g., oval:mil.disa.stig.windows11:def:1)
            $patterns = @(':(\d+)$', ':def:(\d+)$')
            
            foreach ($pattern in $patterns) {
                if ($severity) { break }  # Stop if we found severity
                
                $numMatch = [System.Text.RegularExpressions.Regex]::Match($defId, $pattern)
                if ($numMatch.Success) {
                    $numSuffix = $numMatch.Groups[1].Value
                    
                    # Try to match against xccdfRules keys
                    foreach ($key in $script:xccdfRules.Keys) {
                        # Check multiple ending patterns
                        if ($key.EndsWith(":$numSuffix") -or $key.EndsWith(":def:$numSuffix")) {
                            $severity = $script:xccdfRules[$key].Severity
                            $cveId = if ($script:xccdfRules[$key].ContainsKey('CVE')) { $script:xccdfRules[$key].CVE } else { $null }
                            if ($evalCount -le 3) {
                                Write-Verbose "  DefID: $defId -> Matched to $key via numeric suffix: $numSuffix"
                            }
                            break
                        }
                    }
                }
            }
        }
        # Fallback 2: Try namespace-agnostic matching (everything after last colon)
        # Handles cases like oval:com.vendor:def:123 -> oval:other.vendor:def:123
        if (-not $severity -and $defId -and $defId.Contains(':')) {
            $parts = $defId.Split(':')
            if ($parts.Count -ge 2) {
                $lastPart = $parts[-1]  # Get last part
                $secondLastPart = if ($parts.Count -ge 3) { $parts[-2] } else { $null }
                
                # Try matching on last two parts (e.g., "def:1")
                if ($secondLastPart) {
                    $searchSuffix = "$secondLastPart`:$lastPart"
                    foreach ($key in $script:xccdfRules.Keys) {
                        if ($key.EndsWith($searchSuffix)) {
                            $severity = $script:xccdfRules[$key].Severity
                            $cveId = if ($script:xccdfRules[$key].ContainsKey('CVE')) { $script:xccdfRules[$key].CVE } else { $null }
                            if ($evalCount -le 3) {
                                Write-Verbose "  DefID: $defId -> Matched to $key via suffix: $searchSuffix"
                            }
                            break
                        }
                    }
                }
            }
        }
        # Fallback 3: Direct lookup in OVAL metadata
        if (-not $severity) {
            $severity = Get-InnerText (Select-XmlNode -Xml $def -XPath "./*[local-name()='metadata']/*[local-name()='severity']")
            if ($evalCount -le 3 -and $severity) {
                Write-Verbose "  DefID: $defId -> Severity from OVAL metadata: $severity"
            }
            if ($evalCount -le 3 -and -not $severity) {
                Write-Verbose "  DefID: $defId -> No severity found"
            }
        }
        
        # Extract CVE from OVAL metadata if not already found
        # This is critical for standalone vulnerability OVAL files
        if (-not $cveId) {
            $refNode = Select-XmlNode -Xml $def -XPath "./*[local-name()='metadata']/*[local-name()='reference'][@source='CVE']"
            if ($refNode) {
                $cveId = Get-AttrValue -Node $refNode -Name 'ref_id'
                if ($evalCount -le 3 -and $cveId) {
                    Write-Verbose "  DefID: $defId -> CVE from OVAL metadata: $cveId"
                }
            }
        }
        
        # Also try alternate reference format (some OVAL files use different attributes)
        if (-not $cveId) {
            $refNodes = Select-XmlNodes -Xml $def -XPath "./*[local-name()='metadata']/*[local-name()='reference']"
            foreach ($ref in $refNodes) {
                $refUrl = Get-AttrValue -Node $ref -Name 'ref_url'
                $refId = Get-AttrValue -Node $ref -Name 'ref_id'
                # Check if reference contains CVE pattern
                if ($refUrl -match 'CVE-\d{4}-\d{4,}' -or $refId -match 'CVE-\d{4}-\d{4,}') {
                    $cveId = if ($refId -match 'CVE-\d{4}-\d{4,}') { $refId } else { [regex]::Match($refUrl, 'CVE-\d{4}-\d{4,}').Value }
                    if ($evalCount -le 3 -and $cveId) {
                        Write-Verbose "  DefID: $defId -> CVE extracted from reference: $cveId"
                    }
                    break
                }
            }
        }
        
        $criteria = Select-XmlNode -Xml $def -XPath "./*[local-name()='criteria']"

        $eval = Evaluate-Criteria -criteriaNode $criteria -DefinitionId $defId

        # For vulnerability definitions, invert the Pass logic
        # OVAL criteria describe the VULNERABLE state, so:
        #   - If criteria = TRUE → system IS vulnerable → should FAIL (Pass=$false)
        #   - If criteria = FALSE → system is NOT vulnerable → should PASS (Pass=$true)
        # For compliance definitions, keep original logic:
        #   - If criteria = TRUE → system IS compliant → should PASS (Pass=$true)
        #   - If criteria = FALSE → system is NOT compliant → should FAIL (Pass=$false)
        $passValue = [bool]$eval.Pass
        if ($defClass -eq 'vulnerability') {
            $passValue = -not $passValue
        }

        $obj = [PSCustomObject]@{
            RuleId      = $defId
            RuleTitle   = $title
            Description = $description
            Class       = $defClass
            Severity    = $severity
            CVE         = $cveId
            Pass        = $passValue
        }

        if ($IncludePerTestDetails) {
            $evidenceData = if ($eval -and $eval.Details) { $eval.Details } else { @() }
            $obj | Add-Member -NotePropertyName Evidence -NotePropertyValue $evidenceData
        }
        
        # Add source file for vulnerability scans
        if ($scanMode -ne 'SCAP' -and $definitionSources.ContainsKey($defId)) {
            $sourceFile = Split-Path -Leaf $definitionSources[$defId]
            $obj | Add-Member -NotePropertyName SourceFile -NotePropertyValue $sourceFile
        }

        $results += $obj
    }

    # Output
    $passResults = @($results | Where-Object { $_.Pass })
    $failResults = @($results | Where-Object { -not $_.Pass })
    $passCount = ((@($passResults) | Measure-Object).Count)
    $failCount = ((@($failResults) | Measure-Object).Count)
    $totalCount = ((@($results) | Measure-Object).Count)
    
    # For vulnerability scans: evaluation already inverted Pass (line 1396)
    # So Pass=true means NOT vulnerable, Pass=false means vulnerable
    $vulnerableResults = $failResults
    $notVulnerableResults = $passResults

    if ($OutputJson) {
        $results | ConvertTo-Json -Depth 6
    } elseif ($Output -eq 'CSV') {
        # Convert results to CSV format
        $results | ConvertTo-Csv -NoTypeInformation | Out-String
    } elseif ($Output -eq 'TSV') {
        # Convert results to TSV (tab-separated values) format
        if ($results -and $results.Count -gt 0) {
            $properties = ($results | Select-Object -First 1).PSObject.Properties.Name
            $header = $properties -join "`t"
            $lines = @($header)
            foreach ($result in $results) {
                $values = foreach ($prop in $properties) {
                    $value = $result.$prop
                    if ($null -eq $value) { '' } else { $value.ToString() }
                }
                $lines += ($values -join "`t")
            }
            $lines -join "`n"
        }
    } elseif ($LegacyOutput) {
        Write-Host "`n=== OVAL Registry Test Summary ===" -ForegroundColor Cyan
        # Note: testNodes may not be defined in vulnerability scan mode
        if ($script:tests.Count -gt 0) {
            foreach ($testId in $script:tests.Keys) {
                $test = $script:tests[$testId]
                if ($test.LocalName -like "*registry_test") {
                    $refs = Get-TestRefs -test $test
                    $objectRefId = $refs.objectRefId
                    $stateRefId  = $refs.stateRefId

                    if (-not $objectRefId) {
                        Write-Host "Test ID: $testId" -ForegroundColor Yellow
                        Write-Host "  (skipped: registry test missing object_ref)" -ForegroundColor DarkGray
                        Write-Host ""
                        continue
                    }

                    $obj = $null
                    if ($script:objects.ContainsKey($objectRefId)) { $obj = $script:objects[$objectRefId] }

                    if (-not $obj) {
                        Write-Host "Test ID: $testId" -ForegroundColor Yellow
                        Write-Host "  (object not found: $objectRefId)" -ForegroundColor Red
                        Write-Host ""
                        continue
                    }

                    $stateNode = $null
                    if ($stateRefId -and $script:states.ContainsKey($stateRefId)) { $stateNode = $script:states[$stateRefId] }

                    $hive = Get-InnerText (Select-XmlNode -Xml $obj -XPath "./*[local-name()='hive']")
                    $key  = Get-InnerText (Select-XmlNode -Xml $obj -XPath "./*[local-name()='key']")
                    $name = Get-InnerText (Select-XmlNode -Xml $obj -XPath "./*[local-name()='name']")

                    $valueNode = if ($stateNode) { Select-XmlNode -Xml $stateNode -XPath "./*[local-name()='value']" } else { $null }
                    $expected  = if ($valueNode) { Get-InnerText $valueNode } else { $null }
                    $operation = if ($valueNode) { Get-AttrValue -Node $valueNode -Name 'operation' } else { $null }
                    $datatype  = if ($valueNode) { Get-AttrValue -Node $valueNode -Name 'datatype' } else { $null }

                    if (-not $operation) { $operation = 'equals' }
                    if (-not $datatype)  { $datatype  = 'string' }

                    Write-Host "Test ID: $testId" -ForegroundColor Yellow
                    Write-Host "  Hive:      $hive"
                    Write-Host "  Key:       $key"
                    Write-Host "  Name:      $name"
                    Write-Host "  Expected:  $expected"
                    Write-Host "  Operation: $operation"
                    Write-Host "  Datatype:  $datatype"
                    Write-Host ""
                }
            }
        }

        if ($scanMode -eq 'SCAP') {
            Write-Host "`n=== SCAP Compliance Summary ===" -ForegroundColor Cyan
        } else {
            Write-Host "`n=== Vulnerability Scan Summary ===" -ForegroundColor Cyan
        }
        
        if ($scanMode -eq 'SCAP') {
            $results |
              Select-Object RuleId, @{n='Status'; e={ if ($_.Pass) { 'PASS' } else { 'FAIL' } }}, Severity, RuleTitle |
              Format-Table -AutoSize
        } else {
            # Vulnerability: evaluation already inverted Pass logic (line 1396)
            # So Pass=true means NOT vulnerable, Pass=false means vulnerable
            $results |
              Select-Object RuleId, @{n='Status'; e={ if ($_.Pass) { 'PASS' } else { 'FAIL' } }}, Severity, CVE, RuleTitle |
              Format-Table -AutoSize
        }

        if ($scanMode -ne 'SCAP') {
            Write-Host "`n=== Vulnerability Details ===" -ForegroundColor Yellow
        } else {
            Write-Host "`n=== Detailed Failure Information ===" -ForegroundColor Yellow
        }
        
        # Show failures (Pass=false) for both modes
        foreach ($result in $failResults) {
            Write-Host "`nRule: $($result.RuleId)" -ForegroundColor Red
            Write-Host "Title: $($result.RuleTitle)" -ForegroundColor Blue
            if ($result.CVE) {
                Write-Host "CVE: $($result.CVE)" -ForegroundColor Magenta
            }
            if ($result.Description) {
                Write-Host "Description: $($result.Description)" -ForegroundColor Gray
            }
            if ($result.Severity) {
                $severityColor = switch ($result.Severity.ToLower()) {
                    'high'     { 'Red' }
                    'critical' { 'Red' }
                    'medium'   { 'Yellow' }
                    'low'      { 'Green' }
                    default    { 'White' }
                }
                Write-Host "Severity: $($result.Severity.ToUpper())" -ForegroundColor $severityColor
            }
            if ($result.Evidence) { Print-EvidenceRecursive -Evidence $result.Evidence }
            else { Write-Host "  No detailed evidence available" -ForegroundColor DarkGray }
            Write-Host ("=" * 80) -ForegroundColor DarkGray
        }

        Write-Host "`n=== Final Summary ===" -ForegroundColor Cyan
        Write-Host "Total Rules Evaluated: $totalCount" -ForegroundColor White
        if ($scanMode -eq 'SCAP') {
            Write-Host "Compliant (PASS): $passCount" -ForegroundColor Green
            Write-Host "Non-Compliant (FAIL): $failCount" -ForegroundColor Red
        } else {
            # Evaluation already inverted Pass for vulnerabilities
            # Pass=true means NOT vulnerable, Pass=false means vulnerable
            Write-Host "Not Vulnerable (PASS): $passCount" -ForegroundColor Green
            Write-Host "Vulnerable (FAIL): $failCount" -ForegroundColor Red
        }
        if ($failCount -gt 0 -and $totalCount -gt 0) {
            $failureRate = [math]::Round(($failCount / $totalCount) * 100, 2)
            if ($scanMode -eq 'SCAP') {
                Write-Host "Failure Rate: $failureRate%" -ForegroundColor Yellow
            } else {
                Write-Host "Vulnerability Rate: $failureRate%" -ForegroundColor Yellow
            }
        }
    } else {
        if ($scanMode -eq 'SCAP') {
            Write-Host "`n=== SCAP Compliance Summary ===" -ForegroundColor Cyan
        } else {
            Write-Host "`n=== Vulnerability Scan Summary ===" -ForegroundColor Cyan
        }
        
        # Use same display logic for both - evaluation already inverted for vulnerabilities
        if ($scanMode -eq 'SCAP') {
            $results |
              Select-Object RuleId, @{n='Status'; e={ if ($_.Pass) { 'PASS' } else { 'FAIL' } }}, Severity |
              Format-Table -AutoSize
        } else {
            $results |
              Select-Object RuleId, @{n='Status'; e={ if ($_.Pass) { 'PASS' } else { 'FAIL' } }}, Severity, CVE |
              Format-Table -AutoSize
        }

        Write-Host "`nCompleted: $evalCount/$definitionTotal definitions" -ForegroundColor White
        Write-Host "PASS: $passCount, FAIL: $failCount" -ForegroundColor White

        if ($failCount -gt 0) {
            $failureRate = [math]::Round(($failCount / $totalCount) * 100, 2)
            if ($scanMode -eq 'SCAP') {
                Write-Host ("Failure Rate: {0}%" -f $failureRate) -ForegroundColor Yellow
                Write-Host "`nTop Failures (first 10):" -ForegroundColor Yellow
                $failResults | Select-Object -First 10 |
                  Select-Object RuleId, RuleTitle, Severity |
                  Format-Table -AutoSize
            } else {
                Write-Host ("Vulnerability Rate: {0}%" -f $failureRate) -ForegroundColor Yellow
                Write-Host "`nTop Vulnerabilities (first 10):" -ForegroundColor Yellow
                $failResults | Select-Object -First 10 |
                  Select-Object RuleId, CVE, RuleTitle, Severity |
                  Format-Table -AutoSize
            }
        }
    }

    if ($script:CimSession) {
        try { $script:CimSession | Remove-CimSession -ErrorAction SilentlyContinue } catch {}
        $script:CimSession = $null
    }
}
