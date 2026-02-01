
# PowerSCAP module
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Module-level initializations for StrictMode safety ---
# Globals used by helpers; ensure they exist even before first use
$script:AuditSubcategoryCache = $null
$script:CimSession            = $null

# --- Private components ---
. "$PSScriptRoot\Private\XmlHelpers.ps1"
. "$PSScriptRoot\Private\OvalCore.ps1"
. "$PSScriptRoot\Private\AuditHelpers.ps1"
. "$PSScriptRoot\Private\LocalAccounts.ps1"
. "$PSScriptRoot\Private\RegistryAndWmi.ps1"
. "$PSScriptRoot\Private\TestEvaluators.ps1"
. "$PSScriptRoot\Private\Criteria.ps1"
. "$PSScriptRoot\Private\Output.ps1"
. "$PSScriptRoot\Private\SqlHelpers.ps1"

# --- Public commands ---
. "$PSScriptRoot\Public\Scan-Computer.ps1"
. "$PSScriptRoot\Public\Scan-Domain.ps1"
. "$PSScriptRoot\Public\Scan-Database.ps1"
. "$PSScriptRoot\Public\Scan-SQLInstance.ps1"
. "$PSScriptRoot\Public\Scan-SQLDatabase.ps1"

Export-ModuleMember -Function Scan-Computer, Scan-Domain, Scan-Database, Scan-SQLInstance, Scan-SQLDatabase
