function Scan-Domain {
    [CmdletBinding()]
    param(
        [string]$DomainName,
        [System.Management.Automation.PSCredential]$Credential
    )

    throw [System.NotImplementedException] "Scan-Domain is not implemented yet. TODO: enumerate domain computers, orchestrate remote Scan-Computer calls, aggregate results."
}
