function Scan-Database {
    [CmdletBinding()]
    param(
        [string]$ConnectionString,
        [string]$InputJson
    )

    throw [System.NotImplementedException] "Scan-Database is not implemented yet. TODO: parse JSON, map schema, bulk-insert results."
}
