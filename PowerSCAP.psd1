@{
    RootModule        = 'PowerSCAP.psm1'
    ModuleVersion     = '2.2.0'
    GUID              = '4654b0fe-0081-47cc-8920-274ac0e22c4f'
    Author            = 'Adam Corbett'
    CompanyName       = ''
    Copyright         = '(c) Adam Corbett. All rights reserved.'
    Description       = 'PowerSCAP - Modular SCAP/OVAL evaluator for Windows and SQL Server STIG compliance. Commands: Scan-Computer, Scan-SQLInstance, Scan-SQLDatabase.'
    PowerShellVersion = '7.0'
    FunctionsToExport = @('Scan-Computer','Scan-Domain','Scan-Database','Scan-SQLInstance','Scan-SQLDatabase')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('SCAP','OVAL','Compliance','Windows','SQLServer','STIG')
        }
    }
}
