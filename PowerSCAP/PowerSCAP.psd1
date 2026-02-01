@{
    RootModule        = 'PowerSCAP.psm1'
    ModuleVersion     = '2.1.0'
    GUID              = '4654b0fe-0081-47cc-8920-274ac0e22c4f'
    Author            = 'Adam Corbett'
    CompanyName       = ''
    Copyright         = '(c) Adam Corbett. All rights reserved.'
    Description       = 'PowerSCAP - Modular SCAP/OVAL evaluator for Windows checks. Primary command: Scan-Computer.'
    PowerShellVersion = '7.0'
    FunctionsToExport = @('Scan-Computer','Scan-Domain','Scan-Database')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('SCAP','OVAL','Compliance','Windows')
        }
    }
}
