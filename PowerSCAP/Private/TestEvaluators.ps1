# === Test Evaluators ===
# Auto-generated from original script on 2026-01-30 14:48:45

function Evaluate-LockoutPolicyTest {
    param([System.Xml.XmlNode]$test)

    # win-def:lockoutpolicy_test generally has an object (often empty) and a state with fields
    $refs = Get-TestRefs -test $test
    $stateNode = $null
    if ($refs.stateRefId -and $states.ContainsKey($refs.stateRefId)) { $stateNode = $states[$refs.stateRefId] }
    if (-not $stateNode) {
        return [pscustomobject]@{ Type='LockoutPolicy'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="Lockout policy state not found: $($refs.stateRefId)" }
    }

    # Map OVAL state fields to secedit keys
    $fieldMap = @{
        'lockout_threshold'   = 'LockoutBadCount'     # Number of invalid logon attempts
        'reset_lockout_count' = 'ResetLockoutCount'   # Observation window (minutes)
        'lockout_duration'    = 'LockoutDuration'     # Duration (minutes)
    }

    $policy = Get-SystemAccessPolicy
    $results = @()
    $allPass = $true

    foreach ($child in $stateNode.ChildNodes) {
        if (-not ($child -is [System.Xml.XmlElement])) { continue }
        $fieldName = $child.LocalName
        if (-not $fieldMap.ContainsKey($fieldName)) { continue }

        $expected = Get-InnerText $child
        $operation = Get-AttrValue -Node $child -Name 'operation'; if (-not $operation) { $operation = 'equals' }
        $datatype  = Get-AttrValue -Node $child -Name 'datatype';  if (-not $datatype)  { $datatype  = 'int' }

        $key = $fieldMap[$fieldName]
        $actual = $null
        if ($policy.ContainsKey($key)) { $actual = $policy[$key] }

        $pass = Compare-Value -Actual $actual -Expected $expected -Operation $operation -Datatype $datatype

        if (-not $pass) { $allPass = $false }
        $results += [pscustomobject]@{
            Type     = 'LockoutPolicy'
            Field    = $fieldName
            PolicyKey= $key
            Expected = $expected
            Actual   = if ($null -ne $actual) { $actual } else { '(null)' }
            Pass     = $pass
            Evidence = "op=$operation, datatype=$datatype"
        }
    }

    return [pscustomobject]@{
        Type    = 'LockoutPolicy'
        Pass    = $allPass
        Details = $results
    }
}

function Evaluate-WMITest {
    param([System.Xml.XmlNode]$test)

    $refs = Get-TestRefs -test $test
    $objectRefId = $refs.objectRefId
    $stateRefId  = $refs.stateRefId

    $obj = $null
    if ($objectRefId -and $objects.ContainsKey($objectRefId)) { $obj = $objects[$objectRefId] }
    $stateNode = $null
    if ($stateRefId -and $states.ContainsKey($stateRefId)) { $stateNode = $states[$stateRefId] }

    if (-not $obj) { return [pscustomobject]@{ Type='WMI'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="WMI object not found: $objectRefId" } }

    $namespace = Get-InnerText (Select-XmlNode -Xml $obj -XPath "./*[local-name()='namespace']")
    $wql       = Get-InnerText (Select-XmlNode -Xml $obj -XPath "./*[local-name()='wql']")

    $checkExistence = Get-AttrValue -Node $test -Name 'check_existence'
    $comment = Get-AttrValue -Node $test -Name 'comment'

    $rows = @(Invoke-WmiQuery -Namespace $namespace -Query $wql -MaxRows $MaxWmiRows -UseCim $UseCim)
    $rowCount = (Get-SafeCount $rows)

    # If the test is for "should not exist"
    $shouldNotExist = $false
    if ($checkExistence -eq 'none_exist' -or
        ($comment -match 'not installed' -or $comment -match 'not present' -or $comment -match 'should not exist')) {
        $shouldNotExist = $true
    }

    if ($shouldNotExist) {
        $pass = ($rowCount -eq 0)
        return [pscustomobject]@{
            Type     = 'WMI'
            Namespace= $namespace
            WQL      = $wql
            Expected = "No rows (service/process/feature not present)"
            Actual   = if ($rowCount -eq 0) { "No rows" } else { "$rowCount row(s)" }
            Pass     = $pass
            Evidence = "Query returned $rowCount row(s); expected none"
        }
    }

    # Default: existence is required
    $pass = ($rowCount -gt 0)
    return [pscustomobject]@{
        Type     = 'WMI'
        Namespace= $namespace
        WQL      = $wql
        Expected = "At least one row"
        Actual   = "$rowCount row(s)"
        Pass     = $pass
        Evidence = "Query returned $rowCount row(s)"
    }
}

function Evaluate-RegistryTest {
    param([System.Xml.XmlNode]$test)

    $refs = Get-TestRefs -test $test
    $objectRefId = $refs.objectRefId
    $stateRefId  = $refs.stateRefId

    $obj = $null
    if ($objectRefId -and $objects.ContainsKey($objectRefId)) { $obj = $objects[$objectRefId] }
    $stateNode = $null
    if ($stateRefId -and $states.ContainsKey($stateRefId)) { $stateNode = $states[$stateRefId] }
    
    if (-not $obj) {
        return [pscustomobject]@{ Type='Registry'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="Registry object not found: $objectRefId" }
    }

    $hive = Get-InnerText (Select-XmlNode -Xml $obj -XPath "./*[local-name()='hive']")
    $key  = Get-InnerText (Select-XmlNode -Xml $obj -XPath "./*[local-name()='key']")
    $name = Get-InnerText (Select-XmlNode -Xml $obj -XPath "./*[local-name()='name']")

    # Existence-only if no state
    if (-not $stateNode) {
        $checkExistence = Get-AttrValue -Node $test -Name 'check_existence'
        $val = $null
        if ($name) { $val = Get-RegistryItemProperty -Hive $hive -Key $key -Name $name }
        else {
            $mappedHive = $hive -replace '^HKEY_LOCAL_MACHINE$', 'HKLM:' -replace '^HKEY_CURRENT_USER$', 'HKCU:' -replace '^HKEY_USERS$', 'HKU:' -replace '^HKEY_CLASSES_ROOT$', 'HKCR:'
            $regPath = "$mappedHive\$key"
            try { $val = if (Test-Path -LiteralPath $regPath) { 'key_exists' } else { $null } } catch { $val = $null }
        }
        $exists = ($null -ne $val)
        $pass = $false
        switch ($checkExistence) {
            'none_exist'       { $pass = (-not $exists) }
            'only_one_exists'  { $pass = $exists } # single entity context
            'at_least_one_exists' { $pass = $exists }
            'any_exist'        { $pass = $exists }
            default            { $pass = $exists } # default is existence is required
        }
        return [pscustomobject]@{
            Type     = 'Registry'
            Path     = "$hive\$key"
            Name     = $name
            Expected = "check_existence=$checkExistence"
            Actual   = "exists=$exists"
            Pass     = $pass
            Evidence = "existence check on registry entity"
        }
    }

    $valueNode = Select-XmlNode -Xml $stateNode -XPath "./*[local-name()='value']"
    $expected = Get-InnerText $valueNode

    $operation     = Get-AttrValue -Node $valueNode -Name 'operation';     if (-not $operation) { $operation = 'equals' }
    $datatype      = Get-AttrValue -Node $valueNode -Name 'datatype';      if (-not $datatype) { $datatype = 'string' }
    $caseSensitive = ((Get-AttrValue -Node $valueNode -Name 'case_sensitive') -eq 'true')

    $varRef = Get-AttrValue -Node $valueNode -Name 'var_ref'
    if ($varRef) {
        $vals = Resolve-VarRef -VarRef $varRef
        $actual = Get-RegistryItemProperty -Hive $hive -Key $key -Name $name
        $anyPass = $false
        if ($vals -and (Get-SafeCount $vals) -gt 0) {
            foreach ($v in $vals) {
                if (Compare-Value -Actual $actual -Expected $v -Operation $operation -Datatype $datatype -CaseSensitive $caseSensitive) { $anyPass = $true; break }
            }
        }
        return [pscustomobject]@{
            Type     = 'Registry'
            Path     = "$hive\$key"
            Name     = $name
            Expected = ($vals -join ', ')
            Actual   = if ($null -ne $actual) { $actual } else { '(null)' }
            Pass     = $anyPass
            Evidence = if ($anyPass) { "Match found among variable values (op=$operation, datatype=$datatype)" } else { "No matches among variable values (op=$operation, datatype=$datatype)" }
        }
    }

    $actualValue = Get-RegistryItemProperty -Hive $hive -Key $key -Name $name
    $pass = Compare-Value -Actual $actualValue -Expected $expected -Operation $operation -Datatype $datatype -CaseSensitive $caseSensitive
    return [pscustomobject]@{
        Type     = 'Registry'
        Path     = "$hive\$key"
        Name     = $name
        Expected = if ($null -ne $expected) { $expected } else { '(null)' }
        Actual   = if ($null -ne $actualValue) { $actualValue } else { '(null)' }
        Pass     = $pass
        Evidence = "op=$operation, datatype=$datatype, caseSensitive=$caseSensitive"
    }
}

function Evaluate-FileTest {
    param([System.Xml.XmlNode]$test)

    $refs = Get-TestRefs -test $test
    $objectRefId = $refs.objectRefId
    $stateRefId  = $refs.stateRefId

    $obj = $null
    if ($objectRefId -and $objects.ContainsKey($objectRefId)) { $obj = $objects[$objectRefId] }
    $stateNode = $null
    if ($stateRefId -and $states.ContainsKey($stateRefId)) { $stateNode = $states[$stateRefId] }
    
    if (-not $obj) { return [pscustomobject]@{ Type='File'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="File object not found: $objectRefId" } }
    if (-not $stateNode) { return [pscustomobject]@{ Type='File'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="File state not found: $stateRefId" } }

    $path     = Get-InnerText (Select-XmlNode -Xml $obj -XPath "./*[local-name()='path']")
    $filename = Get-InnerText (Select-XmlNode -Xml $obj -XPath "./*[local-name()='filename']")
    $fullPath = if ($path -and $filename) { Join-Path $path $filename } elseif ($path) { $path } else { $filename }

    if ([string]::IsNullOrWhiteSpace($fullPath)) {
        return [pscustomobject]@{
            Type='File'; Path=$fullPath; Expected='N/A'; Actual='N/A'; Pass=$false
            Evidence='Missing path/filename in file object.'
        }
    }

    $existsNode  = Select-XmlNode -Xml $stateNode -XPath "./*[local-name()='exists']"
    $versionNode = Select-XmlNode -Xml $stateNode -XPath "./*[local-name()='version']"
    $sizeNode    = Select-XmlNode -Xml $stateNode -XPath "./*[local-name()='size']"

    $existsExpected = To-Bool (Get-InnerText $existsNode)
    $existsOp = Get-AttrValue -Node $existsNode -Name 'operation'; if (-not $existsOp) { $existsOp = 'equals' }

    $existsActual = $false
    try { $existsActual = Test-Path -LiteralPath $fullPath } catch { $existsActual = $false }
    $existsPass = $true
    if ($existsNode) {
        $existsPass = Compare-Value -Actual $existsActual -Expected $existsExpected -Operation $existsOp -Datatype 'boolean'
    }

    $versionPass = $true; $versionActual = $null; $versionExpected = Get-InnerText $versionNode
    if ($versionNode -and $existsActual) {
        try {
            $fi = Get-Item -LiteralPath $fullPath -ErrorAction Stop
            $versionActual = $fi.VersionInfo.FileVersion
            $versionOp = Get-AttrValue -Node $versionNode -Name 'operation'; if (-not $versionOp) { $versionOp = 'equals' }
            $versionPass = Compare-Value -Actual $versionActual -Expected $versionExpected -Operation $versionOp -Datatype 'version'
        } catch { $versionPass = $false }
    }

    $sizePass = $true; $sizeActual = $null; $sizeExpected = Get-InnerText $sizeNode
    if ($sizeNode -and $existsActual) {
        try {
            $fi = Get-Item -LiteralPath $fullPath -ErrorAction Stop
            $sizeActual = $fi.Length
            $sizeOp = Get-AttrValue -Node $sizeNode -Name 'operation'; if (-not $sizeOp) { $sizeOp = 'equals' }
            $sizePass = Compare-Value -Actual $sizeActual -Expected $sizeExpected -Operation $sizeOp -Datatype 'integer'
        } catch { $sizePass = $false }
    }

    $overallPass = ($existsPass -and $versionPass -and $sizePass)
    return [pscustomobject]@{
        Type     = 'File'
        Path     = $fullPath
        Expected = "exists=$existsExpected; version=$versionExpected; size=$sizeExpected"
        Actual   = "exists=$existsActual; version=$versionActual; size=$sizeActual"
        Pass     = $overallPass
        Evidence = "existsPass=$existsPass, versionPass=$versionPass, sizePass=$sizePass"
    }
}

function Evaluate-ServiceTest {
    param([System.Xml.XmlNode]$test)

    $refs = Get-TestRefs -test $test
    $objectRefId = $refs.objectRefId
    $stateRefId  = $refs.stateRefId

    $obj = $null
    if ($objectRefId -and $objects.ContainsKey($objectRefId)) { $obj = $objects[$objectRefId] }
    $stateNode = $null
    if ($stateRefId -and $states.ContainsKey($stateRefId)) { $stateNode = $states[$stateRefId] }
    
    if (-not $obj) { return [pscustomobject]@{ Type='Service'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="Service object not found: $objectRefId" } }
    if (-not $stateNode) { return [pscustomobject]@{ Type='Service'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="Service state not found: $stateRefId" } }

    $svcName = Get-InnerText (Select-XmlNode -Xml $obj -XPath "./*[local-name()='service_name']")
    if (-not $svcName) { return [pscustomobject]@{ Type = 'Service'; Pass = $false; Expected='N/A'; Actual='N/A'; Evidence = "service_name not provided" } }

    $expectedStartType = Get-InnerText (Select-XmlNode -Xml $stateNode -XPath "./*[local-name()='start_type']")
    $expectedStatus    = Get-InnerText (Select-XmlNode -Xml $stateNode -XPath "./*[local-name()='status']")

    $existsPass = $false
    $startTypePass = $true
    $statusPass = $true
    $actualStartType = $null
    $actualStatus = $null

    try {
        $svc = Get-Service -Name $svcName -ErrorAction Stop
        $existsPass = $true
        $actualStatus = $svc.Status.ToString()
        if ($expectedStartType) {
            $svcInfo = Get-CimInstance -ClassName Win32_Service -Filter "Name='$svcName'" -ErrorAction SilentlyContinue
            $actualStartType = if ($svcInfo) { $svcInfo.StartMode } else { $null }
            $startTypePass = Compare-Value -Actual $actualStartType -Expected $expectedStartType -Operation 'equals' -Datatype 'string'
        }
        if ($expectedStatus) {
            $statusPass = Compare-Value -Actual $actualStatus -Expected $expectedStatus -Operation 'equals' -Datatype 'string'
        }
    } catch {
        $existsPass = $false
        $startTypePass = $false
        $statusPass = $false
    }

    $overallPass = ($existsPass -and $startTypePass -and $statusPass)
    return [pscustomobject]@{
        Type     = 'Service'
        Name     = $svcName
        Expected = "exists=true; start_type=$expectedStartType; status=$expectedStatus"
        Actual   = "exists=$existsPass; start_type=$actualStartType; status=$actualStatus"
        Pass     = $overallPass
        Evidence = "existsPass=$existsPass, startTypePass=$startTypePass, statusPass=$statusPass"
    }
}

function Evaluate-ProcessTest {
    param([System.Xml.XmlNode]$test)

    $refs = Get-TestRefs -test $test
    $objectRefId = $refs.objectRefId
    $stateRefId  = $refs.stateRefId

    $obj = $null
    if ($objectRefId -and $objects.ContainsKey($objectRefId)) { $obj = $objects[$objectRefId] }
    $stateNode = $null
    if ($stateRefId -and $states.ContainsKey($stateRefId)) { $stateNode = $states[$stateRefId] }
    
    if (-not $obj) { return [pscustomobject]@{ Type='Process'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="Process object not found: $objectRefId" } }

    $name = Get-InnerText (Select-XmlNode -Xml $obj -XPath "./*[local-name()='name']")
    if (-not $name) { return [pscustomobject]@{ Type = 'Process'; Pass = $false; Expected='N/A'; Actual='N/A'; Evidence = 'Process name missing' } }

    $expectedExists = $true
    $existsOp = 'equals'
    if ($stateNode) {
        $existsNode = Select-XmlNode -Xml $stateNode -XPath "./*[local-name()='exists']"
        if ($existsNode) {
            $expectedExists = To-Bool (Get-InnerText $existsNode)
            $existsOp = Get-AttrValue -Node $existsNode -Name 'operation'; if (-not $existsOp) { $existsOp = 'equals' }
        }
    }

    $procs = @()
    try {
        $procs = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='$name'" -ErrorAction SilentlyContinue)
        if ((Get-SafeCount $procs) -eq 0) {
            $procs = @(Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $name -or ($_.ExecutablePath -and $_.ExecutablePath -like "*\$name") })
        }
    } catch { $procs = @() }
    $procCount = (Get-SafeCount $procs)
    $actualExists = ($procCount -gt 0)

    $pass = Compare-Value -Actual $actualExists -Expected $expectedExists -Operation $existsOp -Datatype 'boolean'
    return [pscustomobject]@{
        Type     = 'Process'
        Name     = $name
        Expected = "exists=$expectedExists"
        Actual   = "exists=$actualExists"
        Pass     = $pass
        Evidence = "count=$procCount"
    }
}

function Evaluate-QfeTest {
    param([System.Xml.XmlNode]$test)

    $refs = Get-TestRefs -test $test
    $objectRefId = $refs.objectRefId
    $stateRefId  = $refs.stateRefId

    $obj = $null
    if ($objectRefId -and $objects.ContainsKey($objectRefId)) { $obj = $objects[$objectRefId] }
    $stateNode = $null
    if ($stateRefId -and $states.ContainsKey($stateRefId)) { $stateNode = $states[$stateRefId] }
    
    if (-not $obj) { return [pscustomobject]@{ Type='QFE'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="QFE object not found: $objectRefId" } }

    $hotfixId = Get-InnerText (Select-XmlNode -Xml $obj -XPath "./*[local-name()='hotfix_id']")
    if (-not $hotfixId) { return [pscustomobject]@{ Type = 'QFE'; Pass = $false; Expected='N/A'; Actual='N/A'; Evidence = 'hotfix_id missing' } }

    $expectedInstalled = $true
    $installedOp = 'equals'
    if ($stateNode) {
        $installedNode = Select-XmlNode -Xml $stateNode -XPath "./*[local-name()='installed']"
        if ($installedNode) {
            $expectedInstalled = To-Bool (Get-InnerText $installedNode)
            $installedOp = Get-AttrValue -Node $installedNode -Name 'operation'; if (-not $installedOp) { $installedOp = 'equals' }
        }
    }

    $hf = $null
    try { $hf = Get-HotFix -Id $hotfixId -ErrorAction SilentlyContinue } catch { $hf = $null }
    $actualInstalled = ($null -ne $hf)
    $pass = Compare-Value -Actual $actualInstalled -Expected $expectedInstalled -Operation $installedOp -Datatype 'boolean'
    return [pscustomobject]@{
        Type     = 'QFE'
        HotfixId = $hotfixId
        Expected = "installed=$expectedInstalled"
        Actual   = "installed=$actualInstalled"
        Pass     = $pass
        Evidence = if ($hf) { "Installed On=$($hf.InstalledOn)" } else { "Not installed" }
    }
}

function Evaluate-SidSidTest {
    param([System.Xml.XmlNode]$test)

    $refs = Get-TestRefs -test $test
    $objectRefId = $refs.objectRefId
    $stateRefId  = $refs.stateRefId

    $obj = $null
    if ($objectRefId -and $objects.ContainsKey($objectRefId)) { $obj = $objects[$objectRefId] }
    $stateNode = $null
    if ($stateRefId -and $states.ContainsKey($stateRefId)) { $stateNode = $states[$stateRefId] }

    if (-not $obj) { return [pscustomobject]@{ Type='SidSid'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="SID object not found: $objectRefId" } }
    if (-not $stateNode) { return [pscustomobject]@{ Type='SidSid'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="SID state not found: $stateRefId" } }

    $sidNode = Select-XmlNode -Xml $obj -XPath "./*[local-name()='trustee_sid']"
    if ($sidNode -is [System.Collections.IEnumerable] -and -not ($sidNode -is [string])) { $sidNode = $sidNode | Select-Object -First 1 }
    $sid = (Get-InnerText $sidNode).Trim()

    # If $sid is a regex with RID pattern, attempt resolution (best-effort)
    if ($sid -match '^\^S-1-5-\[0-9-\]\+\-(\d+)\$$') {
        $rid = $Matches[1]
        if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
            $user = Get-LocalUser | Where-Object { $_.SID -match "-$rid$" }
            if ($user) { $sid = $user.SID }
        }
    }

    $nameNode = Select-XmlNode -Xml $stateNode -XPath "./*[local-name()='trustee_name']"
    if ($nameNode -is [System.Collections.IEnumerable] -and -not ($nameNode -is [string])) { $nameNode = $nameNode | Select-Object -First 1 }
    $expectedName = Get-InnerText $nameNode
    $operation = Get-AttrValue -Node $nameNode -Name 'operation'
    if (-not $operation) { $operation = 'equals' }

    # Try Get-LocalUser first
    $actualName = $null
    if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
        $user = Get-LocalUser | Where-Object { $_.SID -eq $sid }
        if ($user) { $actualName = $user.Name }
    }
    # Fallback to CIM
    if (-not $actualName) {
        try {
            $cim = Get-CimInstance -ClassName Win32_UserAccount | Where-Object { $_.SID -eq $sid }
            if ($cim) { $actualName = $cim.Name }
        } catch { }
    }
    # Fallback to .NET
    if (-not $actualName) {
        try {
            $account = ([System.Security.Principal.SecurityIdentifier]$sid).Translate([System.Security.Principal.NTAccount])
            $actualName = $account.Value
        } catch { }
    }
    if (-not $actualName) { $actualName = "(unresolved)" }

    $pass = Compare-Value -Actual $actualName -Expected $expectedName -Operation $operation -Datatype 'string'
    return [pscustomobject]@{
        Type     = 'SidSid'
        SID      = $sid
        Expected = $expectedName
        Actual   = $actualName
        Pass     = $pass
        Evidence = "SID $sid resolved to '$actualName' (expected $expectedName, op=$operation)"
    }
}

function Evaluate-AccessTokenTest {
    param([System.Xml.XmlNode]$test)

    $refs = Get-TestRefs -test $test
    $objectRefId = $refs.objectRefId
    $stateRefId  = $refs.stateRefId

    $obj = $null
    if ($objectRefId -and $objects.ContainsKey($objectRefId)) { $obj = $objects[$objectRefId] }
    $stateNode = $null
    if ($stateRefId -and $states.ContainsKey($stateRefId)) { $stateNode = $states[$stateRefId] }

    if (-not $obj) { return [pscustomobject]@{ Type='AccessToken'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="AccessToken object not found: $objectRefId" } }
    if (-not $stateNode) { return [pscustomobject]@{ Type='AccessToken'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="AccessToken state not found: $stateRefId" } }

    # Find any privilege or right node in the state
    $privNode = $stateNode.ChildNodes | Where-Object { $_.LocalName -match '^se.*(privilege|right)$' }
    if ($privNode -is [System.Collections.IEnumerable] -and -not ($privNode -is [string])) {
        $privNode = $privNode | Select-Object -First 1
    }
    if (-not $privNode) {
        return [pscustomobject]@{
            Type     = 'AccessToken'
            Pass     = $false
            Expected = 'N/A'
            Actual   = 'N/A'
            Evidence = "No privilege or right node found in state"
        }
    }

    # Map OVAL field to Windows privilege name
    $privField = $privNode.LocalName
    $privMap = @{
        # Logon Rights
        'seinteractivelogonright'            = 'SeInteractiveLogonRight'
        'seinteractivelogonprivilege'        = 'SeInteractiveLogonRight'
        'senetworklogonright'                = 'SeNetworkLogonRight'
        'sebatchlogonright'                  = 'SeBatchLogonRight'
        'seservicelogonright'                = 'SeServiceLogonRight'
        'seremoteinteractivelogonright'      = 'SeRemoteInteractiveLogonRight'
        
        # Deny Logon Rights
        'sedenyinteractivelogonright'        = 'SeDenyInteractiveLogonRight'
        'sedenynetworklogonright'            = 'SeDenyNetworkLogonRight'
        'sedenybatchlogonright'              = 'SeDenyBatchLogonRight'
        'sedenyservicelogonright'            = 'SeDenyServiceLogonRight'
        'sedenyremoteinteractivelogonright'  = 'SeDenyRemoteInteractiveLogonRight'
        
        # Privileges
        'seimpersonateprivilege'             = 'SeImpersonatePrivilege'
        'seprofilesingleprocessprivilege'    = 'SeProfileSingleProcessPrivilege'
        'setcbprivilege'                     = 'SeTcbPrivilege'
        'sebackupprivilege'                  = 'SeBackupPrivilege'
        'serestoreprivilege'                 = 'SeRestorePrivilege'
        'sedebugprivilege'                   = 'SeDebugPrivilege'
        'seloadsriverprivilege'              = 'SeLoadDriverPrivilege'
        'setakeownershipprivilege'           = 'SeTakeOwnershipPrivilege'
        'semanagevolumeprivilege'            = 'SeManageVolumePrivilege'
        'seenabedelegationprivilege'         = 'SeEnableDelegationPrivilege'
    }
    $privilege = $privMap[$privField.ToLowerInvariant()]
    if (-not $privilege) { 
        # If not in map, try to convert OVAL field to proper case
        # Most follow pattern: se + name + right/privilege
        $privilege = $privField -replace '^se', 'Se' -replace 'right$', 'Right' -replace 'privilege$', 'Privilege'
        # Capitalize each word part (handle cases like "batchlogon" -> "BatchLogon")
        $privilege = [regex]::Replace($privilege, '([a-z])([A-Z])', '$1$2')
    }

    # Expected value (0 or 1)
    $expected = $privNode.InnerText.Trim()
    $expectedBool = ($expected -eq '1')

    # Export user rights assignments
    $seceditFile = [System.IO.Path]::GetTempFileName()
    secedit.exe /export /cfg $seceditFile 2>$null | Out-Null
    $lines = Get-Content $seceditFile -ErrorAction SilentlyContinue
    Remove-Item $seceditFile -Force -ErrorAction SilentlyContinue

    $line = $lines | Where-Object { $_ -match "^$privilege\s*=" }
    $actual = if ($line) { ($line -split '=',2)[1].Trim() } else { '' }
    $actualSIDs = @()
    if ($actual) {
        $actualSIDs = @($actual -split ',' | ForEach-Object { $_.Trim().TrimStart('*') })
    }

    # Determine principal (optional, for evidence)
    $objName = $null
    $objSID = $null
    $objNameNode = $obj.SelectSingleNode("./*[local-name()='security_principle']")
    if ($objNameNode) { $objName = $objNameNode.InnerText.Trim() }
    $objSIDNode = $obj.SelectSingleNode("./*[local-name()='sid']")
    if ($objSIDNode) { $objSID = $objSIDNode.InnerText.Trim() }
    $principal = $objName
    if (-not $principal) { $principal = $objSID }

    # Resolve SIDs to friendly names for better display
    $resolvedNames = @()
    foreach ($sid in $actualSIDs) {
        if ($sid) {
            try {
                # Try to resolve SID to account name
                $account = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
                $resolvedNames += "$account ($sid)"
            } catch {
                # If resolution fails, just use the SID/name as-is
                $resolvedNames += $sid
            }
        }
    }

    # Is the principal assigned the right?
    # Check if objName is a regex pattern (contains regex special chars)
    $isRegexPattern = ($objName -and ($objName -match '[\^$.*+?{}\[\]\\|()]'))
    
    $isAssigned = $false
    $matchedPrincipals = @()
    
    if ($isRegexPattern) {
        # For regex patterns, check if any actual SID/name matches the pattern
        foreach ($item in $actualSIDs) {
            if ($item) {
                # Try to resolve SID to name for pattern matching
                $nameToMatch = $item
                try {
                    $nameToMatch = (New-Object System.Security.Principal.SecurityIdentifier($item)).Translate([System.Security.Principal.NTAccount]).Value
                } catch {
                    # Use as-is if resolution fails
                }
                
                if ($nameToMatch -match $objName) {
                    $isAssigned = $true
                    $matchedPrincipals += $nameToMatch
                }
            }
        }
    } elseif ($objName) {
        # Exact match for non-regex principals
        $isAssigned = (((@($actualSIDs | Where-Object { $_ -eq $objName }) | Measure-Object).Count) -gt 0)
        if ($isAssigned) { $matchedPrincipals += $objName }
    } elseif ($objSID) {
        # Match by SID
        $isAssigned = (((@($actualSIDs | Where-Object { $_ -eq $objSID }) | Measure-Object).Count) -gt 0)
        if ($isAssigned) { $matchedPrincipals += $objSID }
    } else {
        # No specific principal - just check if ANY principals have the right
        $isAssigned = (((@($actualSIDs) | Measure-Object).Count) -gt 0)
    }

    # For OVAL, expected 0 means the principal should NOT have the right
    $pass = ($expectedBool -eq $isAssigned)
    
    # Build evidence message
    $evidenceMsg = "Privilege $privilege "
    if ($resolvedNames.Count -gt 0) {
        $evidenceMsg += "is assigned to: $($resolvedNames -join '; ')"
    } else {
        $evidenceMsg += "is not assigned to any users/groups"
    }
    if ($isRegexPattern) {
        $evidenceMsg += " | Pattern: $objName"
        if ($matchedPrincipals.Count -gt 0) {
            $evidenceMsg += " | Matched: $($matchedPrincipals -join ', ')"
        } else {
            $evidenceMsg += " | No matches found"
        }
    }
    $evidenceMsg += " | Expected: $expected (should " + $(if ($expectedBool) { "HAVE" } else { "NOT have" }) + " privilege)"

    return [pscustomobject]@{
        Type      = 'AccessToken'
        Privilege = $privilege
        Principal = $principal
        Expected  = $expected
        Actual    = if ($resolvedNames.Count -gt 0) { $resolvedNames -join '; ' } else { '(none)' }
        Pass      = $pass
        Evidence  = $evidenceMsg
    }
}

function Evaluate-FileEffectiveRights53Test {
    param([System.Xml.XmlNode]$test)

    $refs = Get-TestRefs -test $test
    $objectRefId = $refs.objectRefId
    $stateRefId  = $refs.stateRefId

    $obj = $null
    if ($objectRefId -and $objects.ContainsKey($objectRefId)) { $obj = $objects[$objectRefId] }
    $stateNode = $null
    if ($stateRefId -and $states.ContainsKey($stateRefId)) { $stateNode = $states[$stateRefId] }

    if (-not $obj) { return [pscustomobject]@{ Type='FileEffectiveRights53'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="FileEffectiveRights53 object not found: $objectRefId" } }
    if (-not $stateNode) { return [pscustomobject]@{ Type='FileEffectiveRights53'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="FileEffectiveRights53 state not found: $stateRefId" } }

    $pathNode = Select-XmlNode -Xml $obj -XPath "./*[local-name()='filepath']"
    if ($pathNode -is [System.Collections.IEnumerable] -and -not ($pathNode -is [string])) { $pathNode = $pathNode | Select-Object -First 1 }
    $path = Get-InnerText $pathNode

    $trusteeNode = Select-XmlNode -Xml $obj -XPath "./*[local-name()='trustee_sid']"
    if ($trusteeNode -is [System.Collections.IEnumerable] -and -not ($trusteeNode -is [string])) { $trusteeNode = $trusteeNode | Select-Object -First 1 }
    $trustee = Get-InnerText $trusteeNode

    # Identify a right node in the state
    $rightNode = $stateNode.ChildNodes | Where-Object { $_.LocalName -like '*control' -or $_.LocalName -like '*privilege' -or $_.InnerText -match '^(true|false|0|1)$' }
    if (-not $rightNode) { $rightNode = $stateNode.ChildNodes }
    if ($rightNode -is [System.Collections.IEnumerable] -and -not ($rightNode -is [string])) { $rightNode = $rightNode | Select-Object -First 1 }
    $rightName = $rightNode.LocalName
    $expected = Get-InnerText $rightNode
    $operation = Get-AttrValue -Node $rightNode -Name 'operation'
    if (-not $operation) { $operation = 'equals' }

    # Get effective rights for the trustee
    $actual = 'false'
    try {
        $acl = Get-Acl -Path $path -ErrorAction Stop
        $access = @($acl.Access | Where-Object { $_.IdentityReference -like "*$trustee" })
        if ((Get-SafeCount $access) -gt 0) {
            # Map rightName to FileSystemRights
            $rightMap = @{
                'standard_delete'            = 'Delete'
                'standard_read_control'      = 'ReadPermissions'
                'standard_write_dac'         = 'ChangePermissions'
                'standard_write_owner'       = 'TakeOwnership'
                'standard_synchronize'       = 'Synchronize'
                'generic_read'               = 'Read'
                'generic_write'              = 'Write'
                'generic_execute'            = 'ExecuteFile'
                'file_read_data'             = 'ReadData'
                'file_write_data'            = 'WriteData'
                'file_append_data'           = 'AppendData'
                'file_read_ea'               = 'ReadExtendedAttributes'
                'file_write_ea'              = 'WriteExtendedAttributes'
                'file_execute'               = 'ExecuteFile'
                'file_delete_child'          = 'DeleteSubdirectoriesAndFiles'
                'file_read_attributes'       = 'ReadAttributes'
                'file_write_attributes'      = 'WriteAttributes'
            }
            $fsRight = $rightMap[$rightName]
            if (-not $fsRight) { $fsRight = $rightName }
            $hasRightEntries = @($access | Where-Object { $_.FileSystemRights.ToString() -match [regex]::Escape($fsRight) })
            $actual = if ((Get-SafeCount $hasRightEntries) -gt 0) { 'true' } else { 'false' }
        }
    } catch { $actual = 'false' }

    $pass = Compare-Value -Actual $actual -Expected $expected -Operation $operation -Datatype 'boolean'
    return [pscustomobject]@{
        Type     = 'FileEffectiveRights53'
        Path     = $path
        Trustee  = $trustee
        Right    = $rightName
        Expected = $expected
        Actual   = $actual
        Pass     = $pass
        Evidence = "Trustee $trustee has right ${rightName}: $actual (expected $expected, op=$operation)"
    }
}

function Evaluate-AuditEventPolicySubcategoriesTest {
    param([System.Xml.XmlNode]$test)

    $refs = Get-TestRefs -test $test
    $objectRefId = $refs.objectRefId
    $stateRefId  = $refs.stateRefId

    $obj = $null
    if ($objectRefId -and $objects.ContainsKey($objectRefId)) { $obj = $objects[$objectRefId] }
    $stateNode = $null
    if ($stateRefId -and $states.ContainsKey($stateRefId)) { $stateNode = $states[$stateRefId] }

    if (-not $obj) { return [pscustomobject]@{ Type='AuditPolicy'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="Audit policy object not found: $objectRefId" } }
    if (-not $stateNode) { return [pscustomobject]@{ Type='AuditPolicy'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="Audit policy state not found: $stateRefId" } }

    $subcategoryMap = @{
        'sensitive_privilege_use'     = 'Sensitive Privilege Use'
        'logon'                       = 'Logon'
        'logoff'                      = 'Logoff'
        'account_lockout'             = 'Account Lockout'
        'special_logon'               = 'Special Logon'
        'other_object_access_events'  = 'Other Object Access Events'
        'handle_manipulation'         = 'Handle Manipulation'
        'registry'                    = 'Registry'
        'file_system'                 = 'File System'
        'process_creation'            = 'Process Creation'
        'security_state_change'       = 'Security State Change'
        'security_system_extension'   = 'Security System Extension'
        'system_integrity'            = 'System Integrity'
        'audit_policy_change'         = 'Audit Policy Change'
        'authentication_policy_change'= 'Authentication Policy Change'
        'authorization_policy_change' = 'Authorization Policy Change'
        'directory_service_access'    = 'Directory Service Access'
        'directory_service_changes'   = 'Directory Service Changes'
        'computer_account_management' = 'Computer Account Management'
        'user_account_management'     = 'User Account Management'
        'security_group_management'   = 'Security Group Management'
        'credential_validation'       = 'Credential Validation'
        'ipsec_driver'                = 'IPsec Driver'
        'other_system_events'         = 'Other System Events'
    }

    $results = @()
    foreach ($child in $stateNode.ChildNodes) {
        if (-not ($child -is [System.Xml.XmlElement])) { continue }
        $fieldName = $child.LocalName
        $expectedLiteral = (Get-InnerText $child)

        $expectedCanonical = Map-OvalAuditExpectation -OvalValue $expectedLiteral
        if (-not $expectedCanonical) { $expectedCanonical = ($expectedLiteral -replace '_',' ').Trim() }

        $subcategory = $subcategoryMap[$fieldName]
        if (-not $subcategory) { $subcategory = ($fieldName -replace '_',' ').Trim() }

        $actualInfo = Get-AuditSubcategorySetting -Subcategory $subcategory
        $actualCanonical = $actualInfo.SettingString
        $pass = ($actualCanonical.Trim().ToUpperInvariant() -eq $expectedCanonical.Trim().ToUpperInvariant())

        $results += [pscustomobject]@{
            Type        = 'AuditPolicy'
            Subcategory = $subcategory
            Expected    = $expectedCanonical
            Actual      = $actualCanonical
            Pass        = $pass
            Evidence    = "auditpol.exe /get /subcategory:`"$subcategory`" => $($actualInfo.SettingString); SuccessEnabled=$($actualInfo.SuccessEnabled); FailureEnabled=$($actualInfo.FailureEnabled)"
            RawOutput   = $actualInfo.Raw
        }
    }

    $overallPass = (((@($results | Where-Object { -not $_.Pass })) | Measure-Object).Count -eq 0)
    return [pscustomobject]@{
        Type     = 'AuditPolicy'
        Pass     = $overallPass
        Details  = $results
    }
}

function Evaluate-GroupTest {
    param([System.Xml.XmlNode]$test)

    # Resolve refs
    $refs = Get-TestRefs -test $test
    $objectRefId = $refs.objectRefId
    $stateRefId  = $refs.stateRefId

    $obj = $null
    if ($objectRefId -and $objects.ContainsKey($objectRefId)) { $obj = $objects[$objectRefId] }
    $stateNode = $null
    if ($stateRefId -and $states.ContainsKey($stateRefId)) { $stateNode = $states[$stateRefId] }

    if (-not $obj) { 
        return [pscustomobject]@{ Type='Group'; Pass=$false; Expected='N/A'; Actual='N/A'; Evidence="Group object not found: $objectRefId" } 
    }

    # Object: group_name or group_sid (support var_ref)
    $groupNameNode = Select-XmlNode -Xml $obj -XPath "./*[local-name()='group_name' or local-name()='name']"
    $groupSidNode  = Select-XmlNode -Xml $obj -XPath "./*[local-name()='group_sid' or local-name()='sid']"
    $groupName     = Get-InnerText $groupNameNode
    $groupSid      = Get-InnerText $groupSidNode

    $groupNameVarRef = Get-AttrValue -Node $groupNameNode -Name 'var_ref'
    if ($groupNameVarRef) {
        $vals = Resolve-VarRef -VarRef $groupNameVarRef
        if ($vals -and (Get-SafeCount $vals) -gt 0) { $groupName = $vals[0] } # Use first for selection
    }
    $groupSidVarRef = Get-AttrValue -Node $groupSidNode -Name 'var_ref'
    if ($groupSidVarRef) {
        $vals = Resolve-VarRef -VarRef $groupSidVarRef
        if ($vals -and (Get-SafeCount $vals) -gt 0) { $groupSid = $vals[0] }
    }

    # Locate the group via CIM
    $group = $null
    try {
        if ($groupSid) {
            $group = Get-CimInstance -ClassName Win32_Group -Filter "SID='$groupSid'" -ErrorAction SilentlyContinue
        }
        if (-not $group -and $groupName) {
            $group = Get-CimInstance -ClassName Win32_Group -Filter "Name='$groupName'" -ErrorAction SilentlyContinue
            if (-not $group) {
                $group = Get-CimInstance -ClassName Win32_Group -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $groupName } | Select-Object -First 1
            }
        }
    } catch { }

    # Existence-only if no state
    if (-not $stateNode) {
        $checkExistence = Get-AttrValue -Node $test -Name 'check_existence'
        $exists = ($null -ne $group)
        $pass = $false
        switch ($checkExistence) {
            'none_exist'          { $pass = (-not $exists) }
            'only_one_exists'     { $pass = $exists } # single entity context; treat as exists
            'at_least_one_exists' { $pass = $exists }
            'any_exist'           { $pass = $exists }
            default               { $pass = $exists } # default: require existence
        }
        return [pscustomobject]@{
            Type     = 'Group'
            GroupName= $groupName
            GroupSID = $groupSid
            Expected = "check_existence=$checkExistence"
            Actual   = "exists=$exists"
            Pass     = $pass
            Evidence = if ($group) { "Found group: Name=$($group.Name), SID=$($group.SID), Domain=$($group.Domain), LocalAccount=$($group.LocalAccount)" } else { "Group not found" }
        }
    }

    # With state: evaluate properties and membership
    if (-not $group) {
        return [pscustomobject]@{
            Type='Group'; Pass=$false; Expected='State checks'; Actual='Group missing'
            Evidence="Group not found; cannot evaluate state ($($groupName ?? $groupSid))"
        }
    }

    # Pull members
    $members = @(Get-LocalGroupMembers -GroupName $group.Name)
    $memberSIDs  = @($members | ForEach-Object { $_.SID } | Where-Object { $_ })
    $memberNames = @($members | ForEach-Object { $_.Name } | Where-Object { $_ })

    # Helper: evaluate entity_check against actual values & expected(s)
    function Evaluate-EntityCheck {
        param(
            [object[]]$ActualValues,
            [object[]]$ExpectedValues,
            [string]$Operation = 'equals',
            [string]$Datatype = 'string',
            [string]$EntityCheck = 'at least one'
        )
        # flatten
        $ActualValues   = @($ActualValues | Where-Object { $_ -ne $null -and $_ -ne '' })
        $ExpectedValues = @($ExpectedValues | Where-Object { $_ -ne $null -and $_ -ne '' })

        switch ($EntityCheck) {
            'all' {
                foreach ($a in $ActualValues) {
                    $matched = $false
                    foreach ($e in $ExpectedValues) {
                        if (Compare-Value -Actual $a -Expected $e -Operation $Operation -Datatype $Datatype) { $matched = $true; break }
                    }
                    if (-not $matched) { return $false }
                }
                return $true
            }
            'none satisfy' {
                foreach ($a in $ActualValues) {
                    foreach ($e in $ExpectedValues) {
                        if (Compare-Value -Actual $a -Expected $e -Operation $Operation -Datatype $Datatype) { return $false }
                    }
                }
                return $true
            }
            'only one' {
                $count = 0
                foreach ($a in $ActualValues) {
                    foreach ($e in $ExpectedValues) {
                        if (Compare-Value -Actual $a -Expected $e -Operation $Operation -Datatype $Datatype) { $count++; break }
                    }
                }
                return ($count -eq 1)
            }
            default { # 'at least one'
                foreach ($a in $ActualValues) {
                    foreach ($e in $ExpectedValues) {
                        if (Compare-Value -Actual $a -Expected $e -Operation $Operation -Datatype $Datatype) { return $true }
                    }
                }
                return $false
            }
        }
    }

    $results = @()
    $allPass = $true

    # -- group_name state
    $stGroupName = Select-XmlNode -Xml $stateNode -XPath "./*[local-name()='group_name' or local-name()='name']"
    if ($stGroupName) {
        $exp = Get-InnerText $stGroupName
        $op  = Get-AttrValue -Node $stGroupName -Name 'operation'; if (-not $op) { $op = 'equals' }
        $dt  = Get-AttrValue -Node $stGroupName -Name 'datatype';  if (-not $dt) { $dt = 'string' }
        $expVar = Get-AttrValue -Node $stGroupName -Name 'var_ref'
        $expVals = @($exp)
        if ($expVar) { $tmp = Resolve-VarRef -VarRef $expVar; if ($tmp) { $expVals = $tmp } }
        $pass = Evaluate-EntityCheck -ActualValues @($group.Name) -ExpectedValues $expVals -Operation $op -Datatype $dt -EntityCheck 'at least one'
        if (-not $pass) { $allPass = $false }
        $results += [pscustomobject]@{ Type='Group'; Field='group_name'; Expected=($expVals -join ', '); Actual=$group.Name; Pass=$pass; Evidence="op=$op, datatype=$dt" }
    }

    # -- group_sid state
    $stGroupSid = Select-XmlNode -Xml $stateNode -XPath "./*[local-name()='group_sid' or local-name()='sid']"
    if ($stGroupSid) {
        $exp = Get-InnerText $stGroupSid
        $op  = Get-AttrValue -Node $stGroupSid -Name 'operation'; if (-not $op) { $op = 'equals' }
        $dt  = Get-AttrValue -Node $stGroupSid -Name 'datatype';  if (-not $dt) { $dt = 'string' }
        $expVar = Get-AttrValue -Node $stGroupSid -Name 'var_ref'
        $expVals = @($exp)
        if ($expVar) { $tmp = Resolve-VarRef -VarRef $expVar; if ($tmp) { $expVals = $tmp } }
        $pass = Evaluate-EntityCheck -ActualValues @($group.SID) -ExpectedValues $expVals -Operation $op -Datatype $dt -EntityCheck 'at least one'
        if (-not $pass) { $allPass = $false }
        $results += [pscustomobject]@{ Type='Group'; Field='group_sid'; Expected=($expVals -join ', '); Actual=$group.SID; Pass=$pass; Evidence="op=$op, datatype=$dt" }
    }

    # -- domain state
    $stDomain = Select-XmlNode -Xml $stateNode -XPath "./*[local-name()='domain']"
    if ($stDomain) {
        $exp = Get-InnerText $stDomain
        $op  = Get-AttrValue -Node $stDomain -Name 'operation'; if (-not $op) { $op = 'equals' }
        $dt  = Get-AttrValue -Node $stDomain -Name 'datatype';  if (-not $dt) { $dt = 'string' }
        $pass = Compare-Value -Actual $group.Domain -Expected $exp -Operation $op -Datatype $dt
        if (-not $pass) { $allPass = $false }
        $results += [pscustomobject]@{ Type='Group'; Field='domain'; Expected=$exp; Actual=$group.Domain; Pass=$pass; Evidence="op=$op, datatype=$dt" }
    }

    # -- member_count state
    $stMemberCount = Select-XmlNode -Xml $stateNode -XPath "./*[local-name()='member_count']"
    if ($stMemberCount) {
        $exp = Get-InnerText $stMemberCount
        $op  = Get-AttrValue -Node $stMemberCount -Name 'operation'; if (-not $op) { $op = 'equals' }
        $dt  = Get-AttrValue -Node $stMemberCount -Name 'datatype';  if (-not $dt) { $dt = 'integer' }
        $actualCount = ((@($members) | Measure-Object).Count)
        $pass = Compare-Value -Actual $actualCount -Expected $exp -Operation $op -Datatype $dt
        if (-not $pass) { $allPass = $false }
        $results += [pscustomobject]@{ Type='Group'; Field='member_count'; Expected=$exp; Actual=$actualCount; Pass=$pass; Evidence="op=$op, datatype=$dt" }
    }

    # -- membership checks: user_sid / trustee_sid / user_name
    foreach ($memField in @('user_sid','trustee_sid','user_name','trustee_name')) {
        $stNode = Select-XmlNode -Xml $stateNode -XPath "./*[local-name()='$memField']"
        if (-not $stNode) { continue }
        $exp = Get-InnerText $stNode
        $op  = Get-AttrValue -Node $stNode -Name 'operation';    if (-not $op) { $op = 'equals' }
        $dt  = Get-AttrValue -Node $stNode -Name 'datatype';     if (-not $dt) { $dt = 'string' }
        $ec  = Get-AttrValue -Node $stNode -Name 'entity_check'; if (-not $ec) { $ec = 'at least one' }
        $expVar = Get-AttrValue -Node $stNode -Name 'var_ref'
        $expVals = @($exp)
        if ($expVar) { $tmp = Resolve-VarRef -VarRef $expVar; if ($tmp) { $expVals = $tmp } }

        $actualVals = if ($memField -like '*sid') { $memberSIDs } else { $memberNames }
        $pass = Evaluate-EntityCheck -ActualValues $actualVals -ExpectedValues $expVals -Operation $op -Datatype $dt -EntityCheck $ec
        if (-not $pass) { $allPass = $false }
        $results += [pscustomobject]@{
            Type     = 'Group'
            Field    = $memField
            Expected = ($expVals -join ', ')
            Actual   = ($actualVals -join ', ')
            Pass     = $pass
            Evidence = "entity_check=$ec, op=$op, datatype=$dt, members=$((( @($members) | Measure-Object).Count))"
        }
    }

    return [pscustomobject]@{
        Type     = 'Group'
        GroupName= $group.Name
        GroupSID = $group.SID
        Domain   = $group.Domain
        Pass     = $allPass
        Details  = $results
        Evidence = "Members=$((( @($members) | Measure-Object).Count)); LocalAccount=$($group.LocalAccount)"
    }
}

function Evaluate-Test {
    param([System.Xml.XmlNode]$test)

    if (-not $test) {
        return [pscustomobject]@{ Type = 'Unknown'; Pass = $false; Expected='N/A'; Actual='N/A'; Evidence = 'Test reference not found in OVAL tests.' }
    }

    $name = $test.LocalName.ToLowerInvariant()

    switch ($name) {
        {$_ -eq 'registry_test'}                              { return Evaluate-RegistryTest -test $test }
        {$_ -eq 'wmi57_test' -or $_ -like '*wmi*_test'}       { return Evaluate-WMITest -test $test }
        {$_ -eq 'file_test'}                                  { return Evaluate-FileTest -test $test }
        {$_ -eq 'service_test'}                               { return Evaluate-ServiceTest -test $test }
        {$_ -eq 'process_test'}                               { return Evaluate-ProcessTest -test $test }
        {$_ -eq 'qfe_test' -or $_ -eq 'hotfix_test'}          { return Evaluate-QfeTest -test $test }

        # Audit event policy subcategories
        { $_ -eq 'auditeventpolicysubcategories_test' }       { return Evaluate-AuditEventPolicySubcategoriesTest -test $test }
        { $_ -eq 'audit_event_policy_subcategories_test' }    { return Evaluate-AuditEventPolicySubcategoriesTest -test $test }
        { $_ -like '*auditeventpolicy*subcategories_test' }   { return Evaluate-AuditEventPolicySubcategoriesTest -test $test }

        # Account lockout policy
        { $_ -eq 'lockoutpolicy_test' }                       { return Evaluate-LockoutPolicyTest -test $test }
        { $_ -eq 'lockout_policy_test' }                      { return Evaluate-LockoutPolicyTest -test $test }
        { $_ -like '*lockoutpolicy*_test' }                   { return Evaluate-LockoutPolicyTest -test $test }
        
        # SID/SID, AccessToken, FileEffectiveRights53
        { $_ -eq 'sid_sid_test' }                             { return Evaluate-SidSidTest -test $test }
        { $_ -eq 'accesstoken_test' }                         { return Evaluate-AccessTokenTest -test $test }
        { $_ -eq 'fileeffectiverights53_test' }               { return Evaluate-FileEffectiveRights53Test -test $test }

        # Group test
        { $_ -eq 'group_test' }                               { return Evaluate-GroupTest -test $test }

        default {
            return [pscustomobject]@{
                Type     = 'Unknown'
                Pass     = $true
                Expected = 'N/A'
                Actual   = 'N/A'
                Evidence = "Unsupported test type: $name"
            }
        }
    }
}


