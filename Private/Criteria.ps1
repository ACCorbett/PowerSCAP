# === Criteria Evaluator ===
# Auto-generated from original script on 2026-01-30 14:48:45

function Evaluate-Criteria {
    param(
        [System.Xml.XmlNode]$criteriaNode,
        [string]$DefinitionId
    )

    if ($null -eq $criteriaNode) {
        return [pscustomobject]@{
            Operator = 'AND'
            Pass     = $false
            Details  = @([pscustomobject]@{
                Type     = 'Criteria'
                RuleId   = $DefinitionId
                Pass     = $false
                Expected = 'N/A'
                Actual   = 'N/A'
                Evidence = 'No <criteria> node found for this definition.'
            })
        }
    }

    $operatorAttr = Get-AttrValue -Node $criteriaNode -Name 'operator'
    if (-not $operatorAttr) { $operatorAttr = 'AND' }
    $operator = $operatorAttr.ToUpperInvariant()
    $criteriaNegate = To-Bool (Get-AttrValue -Node $criteriaNode -Name 'negate')

    $criterionNodes        = Select-XmlNodes -Xml $criteriaNode -XPath "./*[local-name()='criterion']"
    $nestedCriteriaNodes   = Select-XmlNodes -Xml $criteriaNode -XPath "./*[local-name()='criteria']"
    $extendNodes           = Select-XmlNodes -Xml $criteriaNode -XPath "./*[local-name()='extend_definition']"

    $childDetails = @()
    $childPasses  = @()

    foreach ($c in $criterionNodes) {
        $testRef = Get-AttrValue -Node $c -Name 'test_ref'
        $comment = Get-AttrValue -Node $c -Name 'comment'
        $negate  = To-Bool (Get-AttrValue -Node $c -Name 'negate')

        $t = $null
        if ($testRef -and $tests.ContainsKey($testRef)) { $t = $tests[$testRef] }
        
        $res = Evaluate-Test -test $t
        $res = Add-ResultMeta -Result $res -DefinitionId $DefinitionId -Comment $comment
        if ($negate) {
            $res | Add-Member -NotePropertyName Evidence -NotePropertyValue ("NEGATED: " + $res.Evidence) -Force
            $res | Add-Member -NotePropertyName Pass -NotePropertyValue (-not $res.Pass) -Force
        }
        $childDetails += $res
        $childPasses  += [bool]$res.Pass
    }

    foreach ($nc in $nestedCriteriaNodes) {
        $sub = Evaluate-Criteria -criteriaNode $nc -DefinitionId $DefinitionId
        $subNegate = To-Bool (Get-AttrValue -Node $nc -Name 'negate')
        $subPass = [bool]$sub.Pass
        if ($subNegate) { $subPass = -not $subPass }
        $childPasses += $subPass

        if ($sub -and $sub.Details) { $childDetails += $sub.Details }
    }

    foreach ($ex in $extendNodes) {
        $refId  = Get-AttrValue -Node $ex -Name 'definition_ref'
        $negate = To-Bool (Get-AttrValue -Node $ex -Name 'negate')

        $refDef = $null
        if ($refId -and $definitions.ContainsKey($refId)) { $refDef = $definitions[$refId] }
        
        if ($refDef) {
            $subCrit = Select-XmlNode -Xml $refDef -XPath "./*[local-name()='criteria']"
            $subEval = Evaluate-Criteria -criteriaNode $subCrit -DefinitionId $refId
            $subPass = [bool]$subEval.Pass
            if ($negate) { $subPass = -not $subPass }
            $childPasses += $subPass

            if ($subEval -and $subEval.Details) { $childDetails += $subEval.Details }
        } else {
            $missing = [pscustomobject]@{ Type = 'DefinitionRef'; RuleId=$DefinitionId; Pass = $false; Expected='N/A'; Actual='N/A'; Evidence = "Referenced definition not found: $refId" }
            $childDetails += $missing
            $childPasses  += $false
        }
    }

    $overall = $false
    $childCount = ((@($childPasses) | Measure-Object).Count)
    if ($childCount -gt 0) {
        if ($operator -eq 'AND') {
            $overall = ($childPasses -notcontains $false)
        } elseif ($operator -eq 'OR') {
            $overall = ($childPasses -contains $true)
        } else {
            $overall = ($childPasses -notcontains $false)
        }
    }

    if ($criteriaNegate) { $overall = -not $overall }

    return [pscustomobject]@{
        Operator = $operator
        Pass     = $overall
        Details  = $childDetails
    }
}


