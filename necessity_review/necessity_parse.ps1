[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$source = [Console]::In.ReadToEnd()
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors)
$writes = [System.Collections.Generic.List[string]]::new()
$executes = [System.Collections.Generic.List[string]]::new()
$responsibilities = [System.Collections.Generic.List[string]]::new()
$coverage = [System.Collections.Generic.List[string]]::new()
$features = [System.Collections.Generic.List[string]]::new()

function Add-Unique($list, $value) { if ($value -and -not $list.Contains($value)) { $list.Add($value) } }
function Literal-Text($node) {
  if ($node -is [System.Management.Automation.Language.StringConstantExpressionAst]) { return $node.Value }
  if ($node -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) {
    if ($node.NestedExpressions.Count -eq 0) { return $node.Value }
  }
  return $null
}
function Static-Element($node) {
  $text = Literal-Text $node
  if ($null -ne $text) { return $text }
  if ($node -is [System.Management.Automation.Language.CommandParameterAst]) {
    $argument = $node.Argument
    if ($null -eq $argument -or $null -ne (Literal-Text $argument)) { return $node.Extent.Text }
  }
  return $null
}
function Static-CommandArgv($command) {
  if ($command.Redirections.Count -ne 0 -or $command.InvocationOperator -notin 'Unknown','Ampersand') { return $null }
  $argv = [System.Collections.Generic.List[string]]::new()
  foreach ($element in @($command.CommandElements)) {
    $text = Static-Element $element
    if ($null -eq $text) { return $null }
    $argv.Add($text)
  }
  if ($argv.Count -eq 0) { return $null }
  return @($argv)
}
function Static-PythonScript($argv) {
  if ($null -eq $argv -or $argv.Count -lt 2) { return $null }
  $first = $argv[1]
  if ($first -eq '-' -or $first.StartsWith('-')) { return $null }
  return $first
}
function Static-Argv($tree) {
  if ($tree.UsingStatements.Count -ne 0 -or $null -ne $tree.ScriptRequirements -or $null -ne $tree.ParamBlock -or $null -ne $tree.DynamicParamBlock -or $null -ne $tree.BeginBlock -or $null -ne $tree.ProcessBlock -or $null -ne $tree.CleanBlock -or $null -eq $tree.EndBlock) { return $null }
  if ($tree.EndBlock.Traps.Count -ne 0) { return $null }
  if ($tree.EndBlock.Statements.Count -ne 1) { return $null }
  $pipeline = $tree.EndBlock.Statements[0]
  if ($pipeline -isnot [System.Management.Automation.Language.PipelineAst] -or $pipeline.Background -or $pipeline.PipelineElements.Count -ne 1) { return $null }
  $command = $pipeline.PipelineElements[0]
  if ($command -isnot [System.Management.Automation.Language.CommandAst]) { return $null }
  $argv = Static-CommandArgv $command
  if ($null -eq $argv) { return $null }
  $name = [IO.Path]::GetFileName($argv[0].Replace('\', '/')).ToLowerInvariant()
  if ($name -in 'invoke-expression','iex','.', 'source') { return $null }
  return $argv
}
function Command-Argument($elements) {
  $items = @($elements)
  for ($index = 1; $index -lt $items.Count - 1; $index++) {
    if ($items[$index] -is [System.Management.Automation.Language.CommandParameterAst] -and $items[$index].ParameterName -in 'Path','LiteralPath','FilePath') {
      $text = Literal-Text $items[$index + 1]
      if ($text) { return $text }
    }
  }
  foreach ($element in @($items | Select-Object -Skip 1)) {
    $text = Literal-Text $element
    if ($text -and -not $text.StartsWith('-')) { return $text }
  }
  return $null
}
function Observe-Ast($tree) {
  $generated = [System.Collections.Generic.List[string]]::new()
  $commands = @($tree.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true)) | Sort-Object { $_.Extent.StartOffset }
  foreach ($command in $commands) {
    $commandName = $command.GetCommandName()
    if (-not $commandName) { Add-Unique $coverage 'powershell:unassessed (dynamic command)'; continue }
    $name = [IO.Path]::GetFileName($commandName.Replace('\', '/')).ToLowerInvariant()
    $elements = @($command.CommandElements)
    $argument = Command-Argument $elements
    $staticArgv = Static-CommandArgv $command
    $pythonScript = Static-PythonScript $staticArgv
    if ($name -in 'set-content','add-content','out-file','export-clixml','new-item') {
      Add-Unique $responsibilities 'state'
      if ($argument) { Add-Unique $writes $argument; Add-Unique $generated $argument } else { Add-Unique $coverage 'powershell:unassessed (dynamic write path)' }
    } elseif ($name -in 'get-content','import-clixml','convertfrom-json','convertto-json') {
      Add-Unique $responsibilities 'state'
    } elseif ($name -in 'start-process','start-scheduledtask','register-scheduledtask','new-object') {
      Add-Unique $responsibilities 'process'; Add-Unique $executes $commandName
    } elseif ($name -in 'start-sleep','wait-process') {
      Add-Unique $responsibilities 'wait'
    } elseif ($name -in 'remove-item','del','rm') {
      Add-Unique $responsibilities 'cleanup'
    } elseif ($name -in 'write-output','write-host','write-information') {
      Add-Unique $responsibilities 'report'
    } elseif ($name -eq 'invoke-expression') {
      if ($argument) {
        $nestedTokens = $null; $nestedErrors = $null
        $nested = [System.Management.Automation.Language.Parser]::ParseInput($argument, [ref]$nestedTokens, [ref]$nestedErrors)
        if (@($nestedErrors).Count) { Add-Unique $coverage 'powershell:unassessed (nested syntax error)' } else { Observe-Ast $nested }
      } else { Add-Unique $coverage 'powershell:unassessed (dynamic invoke-expression)' }
    } elseif ($name -in 'python','python3','python.exe','python3.exe','py','py.exe','pwsh','pwsh.exe','powershell','powershell.exe','bash','bash.exe','cmd','cmd.exe','wsl','wsl.exe','iex') {
      # Only an exact static Python version query has no supplied program.
      # Other flags, extra arguments and expansions remain unassessed.
      $versionArgument = if ($elements.Count -eq 2) { Literal-Text $elements[1] } else { $null }
      if ($elements.Count -eq 2 -and $elements[1] -is [System.Management.Automation.Language.CommandParameterAst]) {
        $versionArgument = $elements[1].Extent.Text
      }
      if ($name -in 'python','python3','python.exe','python3.exe','py','py.exe' -and $versionArgument -cin '--version','-V' -and $command.Redirections.Count -eq 0) {
        Add-Unique $responsibilities 'process'; Add-Unique $executes $commandName
      } elseif ($name -in 'python','python3','python.exe','python3.exe','py','py.exe' -and $pythonScript) {
        Add-Unique $responsibilities 'process'; Add-Unique $executes $commandName; Add-Unique $executes $pythonScript
        if ($generated.Contains($pythonScript)) { Add-Unique $features 'generated-file-execution' }
      } else {
        Add-Unique $coverage 'powershell:unassessed (nested interpreter or evaluation alias)'
      }
    } else {
      # Static existing commands are normal entrypoints, not newly assembled
      # code merely because their command name is outside this small role map.
      Add-Unique $responsibilities 'process'; Add-Unique $executes $commandName
    }
  }
  foreach ($member in $tree.FindAll({ param($node) $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)) {
    Add-Unique $coverage 'powershell:unassessed (method invocation)'
  }
}
if (-not @($errors).Count) { Observe-Ast $ast }
@{ errors = @($errors).Count; coverage = @($coverage); features = @($features); writes = @($writes); executes = @($executes); responsibilities = @($responsibilities); static_argv = Static-Argv $ast } | ConvertTo-Json -Compress
