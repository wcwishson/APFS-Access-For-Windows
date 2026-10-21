param([Parameter(Mandatory)][string]$SourceRoot,[Parameter(Mandatory)][string]$Destination)
$ErrorActionPreference='Stop'
$manifest=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'source-pins.json') -Raw|ConvertFrom-Json
$root=[IO.Path]::GetFullPath($SourceRoot).TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar
$output=[IO.Path]::GetFullPath($Destination).TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar
if($output.StartsWith($root,[StringComparison]::OrdinalIgnoreCase) -or $root.StartsWith($output,[StringComparison]::OrdinalIgnoreCase)){throw 'Source and generated destination must be disjoint'}
$expected=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach($entry in $manifest.files){[void]$expected.Add($entry.path)}
$actual=@(Get-ChildItem -LiteralPath (Join-Path $root 'SMBLibrary'),(Join-Path $root 'Utilities') -Recurse -File -Filter *.cs)
if($actual.Count -ne $expected.Count){throw 'Unpinned source inventory'}
foreach($file in $actual){if(!$expected.Contains($file.FullName.Substring($root.Length).Replace('\','/'))){throw 'Unexpected source file'}}
foreach($entry in $manifest.files){
 $path=[IO.Path]::GetFullPath((Join-Path $root $entry.path))
 if(!$path.StartsWith($root,[StringComparison]::OrdinalIgnoreCase) -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ine $entry.sha256){throw ('Pinned source mismatch: '+$entry.path)}
}
$patchPath=Join-Path $PSScriptRoot 'required-signing-and-clone.patch'
if((Get-FileHash -LiteralPath $patchPath -Algorithm SHA256).Hash -ine $manifest.patchSha256){throw 'Patch hash mismatch'}
$lines=[IO.File]::ReadAllText($patchPath).Replace("`r`n","`n").Split("`n")
$index=0; $changed=0
while($index -lt $lines.Count -and $lines[$index]){
 if($lines[$index] -notmatch '^--- a/(.+)$'){throw 'Invalid patch file header'}
 $relative=$Matches[1]; $index++
 if($lines[$index] -cne ('+++ b/'+$relative)){throw 'Patch destination mismatch'}; $index++
 $entry=@($manifest.changes|Where-Object path -ceq $relative)
 if($entry.Count -ne 1){throw 'Unpinned patch destination'}
 $original=[IO.File]::ReadAllText((Join-Path $root $relative)).Replace("`r`n","`n").Split("`n")
 $result=[Collections.Generic.List[string]]::new(); $cursor=0
 while($index -lt $lines.Count -and $lines[$index].StartsWith('@@')){
  if($lines[$index] -notmatch '^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@'){throw 'Invalid patch hunk'}
  $oldStart=[int]$Matches[1]-1; $oldCount=if($Matches[2]){[int]$Matches[2]}else{1}
  $newCount=if($Matches[4]){[int]$Matches[4]}else{1}; $usedOld=0; $usedNew=0; $index++
  if($oldStart -lt $cursor -or $oldStart -gt $original.Count){throw 'Invalid patch location'}
  while($cursor -lt $oldStart){$result.Add($original[$cursor]);$cursor++}
  while($index -lt $lines.Count -and !$lines[$index].StartsWith('@@') -and !$lines[$index].StartsWith('--- ') -and $lines[$index].Length){
   $line=$lines[$index];$index++;$kind=$line[0];$text=$line.Substring(1)
   if($kind -eq ' ' -or $kind -eq '-'){
    if($cursor -ge $original.Count -or $original[$cursor] -cne $text){throw 'Patch context mismatch'}
    $cursor++;$usedOld++
   }
   if($kind -eq ' ' -or $kind -eq '+'){$result.Add($text);$usedNew++}
   if($kind -notin @(' ','-','+')){throw 'Unsupported patch line'}
  }
  if($usedOld -ne $oldCount -or $usedNew -ne $newCount){throw 'Patch hunk count mismatch'}
 }
 while($cursor -lt $original.Count){$result.Add($original[$cursor]);$cursor++}
 $destinationPath=[IO.Path]::GetFullPath((Join-Path $output $relative))
 if(!$destinationPath.StartsWith($output,[StringComparison]::OrdinalIgnoreCase)){throw 'Patch destination escaped'}
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes([string]::Join("`n",$result))
 $hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))
 if($hash -ine $entry[0].afterSha256){throw 'Patched file hash mismatch'}
 [IO.Directory]::CreateDirectory((Split-Path $destinationPath))|Out-Null
 [IO.File]::WriteAllBytes($destinationPath,$bytes); $changed++
}
if($changed -ne $manifest.changes.Count){throw 'Patch file count mismatch'}
$generated=@(Get-ChildItem -LiteralPath $output -Recurse -File -Filter *.cs)
if($generated.Count -ne $manifest.changes.Count){throw 'Unexpected generated source file'}
foreach($file in $generated){if($file.FullName.Substring($output.Length).Replace('\','/') -cnotin @($manifest.changes.path)){throw 'Unpinned generated source'}}
Write-Output ('Pinned SMBLibrary source verified; patched files: '+$changed)
