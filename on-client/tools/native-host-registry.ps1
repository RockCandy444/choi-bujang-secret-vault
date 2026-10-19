# 별도 호스트 registry. 원 Vault·학생 폴더에는 파일을 쓰지 않는다.
# Use only modules supplied by this running PowerShell engine; preserve every ACL/identity check.
$env:PSModulePath=[IO.Path]::Combine($PSHOME,'Modules')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
[Console]::InputEncoding=New-Object Text.UTF8Encoding($false)
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
$held=New-Object Collections.Generic.List[IDisposable]
$mutex=$null;$locked=$false;$pendingTemp=$null;$pendingIdentity=$null
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
$watch=[Diagnostics.Stopwatch]::StartNew()
function Fail([string]$code){throw $code}
function Exact($v,[string[]]$keys){if($null -eq $v -or $v -isnot [pscustomobject]){return $false};$names=@($v.PSObject.Properties.Name);return $names.Count -eq $keys.Count -and @($keys|Where-Object{$names -cnotcontains $_}).Count -eq 0}
function Json($v){return ConvertTo-Json -InputObject $v -Depth 16 -Compress}
function Utf8([string]$v){return ,([Text.Encoding]::UTF8.GetBytes($v))}
function Hash([byte[]]$v){$h=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($h.ComputeHash($v))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}}
function ReadLine([int]$max){$b=New-Object Text.StringBuilder;while($true){$x=[Console]::In.Read();if($x -eq -1){Fail 'NATIVE_HOST_OUTCOME_UNKNOWN'};if($x -eq 10){break};if($b.Length -ge $max){Fail 'NATIVE_HOST_INPUT_INVALID'};[void]$b.Append([char]$x)};return $b.ToString()}
function Emit($v){[Console]::Out.WriteLine((Json $v));[Console]::Out.Flush()}
function Alive{if([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() -ge $request.deadline -or $watch.ElapsedMilliseconds -ge $request.remainingMs){Fail 'NATIVE_HOST_EXPIRED'}}
function Uuid($v){return $v -is [string] -and $v -cmatch '^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$'}
function Digest($v){return $v -is [string] -and $v -cmatch '^[a-f0-9]{64}$'}
try{
  $request=(ReadLine 16384)|ConvertFrom-Json
  if(!(Exact $request @('schema','action','registryRoot','vaultRoot','projectRoot','configurationFile','deadline','remainingMs','nonce','binding')) -or $request.schema -cne 'alekov.native-registry.request.v1' -or @('select','save','load','remove') -cnotcontains $request.action -or !(Uuid $request.nonce) -or $request.remainingMs -lt 1 -or $request.remainingMs -gt 15000){Fail 'NATIVE_HOST_INPUT_INVALID'}
  Alive
  Add-Type -TypeDefinition @'
using System;using System.IO;using System.Runtime.InteropServices;using Microsoft.Win32.SafeHandles;
public static class AlekovRegistryNative {
 [StructLayout(LayoutKind.Sequential)] struct INFO { public uint attr;public System.Runtime.InteropServices.ComTypes.FILETIME c,a,w;public uint vol,hi,lo,links,indexHi,indexLo; }
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFile(string p,uint a,uint s,IntPtr z,uint c,uint f,IntPtr t);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle h,out INFO i);
 public static SafeFileHandle Hold(string p){var h=CreateFile(p,0x80,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);INFO i;if(h.IsInvalid||!GetFileInformationByHandle(h,out i)||(i.attr&0x400)!=0||(i.attr&0x10)==0){h.Dispose();throw new IOException("NATIVE_HOST_PATH_UNSAFE");}return h;}
 public static string Identity(SafeFileHandle h,bool directory){INFO i;if(!GetFileInformationByHandle(h,out i)||(i.attr&0x400)!=0||((i.attr&0x10)!=0)!=directory||!directory&&i.links!=1)throw new IOException("NATIVE_HOST_PATH_UNSAFE");return i.vol.ToString("x8")+i.indexHi.ToString("x8")+i.indexLo.ToString("x8")+":"+i.c.dwHighDateTime.ToString("x8")+i.c.dwLowDateTime.ToString("x8");}
}
'@
  function Path([string]$raw){$p=[IO.Path]::GetFullPath($raw);if($p -cnotmatch '^[A-Za-z]:\\' -or $p.Substring(2).Contains(':') -or $p.Contains([char]0) -or ![IO.Directory]::Exists($p) -or $p.TrimEnd('\') -ceq [IO.Path]::GetPathRoot($p).TrimEnd('\')){Fail 'NATIVE_HOST_PATH_UNSAFE'};return $p.TrimEnd('\')}
  $registry=Path $request.registryRoot;$vault=Path $request.vaultRoot;$project=Path $request.projectRoot
  if($registry -ieq $vault -or $registry -ieq $project -or $registry.StartsWith($project+'\',[StringComparison]::OrdinalIgnoreCase) -or $vault.StartsWith($project+'\',[StringComparison]::OrdinalIgnoreCase)){Fail 'NATIVE_HOST_PATH_UNSAFE'}
  function HoldChain([string]$p){$chain=New-Object Collections.Generic.List[string];$d=New-Object IO.DirectoryInfo($p);while($null -ne $d){$chain.Add($d.FullName);$d=$d.Parent};$last=$null;for($i=$chain.Count-1;$i -ge 0;$i--){$last=[AlekovRegistryNative]::Hold($chain[$i]);$held.Add($last)};return [AlekovRegistryNative]::Identity($last,$true)}
  $registryIdentity=HoldChain $registry;$vaultIdentity=HoldChain $vault;$projectIdentity=HoldChain $project
  function Acl([string]$p){$a=Get-Acl -LiteralPath $p;$rules=@($a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]));if($a.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $sid.Value -or !$a.AreAccessRulesProtected -or $rules.Count -ne 1 -or $rules[0].IdentityReference.Value -cne $sid.Value -or $rules[0].AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $rules[0].FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl){Fail 'NATIVE_HOST_ACL_UNSAFE'}}
  function PrivateAcl([string]$p,[bool]$directory){if($directory){$a=New-Object Security.AccessControl.DirectorySecurity;$r=New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit, ObjectInherit','None','Allow')}else{$a=New-Object Security.AccessControl.FileSecurity;$r=New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','Allow')};$a.SetOwner($sid);$a.SetAccessRuleProtection($true,$false);$a.AddAccessRule($r);if($directory){[IO.Directory]::SetAccessControl($p,$a)}else{[IO.File]::SetAccessControl($p,$a)};Acl $p}
  $ma=New-Object Security.AccessControl.MutexSecurity;$ma.SetAccessRuleProtection($true,$false);$ma.AddAccessRule((New-Object Security.AccessControl.MutexAccessRule($sid,'FullControl','Allow')));$created=$false
  $mutex=New-Object Threading.Mutex($false,('Local\AlekovNativeRegistry_'+(Hash (Utf8 ($sid.Value+'|'+$registry.ToLowerInvariant())))),[ref]$created,$ma)
  try{$locked=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$locked=$true;Fail 'NATIVE_HOST_OUTCOME_UNKNOWN'};if(!$locked){Fail 'NATIVE_HOST_BUSY'}
  $statePath=[IO.Path]::Combine($registry,'.alekov-native-registry.json')
  function ReadOwned([string]$p,[int]$max){if(([IO.File]::GetAttributes($p) -band [IO.FileAttributes]::ReparsePoint) -ne 0){Fail 'NATIVE_HOST_PATH_UNSAFE'};$f=[IO.File]::Open($p,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None);try{Acl $p;$identity=[AlekovRegistryNative]::Identity($f.SafeFileHandle,$false);if($f.Length -gt $max){Fail 'NATIVE_HOST_STORAGE_INVALID'};$b=New-Object byte[] ([int]$f.Length);$offset=0;while($offset -lt $b.Length){$n=$f.Read($b,$offset,$b.Length-$offset);if($n -le 0){Fail 'NATIVE_HOST_STORAGE_INVALID'};$offset+=$n};return @{identity=$identity;digest=(Hash $b);value=([Text.Encoding]::UTF8.GetString($b)|ConvertFrom-Json)}}finally{$f.Dispose()}}
  function WriteNew([string]$p,[byte[]]$bytes){$f=[IO.File]::Open($p,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None);try{PrivateAcl $p $false;$f.Write($bytes,0,$bytes.Length);$f.Flush($true);return [AlekovRegistryNative]::Identity($f.SafeFileHandle,$false)}finally{$f.Dispose()}}
  if($null -ne $request.configurationFile){$cf=$request.configurationFile;if(!(Exact $cf @('path','digest','identity')) -or !(Digest $cf.digest) -or $cf.path -isnot [string]){Fail 'NATIVE_HOST_INPUT_INVALID'}
    $cp=[IO.Path]::GetFullPath($cf.path);if($cp -cnotmatch '^[A-Za-z]:\\' -or $cp.Substring(2).Contains(':')){Fail 'NATIVE_HOST_PATH_UNSAFE'};[void](HoldChain ([IO.Path]::GetDirectoryName($cp)));$readConfig=ReadOwned $cp 8192;if($readConfig.digest -cne $cf.digest){Fail 'NATIVE_HOST_CONTEXT_CHANGED'}}
  if(![IO.File]::Exists($statePath)){
    $a=Get-Acl -LiteralPath $registry;if($a.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $sid.Value -or [IO.Directory]::GetFileSystemEntries($registry).Length -ne 0){Fail 'NATIVE_HOST_OWNER_MISMATCH'};PrivateAcl $registry $true
    $initial=[ordered]@{schema='alekov.native-registry.v1';ownerSid=$sid.Value;registryIdentity=$registryIdentity;revision=1;projects=@();history=@();heads=@()};[void](WriteNew $statePath (Utf8 (Json $initial)))
  }
  Acl $registry;$record=ReadOwned $statePath 262144;$state=$record.value
  if(!(Exact $state @('schema','ownerSid','registryIdentity','revision','projects','history','heads')) -or $state.schema -cne 'alekov.native-registry.v1' -or $state.ownerSid -cne $sid.Value -or $state.registryIdentity -cne $registryIdentity -or $state.revision -lt 1 -or $state.projects -isnot [array] -or $state.history -isnot [array] -or $state.heads -isnot [array] -or $state.projects.Count -gt 128 -or $state.history.Count -gt 256 -or $state.heads.Count -gt 128){Fail 'NATIVE_HOST_STORAGE_INVALID'}
  foreach($p in $state.projects){if(!(Exact $p @('pathDigest','directoryInstance','projectId')) -or !(Digest $p.pathDigest) -or !(Uuid $p.projectId) -or $p.directoryInstance -isnot [string]){Fail 'NATIVE_HOST_STORAGE_INVALID'}}
  $fenceKeys=@('operationId','nativeInstance','generation','projectGeneration','directoryInstance','contextDigest','tokenDigest','credentialDigest','state','revision','vault','deadline')
  foreach($f in @($state.history)+@($state.heads)){if(!(Exact $f $fenceKeys) -or !(Uuid $f.operationId) -or !(Uuid $f.nativeInstance) -or !(Digest $f.contextDigest) -or !(Digest $f.tokenDigest) -or !(Digest $f.credentialDigest) -or @('pending','accepted','unknown','removing','removed') -cnotcontains $f.state -or $f.revision -lt 1 -or $f.generation -lt 1 -or $f.projectGeneration -lt 1 -or $f.directoryInstance -isnot [string] -or $f.deadline -lt 1){Fail 'NATIVE_HOST_STORAGE_INVALID'}}
  function Persist{
    Alive;$current=ReadOwned $statePath 262144;if($current.identity -cne $record.identity -or $current.digest -cne $record.digest){Fail 'NATIVE_HOST_COMPARE_FAILED'}
    $state.revision++;$b=Utf8 (Json $state);if($b.Length -gt 262144){Fail 'NATIVE_HOST_CAPACITY'}
    $pendingTemp=[IO.Path]::Combine($registry,'.native-'+[Guid]::NewGuid().ToString('N')+'.tmp');$pendingIdentity=WriteNew $pendingTemp $b
    Alive;$again=ReadOwned $statePath 262144;if($again.identity -cne $record.identity -or $again.digest -cne $record.digest){Fail 'NATIVE_HOST_COMPARE_FAILED'}
    # 이전 파일도 권한과 identity를 검증해 남긴다. 불명확한 정리를 성공으로 표시하지 않는다.
    $backup=[IO.Path]::Combine($registry,'.native-history-'+[Guid]::NewGuid().ToString('N')+'.bak');[IO.File]::Replace($pendingTemp,$statePath,$backup,$false);$pendingTemp=$null
    $old=ReadOwned $backup 262144;if($old.identity -cne $record.identity -or $old.digest -cne $record.digest){Fail 'NATIVE_HOST_OUTCOME_UNKNOWN'}
    # 이전 파일은 불변 이력으로 남기며 다른 파일을 지우지 않는다.
    $script:record=ReadOwned $statePath 262144;Alive
  }
  function Marker{
    $p=[IO.Path]::Combine($vault,'.alekov-owner.json')
    if(![IO.File]::Exists($p)){if([IO.Directory]::GetFileSystemEntries($vault).Length -ne 0){Fail 'NATIVE_HOST_OWNER_MISMATCH'};return [pscustomobject][ordered]@{adopted=$false;root=$vaultIdentity;identity=$null;digest=$null;vaultId=$null}}
    Acl $vault;$r=ReadOwned $p 16384;$v=$r.value;if(!(Exact $v @('schema','appId','audience','ownerSid','vaultId')) -or $v.schema -cne 'alekov.app-vault.owner.v1' -or $v.appId -cne 'aleph-on' -or $v.audience -cne 'on-client' -or $v.ownerSid -cne $sid.Value -or !(Uuid $v.vaultId)){Fail 'NATIVE_HOST_OWNER_MISMATCH'}
    return [pscustomobject][ordered]@{adopted=$true;root=$vaultIdentity;identity=$r.identity;digest=$r.digest;vaultId=$v.vaultId}
  }
  $pathDigest=Hash (Utf8 ($project.ToLowerInvariant()));$mapping=@($state.projects|Where-Object{$_.pathDigest -ceq $pathDigest -and $_.directoryInstance -ceq $projectIdentity})
  if($mapping.Count -gt 1){Fail 'NATIVE_HOST_STORAGE_INVALID'}
  if($mapping.Count -eq 0){if($state.projects.Count -ge 128){Fail 'NATIVE_HOST_CAPACITY'};$entry=[pscustomobject]@{pathDigest=$pathDigest;directoryInstance=$projectIdentity;projectId=[Guid]::NewGuid().ToString('D')};$state.projects=@($state.projects)+@($entry);Persist}else{$entry=$mapping[0]}
  if($request.action -ceq 'select'){if($null -ne $request.binding){Fail 'NATIVE_HOST_INPUT_INVALID'};Emit @{stage='ready';nonce=$request.nonce;result=@{projectId=$entry.projectId;directoryInstance=$projectIdentity;registryRevision=$state.revision}};$commit=(ReadLine 512)|ConvertFrom-Json;if(!(Exact $commit @('nonce','outcome')) -or $commit.nonce -cne $request.nonce -or $commit.outcome -cne 'read'){Fail 'NATIVE_HOST_INPUT_INVALID'};Alive;Emit @{stage='done';nonce=$request.nonce};exit 0}
  $binding=$request.binding
  if(!(Exact $binding @('operationId','nativeInstance','generation','projectGeneration','directoryInstance','contextDigest','tokenDigest','credentialDigest','expectedRevision')) -or !(Uuid $binding.operationId) -or !(Uuid $binding.nativeInstance) -or $binding.generation -lt 1 -or $binding.projectGeneration -lt 1 -or $binding.directoryInstance -cne $projectIdentity -or !(Digest $binding.contextDigest) -or !(Digest $binding.tokenDigest) -or !(Digest $binding.credentialDigest)){Fail 'NATIVE_HOST_INPUT_INVALID'}
  $head=@($state.heads|Where-Object{$_.contextDigest -ceq $binding.contextDigest});if($head.Count -gt 1){Fail 'NATIVE_HOST_STORAGE_INVALID'};$currentHead=if($head.Count){$head[0]}else{$null}
  $marker=Marker
  if($request.action -ceq 'save'){
    if($state.history.Count -ge 256 -or @($state.history|Where-Object{$_.tokenDigest -ceq $binding.tokenDigest -and @('pending','unknown','removing') -ccontains $_.state}).Count -gt 0){Fail 'NATIVE_HOST_OUTCOME_UNKNOWN'}
    $f=[pscustomobject]@{operationId=$binding.operationId;nativeInstance=$binding.nativeInstance;generation=$binding.generation;projectGeneration=$binding.projectGeneration;directoryInstance=$binding.directoryInstance;contextDigest=$binding.contextDigest;tokenDigest=$binding.tokenDigest;credentialDigest=$binding.credentialDigest;state='pending';revision=$state.revision+1;vault=$marker;deadline=$request.deadline}
    if($null -eq $currentHead -and $state.heads.Count -ge 128){Fail 'NATIVE_HOST_CAPACITY'};$state.heads=@($state.heads|Where-Object{$_.contextDigest -cne $binding.contextDigest})+@($f);$state.history=@($state.history)+@($f);Persist;$currentHead=$f
  }else{
    if($null -eq $currentHead -or $currentHead.state -cne 'accepted' -or $currentHead.nativeInstance -cne $binding.nativeInstance -or $currentHead.generation -ne $binding.generation -or $currentHead.projectGeneration -ne $binding.projectGeneration -or $currentHead.directoryInstance -cne $binding.directoryInstance -or ($currentHead.revision -ne $binding.expectedRevision -and $binding.expectedRevision -ne 0) -or (Json $currentHead.vault) -cne (Json $marker)){Fail 'NATIVE_HOST_CONTEXT_CHANGED'}
    if($request.action -ceq 'remove'){
      if($currentHead.tokenDigest -cne $binding.tokenDigest -or @($state.history|Where-Object{$_.tokenDigest -ceq $binding.tokenDigest -and @('pending','unknown','removing') -ccontains $_.state}).Count -gt 0){Fail 'NATIVE_HOST_COMPARE_FAILED'}
      if($state.history.Count -ge 256){Fail 'NATIVE_HOST_CAPACITY'}
      # JSON을 다시 읽으면 이전 head와 history는 별도 객체다. 이번 remove를 새 이력으로 남긴다.
      # 정상 종료 전 실패/취소되면 removing/unknown이 남아 같은 token의 재저장을 차단한다.
      $currentHead=(Json $currentHead)|ConvertFrom-Json
      $currentHead.operationId=$binding.operationId;$currentHead.deadline=$request.deadline
      $state.heads=@($state.heads|Where-Object{$_.contextDigest -cne $binding.contextDigest})+@($currentHead)
      $state.history=@($state.history)+@($currentHead)
      $currentHead.state='removing';$currentHead.revision=$state.revision+1;Persist
    }
  }
  Emit @{stage='ready';nonce=$request.nonce;result=$currentHead}
  $commit=(ReadLine 512)|ConvertFrom-Json
  if(!(Exact $commit @('nonce','outcome')) -or $commit.nonce -cne $request.nonce -or @('accepted','unknown','read','removed') -cnotcontains $commit.outcome){Fail 'NATIVE_HOST_INPUT_INVALID'}
  Alive;$again=ReadOwned $statePath 262144;if($again.identity -cne $record.identity -or $again.digest -cne $record.digest){Fail 'NATIVE_HOST_COMPARE_FAILED'}
  if($request.action -ceq 'load'){if($commit.outcome -cne 'read' -or (Json (Marker)) -cne (Json $marker)){Fail 'NATIVE_HOST_COMPARE_FAILED'}}
  else{
    if($request.action -ceq 'save' -and $commit.outcome -ceq 'accepted'){$after=Marker;if(!$after.adopted -or $after.root -cne $marker.root -or ($marker.adopted -and (Json $after) -cne (Json $marker))){Fail 'NATIVE_HOST_COMPARE_FAILED'};$currentHead.vault=$after;$currentHead.state='accepted'}
    elseif($request.action -ceq 'remove' -and $commit.outcome -ceq 'removed'){$currentHead.state='removed'}
    elseif($commit.outcome -ceq 'unknown'){$currentHead.state='unknown'}else{Fail 'NATIVE_HOST_INPUT_INVALID'}
    $currentHead.revision=$state.revision+1;Persist
  }
  Alive;Emit @{stage='done';nonce=$request.nonce}
}catch{Emit @{stage='error';code='NATIVE_HOST_REGISTRY_UNVERIFIED'};exit 1}
finally{foreach($h in $held){$h.Dispose()};if($locked){$mutex.ReleaseMutex()};if($null -ne $mutex){$mutex.Dispose()}}
