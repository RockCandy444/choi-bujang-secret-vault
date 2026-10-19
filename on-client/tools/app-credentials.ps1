# Private native-host protocol. No credential in arguments, environment or diagnostics.
# Use only modules supplied by this running PowerShell engine; preserve every ACL/identity check.
$env:PSModulePath=[IO.Path]::Combine($PSHOME,'Modules')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::InputEncoding = New-Object Text.UTF8Encoding($false)
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
$script:held = New-Object Collections.Generic.List[IDisposable]
$script:temporary = $null
$script:temporaryIdentity = $null
$script:temporaryDigest = $null
$script:rootPath = $null
$script:mutex = $null
$script:mutexHeld = $false
$script:ownerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User

function Fail([string]$code) { throw $code }
function Exact($value, [string[]]$keys) {
  if ($null -eq $value -or $value -isnot [pscustomobject]) { return $false }
  $actual = @($value.PSObject.Properties.Name)
  return $actual.Count -eq $keys.Count -and @($keys | Where-Object { $actual -cnotcontains $_ }).Count -eq 0
}
function Hash([byte[]]$bytes) {
  $hasher = [Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($hasher.ComputeHash($bytes))).Replace('-','').ToLowerInvariant() } finally { $hasher.Dispose() }
}
function Utf8([string]$s) { return ,([Text.Encoding]::UTF8.GetBytes($s)) }
function Json($v) { return ConvertTo-Json -InputObject $v -Depth 12 -Compress }
function ReadLineBounded([int]$limit) {
  $builder = New-Object Text.StringBuilder
  while ($true) {
    $v = [Console]::In.Read()
    if ($v -eq -1 -or $v -eq 10) { break }
    if ($builder.Length -ge $limit) { Fail 'ALEKOV_VAULT_INPUT_INVALID' }
    [void]$builder.Append([char]$v)
  }
  return $builder.ToString()
}
function Emit($v) { [Console]::Out.WriteLine((Json $v)); [Console]::Out.Flush() }
function Alive {
  if ([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() -ge $script:request.deadline) { Fail 'ALEKOV_VAULT_TIMEOUT' }
}
function ContextJson($c) {
  return Json ([ordered]@{alephUserId=$c.alephUserId;identityVersion=$c.identityVersion;projectId=$c.projectId;siteId=$c.siteId;subjectId=$c.subjectId})
}
function ValidContext($c) {
  if (!(Exact $c @('subjectId','alephUserId','siteId','identityVersion','projectId'))) { return $false }
  foreach ($k in @('subjectId','alephUserId','siteId','projectId')) { if ($c.$k -isnot [string] -or $c.$k -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$') { return $false } }
  return $c.identityVersion -is [long] -or $c.identityVersion -is [int]
}
function ValidateCredential($c, [bool]$requireCurrent = $true) {
  $keys = @('schema','appId','audience','subjectId','alephUserId','siteId','identityVersion','projectId','grantId','grantVersion','credentialId','policyVersion','accessPolicyId','baseUrl','token','expiresAt')
  if (!(Exact $c $keys) -or $c.schema -cne 'alekov.app-connect.credential.v1' -or $c.appId -cne 'aleph-on' -or $c.audience -cne 'on-client' -or
      $c.baseUrl -cne $script:request.baseUrl -or $c.token -isnot [string] -or $c.token -cnotmatch '^sk-on-[A-Za-z0-9_-]{43}$') { Fail 'ALEKOV_VAULT_CREDENTIAL_INVALID' }
  foreach ($k in @('subjectId','alephUserId','siteId','identityVersion','projectId')) { if ($c.$k -cne $script:request.expectedContext.$k) { Fail 'ALEKOV_VAULT_CONTEXT_CHANGED' } }
  foreach ($k in @('grantId','credentialId','policyVersion','accessPolicyId')) { if ($c.$k -isnot [string] -or $c.$k -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$') { Fail 'ALEKOV_VAULT_CREDENTIAL_INVALID' } }
  if (($c.grantVersion -isnot [long] -and $c.grantVersion -isnot [int]) -or $c.grantVersion -lt 1) { Fail 'ALEKOV_VAULT_CREDENTIAL_INVALID' }
  $expiry = [DateTimeOffset]::MinValue
  if ($c.expiresAt -isnot [string] -or ![DateTimeOffset]::TryParseExact($c.expiresAt,'yyyy-MM-ddTHH:mm:ss.fffZ',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal,[ref]$expiry)) { Fail 'ALEKOV_VAULT_CREDENTIAL_INVALID' }
  if ($requireCurrent -and $expiry -le [DateTimeOffset]::UtcNow) { Fail 'ALEKOV_VAULT_EXPIRED' }
}

try {
  $script:request = (ReadLineBounded 32768) | ConvertFrom-Json
  if (!(Exact $request @('schema','action','vaultRoot','baseUrl','deadline','nonce','expectedContext','contextFingerprint','connectionId','credential','credentialFingerprint')) -or
      $request.schema -cne 'alekov.app-vault.request.v1' -or @('save','load','remove') -cnotcontains $request.action -or
      !(ValidContext $request.expectedContext) -or $request.expectedContext.identityVersion -lt 1 -or
      $request.nonce -cnotmatch '^[a-f0-9-]{36}$' -or $request.contextFingerprint -cnotmatch '^[a-f0-9]{64}$' -or
      $request.contextFingerprint -cne (Hash (Utf8 (ContextJson $request.expectedContext)))) { Fail 'ALEKOV_VAULT_INPUT_INVALID' }
  Alive
  $uri = [Uri]$request.baseUrl
  if ($uri.Scheme -cne 'https' -or $uri.UserInfo -or $uri.Query -or $uri.Fragment -or $uri.AbsolutePath -cne '/api/apps/aleph-on/v1') { Fail 'ALEKOV_VAULT_INPUT_INVALID' }
  if ($request.action -ceq 'save') { ValidateCredential $request.credential }
  if ($request.action -ceq 'remove' -and $request.credentialFingerprint -cnotmatch '^[a-f0-9]{64}$') { Fail 'ALEKOV_VAULT_INPUT_INVALID' }

  Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
public static class AlekovVaultNative {
 [StructLayout(LayoutKind.Sequential)] struct INFO { public uint attr; public System.Runtime.InteropServices.ComTypes.FILETIME c,a,w; public uint vol, hi,lo,links,indexHi,indexLo; }
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern SafeFileHandle CreateFile(string p,uint a,uint s,IntPtr z,uint c,uint f,IntPtr t);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle h,out INFO i);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetFileInformationByHandle(SafeFileHandle h,int kind,ref byte info,uint size);
 public static SafeFileHandle DirectoryLock(string p) {
   var h=CreateFile(p,0x80,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
   if(h.IsInvalid) { h.Dispose(); throw new IOException("ALEKOV_VAULT_PATH_UNSAFE"); }
   INFO i; if(!GetFileInformationByHandle(h,out i) || (i.attr&0x400)!=0 || (i.attr&0x10)==0) { h.Dispose();throw new IOException("ALEKOV_VAULT_PATH_UNSAFE"); }
   return h;
 }
 public static string FileIdentity(FileStream stream) {
   INFO i; if(!GetFileInformationByHandle(stream.SafeFileHandle,out i) || (i.attr&0x410)!=0 || i.links!=1) throw new IOException("ALEKOV_VAULT_PATH_UNSAFE");
   return i.vol.ToString("x8")+i.indexHi.ToString("x8")+i.indexLo.ToString("x8");
 }
 public static void DeleteExact(string p,string identity,string digest) {
   // Delete the validated handle, never a newly resolved path or a different inode.
   var h=CreateFile(p,0x80010000,0,IntPtr.Zero,3,0x00200000,IntPtr.Zero);
   if(h.IsInvalid) { h.Dispose();throw new IOException("ALEKOV_VAULT_STORAGE_FAILED"); }
   using(var f=new FileStream(h,FileAccess.Read)) {
     if(FileIdentity(f)!=identity || f.Length>16384) throw new IOException("ALEKOV_VAULT_COMPARE_FAILED");
     using(var sha=SHA256.Create()) if(BitConverter.ToString(sha.ComputeHash(f)).Replace("-","").ToLowerInvariant()!=digest) throw new IOException("ALEKOV_VAULT_COMPARE_FAILED");
     byte remove=1;
     if(!SetFileInformationByHandle(f.SafeFileHandle,4,ref remove,1)) throw new IOException("ALEKOV_VAULT_STORAGE_FAILED");
   }
 }
}
'@
  [void][Reflection.Assembly]::LoadWithPartialName('System.Security')
  $script:rootPath = [IO.Path]::GetFullPath([string]$request.vaultRoot)
  if ($rootPath -cnotmatch '^[A-Za-z]:\\' -or $rootPath.Substring(2).Contains(':') -or ![IO.Directory]::Exists($rootPath) -or
      $rootPath.TrimEnd('\') -ceq [IO.Path]::GetPathRoot($rootPath).TrimEnd('\')) { Fail 'ALEKOV_VAULT_PATH_UNSAFE' }
  # Hold every directory identity against rename/reparse replacement during this operation.
  $chain = New-Object Collections.Generic.List[string]
  $dir = New-Object IO.DirectoryInfo($rootPath)
  while ($null -ne $dir) { $chain.Add($dir.FullName); $dir=$dir.Parent }
  for ($i=$chain.Count-1; $i -ge 0; $i--) { $held.Add([AlekovVaultNative]::DirectoryLock($chain[$i])) }
  $mutexAcl=New-Object Security.AccessControl.MutexSecurity
  $mutexAcl.SetAccessRuleProtection($true,$false)
  $mutexAcl.AddAccessRule((New-Object Security.AccessControl.MutexAccessRule($ownerSid,'FullControl','Allow')))
  $created=$false
  $mutexName='Local\AlekovAppCredentialV1_'+(Hash (Utf8 ($ownerSid.Value+'|'+$rootPath.ToLowerInvariant())))
  $script:mutex=New-Object Threading.Mutex($false,$mutexName,[ref]$created,$mutexAcl)
  try { $script:mutexHeld=$mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $script:mutexHeld=$true; Fail 'ALEKOV_VAULT_OUTCOME_UNKNOWN' }
  if (!$mutexHeld) { Fail 'ALEKOV_VAULT_BUSY' }

  function AssertAcl([string]$p) {
    $acl = Get-Acl -LiteralPath $p
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $ownerSid.Value -or !$acl.AreAccessRulesProtected) { Fail 'ALEKOV_VAULT_OWNER_MISMATCH' }
    $rules = @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne 1 -or $rules[0].IdentityReference.Value -cne $ownerSid.Value -or $rules[0].AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
        $rules[0].FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl) { Fail 'ALEKOV_VAULT_ACL_UNSAFE' }
  }
  function SetPrivateAcl([string]$p, [bool]$directory) {
    if ($directory) { $acl = New-Object Security.AccessControl.DirectorySecurity } else { $acl = New-Object Security.AccessControl.FileSecurity }
    $acl.SetOwner($ownerSid); $acl.SetAccessRuleProtection($true,$false)
    if ($directory) { $rule = New-Object Security.AccessControl.FileSystemAccessRule($ownerSid,'FullControl','ContainerInherit, ObjectInherit','None','Allow') }
    else { $rule = New-Object Security.AccessControl.FileSystemAccessRule($ownerSid,'FullControl','Allow') }
    $acl.AddAccessRule($rule); Set-Acl -LiteralPath $p -AclObject $acl
    AssertAcl $p
  }
  function OpenOwned([string]$p) {
    if (([IO.File]::GetAttributes($p) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Fail 'ALEKOV_VAULT_PATH_UNSAFE' }
    $stream = [IO.File]::Open($p,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
    try { [void][AlekovVaultNative]::FileIdentity($stream); AssertAcl $p; return $stream } catch { $stream.Dispose(); throw }
  }
  function Bytes($stream) {
    if ($stream.Length -gt 16384) { Fail 'ALEKOV_VAULT_RECORD_INVALID' }
    $stream.Position=0; $b=New-Object byte[] ([int]$stream.Length); $offset=0
    while ($offset -lt $b.Length) { $read=$stream.Read($b,$offset,$b.Length-$offset); if ($read -le 0) { Fail 'ALEKOV_VAULT_RECORD_INVALID' }; $offset += $read }
    return ,$b
  }
  function WriteNew([string]$p,[byte[]]$bytes) {
    $stream = [IO.File]::Open($p,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try { SetPrivateAcl $p $false; $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true); [void][AlekovVaultNative]::FileIdentity($stream) } finally { $stream.Dispose() }
  }
  $markerPath = [IO.Path]::Combine($rootPath,'.alekov-owner.json')
  if (![IO.File]::Exists($markerPath)) {
    # Adoption is limited to an existing, empty directory owned by the execution user.
    $rootAcl=Get-Acl -LiteralPath $rootPath
    if ($rootAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $ownerSid.Value -or [IO.Directory]::GetFileSystemEntries($rootPath).Length -ne 0) { Fail 'ALEKOV_VAULT_OWNER_MISMATCH' }
    SetPrivateAcl $rootPath $true
    $marker = [ordered]@{schema='alekov.app-vault.owner.v1';appId='aleph-on';audience='on-client';ownerSid=$ownerSid.Value;vaultId=[Guid]::NewGuid().ToString('D')}
    WriteNew $markerPath (Utf8 (Json $marker))
  }
  AssertAcl $rootPath
  $markerStream=OpenOwned $markerPath; $held.Add($markerStream)
  $marker=[Text.Encoding]::UTF8.GetString((Bytes $markerStream)) | ConvertFrom-Json
  if (!(Exact $marker @('schema','appId','audience','ownerSid','vaultId')) -or $marker.schema -cne 'alekov.app-vault.owner.v1' -or $marker.appId -cne 'aleph-on' -or
      $marker.audience -cne 'on-client' -or $marker.ownerSid -cne $ownerSid.Value -or $marker.vaultId -cnotmatch '^[a-f0-9-]{36}$') { Fail 'ALEKOV_VAULT_OWNER_MISMATCH' }
  $recordPath=[IO.Path]::Combine($rootPath,$request.contextFingerprint+'.credential')
  $entropy=Utf8 ('alekov.app-vault.record.v1|'+$marker.vaultId+'|'+$request.contextFingerprint)
  function ReadRecord([string]$p, [bool]$requireCurrent) {
    $stream=OpenOwned $p
    try {
      $identity=[AlekovVaultNative]::FileIdentity($stream); $bytes=Bytes $stream
      $record=[Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
      if (!(Exact $record @('schema','vaultId','contextFingerprint','credentialFingerprint','protected')) -or $record.schema -cne 'alekov.app-vault.record.v1' -or
          $record.vaultId -cne $marker.vaultId -or $record.contextFingerprint -cne $request.contextFingerprint -or $record.credentialFingerprint -cnotmatch '^[a-f0-9]{64}$' -or
          $record.protected -isnot [string]) { Fail 'ALEKOV_VAULT_RECORD_INVALID' }
      $clear=[Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($record.protected),$entropy,[Security.Cryptography.DataProtectionScope]::CurrentUser)
      try { $credential=[Text.Encoding]::UTF8.GetString($clear) | ConvertFrom-Json } finally { [Array]::Clear($clear,0,$clear.Length) }
      ValidateCredential $credential $requireCurrent
      if ((Hash (Utf8 $credential.token)) -cne $record.credentialFingerprint) { Fail 'ALEKOV_VAULT_RECORD_INVALID' }
      return @{identity=$identity;digest=(Hash $bytes);credential=$credential;fingerprint=$record.credentialFingerprint}
    } finally { $stream.Dispose() }
  }
  $previous=$null
  if ([IO.File]::Exists($recordPath)) { $previous=ReadRecord $recordPath ($request.action -ceq 'load') }
  elseif ([IO.Directory]::Exists($recordPath)) { Fail 'ALEKOV_VAULT_PATH_UNSAFE' }
  if ($request.action -ceq 'remove' -and $null -ne $previous -and $previous.fingerprint -cne $request.credentialFingerprint) { Fail 'ALEKOV_VAULT_COMPARE_FAILED' }
  if ($request.action -ceq 'save') {
    $clear=Utf8 (Json $request.credential)
    try { $encrypted=[Security.Cryptography.ProtectedData]::Protect($clear,$entropy,[Security.Cryptography.DataProtectionScope]::CurrentUser) } finally { [Array]::Clear($clear,0,$clear.Length) }
    $newRecord=[ordered]@{schema='alekov.app-vault.record.v1';vaultId=$marker.vaultId;contextFingerprint=$request.contextFingerprint;credentialFingerprint=(Hash (Utf8 $request.credential.token));protected=[Convert]::ToBase64String($encrypted)}
    $script:temporary=[IO.Path]::Combine($rootPath,'.alekov-'+[Guid]::NewGuid().ToString('N')+'.tmp')
    WriteNew $temporary (Utf8 (Json $newRecord))
    $prepared=ReadRecord $temporary $true
    $script:temporaryIdentity=$prepared.identity; $script:temporaryDigest=$prepared.digest
  }
  Alive; Emit @{stage='ready';nonce=$request.nonce}
  $commit=(ReadLineBounded 128) | ConvertFrom-Json
  if (!(Exact $commit @('commit')) -or $commit.commit -cne $request.nonce) { Fail 'ALEKOV_VAULT_CANCELLED' }
  Alive
  # Recheck the exact record after the host's final current-context callback.
  $now=$null
  if ([IO.File]::Exists($recordPath)) { $now=ReadRecord $recordPath ($request.action -ceq 'load') }
  elseif ([IO.Directory]::Exists($recordPath)) { Fail 'ALEKOV_VAULT_PATH_UNSAFE' }
  if (($null -eq $previous) -ne ($null -eq $now) -or ($null -ne $previous -and ($previous.identity -cne $now.identity -or $previous.digest -cne $now.digest))) { Fail 'ALEKOV_VAULT_COMPARE_FAILED' }
  AssertAcl $rootPath; [void][AlekovVaultNative]::FileIdentity($markerStream); Alive
  if ($request.action -ceq 'save') {
    ValidateCredential $request.credential
    $tempRecord=ReadRecord $temporary $true
    if ($tempRecord.fingerprint -cne $newRecord.credentialFingerprint) { Fail 'ALEKOV_VAULT_COMPARE_FAILED' }
    if ($null -eq $previous) { [IO.File]::Move($temporary,$recordPath); $script:temporary=$null }
    else {
      $backup=[IO.Path]::Combine($rootPath,'.alekov-'+[Guid]::NewGuid().ToString('N')+'.bak')
      [IO.File]::Replace($temporary,$recordPath,$backup,$false)
      $script:temporary=$null
      # Preserve the backup on ambiguity. Do not overwrite a concurrent external actor.
      $replaced=ReadRecord $backup $false
      if ($replaced.identity -cne $previous.identity -or $replaced.digest -cne $previous.digest) { Fail 'ALEKOV_VAULT_OUTCOME_UNKNOWN' }
    }
    $saved=ReadRecord $recordPath $true
    if ($saved.identity -cne $tempRecord.identity -or $saved.digest -cne $tempRecord.digest -or $saved.fingerprint -cne $newRecord.credentialFingerprint) { Fail 'ALEKOV_VAULT_OUTCOME_UNKNOWN' }
    if ($null -ne $previous) { [AlekovVaultNative]::DeleteExact($backup,$replaced.identity,$replaced.digest) }
    $result=@{connectionId=$request.connectionId;credentialFingerprint=$newRecord.credentialFingerprint;contextFingerprint=$request.contextFingerprint;persisted=$true}
  } elseif ($request.action -ceq 'load') {
    $result=$null; if ($null -ne $now) { $result=$now.credential }
  } else {
    $removed=$false
    if ($null -ne $now) {
      [AlekovVaultNative]::DeleteExact($recordPath,$now.identity,$now.digest)
      $removed=$true
    }
    $result=@{removed=$removed;contextFingerprint=$request.contextFingerprint;credentialFingerprint=$request.credentialFingerprint}
  }
  Emit @{ok=$true;result=$result}
} catch {
  $code='ALEKOV_VAULT_STORAGE_FAILED'
  if ($_.Exception.Message -cmatch '^ALEKOV_VAULT_[A-Z_]+$') { $code=$_.Exception.Message }
  Emit @{ok=$false;code=$code}
  exit 1
} finally {
  # Only our freshly generated encrypted temporary file is eligible for cleanup.
  if ($null -ne $temporary -and $null -ne $temporaryIdentity -and [IO.File]::Exists($temporary)) {
    try { [AlekovVaultNative]::DeleteExact($temporary,$temporaryIdentity,$temporaryDigest) } catch { }
  }
  if ($mutexHeld) { $mutex.ReleaseMutex() }
  if ($null -ne $mutex) { $mutex.Dispose() }
  for ($i=$held.Count-1; $i -ge 0; $i--) { $held[$i].Dispose() }
}
