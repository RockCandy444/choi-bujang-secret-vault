<#
  학생 프로젝트 밖의 새 전용 폴더에 앱 호스트 설정을 준비합니다.
  -Create 없이는 검사 결과만 출력합니다. 기존 파일·권한·저장소를 변경하지 않습니다.
  로그인, 열쇠 발급, 서버 실행, 네트워크 요청은 하지 않습니다.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$ProjectRoot,
  [Parameter(Mandatory=$true)][string]$HostRoot,
  [switch]$Create
)
# Use only modules supplied by this running PowerShell engine; preserve every ACL/identity check.
$env:PSModulePath=[IO.Path]::Combine($PSHOME,'Modules')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
$held=New-Object Collections.Generic.List[IDisposable]
$createdPaths=New-Object Collections.Generic.List[string]
$stage='validate'
$failure='ALEKOV_NATIVE_PREPARE_FAILED'
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
function Reject([string]$code){$script:failure=$code;throw $code}
function Emit($value){[Console]::Out.WriteLine((ConvertTo-Json -InputObject $value -Depth 6 -Compress))}
function Hash([byte[]]$bytes){$sha=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}}
function LocalPath([string]$raw){
  if($raw -cnotmatch '^[A-Za-z]:\\' -or $raw.Substring(2).Contains(':') -or $raw.IndexOfAny([IO.Path]::GetInvalidPathChars()) -ge 0 -or $raw.Contains('"')){Reject 'ALEKOV_NATIVE_PREPARE_PATH_UNSAFE'}
  $full=[IO.Path]::GetFullPath($raw).TrimEnd('\')
  if(![string]::Equals($full,$raw.TrimEnd('\'),[StringComparison]::OrdinalIgnoreCase) -or $full.Length -le 3 -or @($full.Substring(3).Split('\')|Where-Object{!$_ -or $_ -match '[. ]$'}).Count -gt 0){Reject 'ALEKOV_NATIVE_PREPARE_PATH_UNSAFE'}
  return $full
}
function Under([string]$a,[string]$b){return [string]::Equals($a,$b,[StringComparison]::OrdinalIgnoreCase) -or $a.StartsWith($b+'\',[StringComparison]::OrdinalIgnoreCase)}
function PrivateSecurity([bool]$directory){
  if($directory){$security=New-Object Security.AccessControl.DirectorySecurity;$rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit, ObjectInherit','None','Allow')}
  else{$security=New-Object Security.AccessControl.FileSecurity;$rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','Allow')}
  $security.SetOwner($sid);$security.SetAccessRuleProtection($true,$false);$security.AddAccessRule($rule);return $security
}
function CheckAcl([string]$p){
  $acl=Get-Acl -LiteralPath $p;$rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
  if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $sid.Value -or !$acl.AreAccessRulesProtected -or $rules.Count -ne 1 -or $rules[0].IdentityReference.Value -cne $sid.Value -or $rules[0].AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $rules[0].FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl){Reject 'ALEKOV_NATIVE_PREPARE_ACL_UNSAFE'}
}
try{
  $project=LocalPath $ProjectRoot;$hostPath=LocalPath $HostRoot
  if((Under $hostPath $project) -or (Under $project $hostPath)){Reject 'ALEKOV_NATIVE_PREPARE_NESTED'}
  if(![IO.Directory]::Exists($project)){Reject 'ALEKOV_NATIVE_PREPARE_PROJECT_MISSING'}
  if(Test-Path -LiteralPath $hostPath){Reject 'ALEKOV_NATIVE_PREPARE_EXISTS'}
  $parent=[IO.Path]::GetDirectoryName($hostPath)
  if(![IO.Directory]::Exists($parent)){Reject 'ALEKOV_NATIVE_PREPARE_PARENT_MISSING'}
  Add-Type -TypeDefinition @'
using System;using System.IO;using System.Text;using System.ComponentModel;using System.Runtime.InteropServices;using Microsoft.Win32.SafeHandles;
public static class AlekovNativePrepare {
 [StructLayout(LayoutKind.Sequential)] struct INFO {public uint attr;public System.Runtime.InteropServices.ComTypes.FILETIME c,a,w;public uint vol,hi,lo,links,indexHi,indexLo;}
 [StructLayout(LayoutKind.Sequential)] struct SECURITY {public int length;public IntPtr descriptor;public int inherit;}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFile(string p,uint a,uint s,IntPtr z,uint c,uint f,IntPtr t);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,EntryPoint="CreateFileW")] static extern SafeFileHandle CreatePrivateFile(string p,uint a,uint s,ref SECURITY z,uint c,uint f,IntPtr t);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateDirectory(string p,ref SECURITY z);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle h,out INFO i);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandle(SafeFileHandle h,StringBuilder p,uint size,uint flags);
 public static string Identity(SafeFileHandle h,bool directory){INFO i;if(h.IsInvalid||!GetFileInformationByHandle(h,out i)||(i.attr&0x400)!=0||((i.attr&0x10)!=0)!=directory||(!directory&&i.links!=1))throw new IOException("UNSAFE_IDENTITY");return i.vol.ToString("x8")+i.indexHi.ToString("x8")+i.indexLo.ToString("x8")+":"+i.c.dwHighDateTime.ToString("x8")+i.c.dwLowDateTime.ToString("x8");}
 public static SafeFileHandle Hold(string p){var h=CreateFile(p,0x80,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);try{Identity(h,true);var name=new StringBuilder(32768);uint n=GetFinalPathNameByHandle(h,name,(uint)name.Capacity,0);if(n==0||n>=name.Capacity)throw new IOException("UNSAFE_PATH");string final=name.ToString();if(final.StartsWith(@"\\?\",StringComparison.Ordinal))final=final.Substring(4);if(!String.Equals(final.TrimEnd('\\'),Path.GetFullPath(p).TrimEnd('\\'),StringComparison.OrdinalIgnoreCase))throw new IOException("PATH_ALIAS_REJECTED");return h;}catch{h.Dispose();throw;}}
 public static void MakeDirectory(string p,byte[] descriptor){var pin=GCHandle.Alloc(descriptor,GCHandleType.Pinned);try{var sa=new SECURITY{length=Marshal.SizeOf(typeof(SECURITY)),descriptor=pin.AddrOfPinnedObject(),inherit=0};if(!CreateDirectory(p,ref sa))throw new Win32Exception(Marshal.GetLastWin32Error());}finally{pin.Free();}}
 public static FileStream WriteNew(string p,byte[] descriptor,byte[] bytes){var pin=GCHandle.Alloc(descriptor,GCHandleType.Pinned);SafeFileHandle handle=null;try{var sa=new SECURITY{length=Marshal.SizeOf(typeof(SECURITY)),descriptor=pin.AddrOfPinnedObject(),inherit=0};handle=CreatePrivateFile(p,0xC0000000,0,ref sa,1,0x80200080,IntPtr.Zero);if(handle.IsInvalid)throw new Win32Exception(Marshal.GetLastWin32Error());var stream=new FileStream(handle,FileAccess.ReadWrite);try{stream.Write(bytes,0,bytes.Length);stream.Flush(true);Identity(stream.SafeFileHandle,false);return stream;}catch{stream.Dispose();throw;}}catch{if(handle!=null)handle.Dispose();throw;}finally{pin.Free();}}
}
'@
  function HoldOne([string]$p){try{$handle=[AlekovNativePrepare]::Hold($p)}catch{Reject 'ALEKOV_NATIVE_PREPARE_PATH_UNSAFE'};$held.Add($handle);return @{path=$p;handle=$handle;identity=[AlekovNativePrepare]::Identity($handle,$true)}}
  function HoldChain([string]$p){$chain=New-Object Collections.Generic.List[string];$d=New-Object IO.DirectoryInfo($p);while($null -ne $d){$chain.Add($d.FullName);$d=$d.Parent};for($i=$chain.Count-1;$i -ge 0;$i--){HoldOne $chain[$i]}}
  $projectChain=@(HoldChain $project);$parentChain=@(HoldChain $parent);$projectProof=$projectChain[-1];$parentProof=$parentChain[-1]
  if(@($parentChain|Where-Object{$_.identity -ceq $projectProof.identity}).Count -gt 0){Reject 'ALEKOV_NATIVE_PREPARE_NESTED'}
  $registry=[IO.Path]::Combine($hostPath,'registry');$vault=[IO.Path]::Combine($hostPath,'vault');$configPath=[IO.Path]::Combine($hostPath,'native.json')
  if(!$Create){Emit @{ok=$true;created=$false;configurationPath=$configPath;projectRoot=$project;hostRoot=$hostPath};exit 0}
  $directorySecurity=PrivateSecurity $true;$fileSecurity=PrivateSecurity $false
  $proofs=New-Object Collections.Generic.List[object]
  foreach($target in @($hostPath,$registry,$vault)){
    $stage='create-directory';[AlekovNativePrepare]::MakeDirectory($target,$directorySecurity.GetSecurityDescriptorBinaryForm());$createdPaths.Add($target)
    $proofs.Add((HoldOne $target));CheckAcl $target
  }
  $config=[ordered]@{enabled=$true;registryRoot=$registry;vaultRoot=$vault;projectRoot=$project;gatewayOrigin='https://ai-classroom-gateway-production.up.railway.app';portalOrigin='https://aleph-omega.vercel.app'}
  $bytes=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $config -Compress)+"`n")
  $stage='create-config';$file=[AlekovNativePrepare]::WriteNew($configPath,$fileSecurity.GetSecurityDescriptorBinaryForm(),$bytes);$held.Add($file);$createdPaths.Add($configPath)
  $fileIdentity=[AlekovNativePrepare]::Identity($file.SafeFileHandle,$false);CheckAcl $configPath
  $stage='verify';$file.Position=0;$actual=New-Object byte[] ([int]$file.Length);$offset=0;while($offset -lt $actual.Length){$n=$file.Read($actual,$offset,$actual.Length-$offset);if($n -le 0){Reject 'ALEKOV_NATIVE_PREPARE_CHANGED'};$offset+=$n}
  if((Hash $bytes) -cne (Hash $actual) -or [AlekovNativePrepare]::Identity($file.SafeFileHandle,$false) -cne $fileIdentity){Reject 'ALEKOV_NATIVE_PREPARE_CHANGED'}
  foreach($proof in @($projectProof,$parentProof)+@($proofs.ToArray())){if([AlekovNativePrepare]::Identity($proof.handle,$true) -cne $proof.identity){Reject 'ALEKOV_NATIVE_PREPARE_CHANGED'}}
  foreach($target in @($hostPath,$registry,$vault,$configPath)){CheckAcl $target}
  Emit @{ok=$true;created=$true;configurationPath=$configPath;projectRoot=$project;hostRoot=$hostPath;configSha256=(Hash $actual)}
}catch{
  Emit @{ok=$false;error=@{code=$failure;message='호스트 설정을 준비하지 못했습니다. 기존 파일은 변경하지 않았으며, 이번에 만든 항목은 확인할 수 있도록 남겨 두었습니다.'};stage=$stage;createdPaths=@($createdPaths.ToArray())}
  exit 1
}finally{for($i=$held.Count-1;$i -ge 0;$i--){$held[$i].Dispose()}}
