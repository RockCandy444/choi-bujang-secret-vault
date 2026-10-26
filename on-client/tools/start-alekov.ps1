<#
  앱 학생 앱 실행 도구 (ALEKOV-STUDENT-LAUNCH-GUIDE-01, 채널 #705 묶음 3)

  하는 일
   - 이 파일이 들어 있는 앱 폴더(on-client)의 src/server.mjs 하나만 실행합니다.
   - 실행 전에 Node.js 버전, 폴더 구성, 포트 사용 여부를 확인합니다.
   - 서버가 뜨면 브라우저로 열 주소를 알려 줍니다. AI 연결 여부는 화면에서 확인합니다.

  하지 않는 일
   - 프로그램 설치, 전역 실행 정책 변경, 드라이버·터널·인증 설정을 하지 않습니다.
   - 이미 포트를 쓰는 다른 프로그램을 종료하지 않습니다.
   - 열쇠·토큰 같은 비밀 환경변수를 서버에 넘기거나 화면·기록에 남기지 않습니다.

  사용 (앱 폴더에서)
    powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-alekov.ps1
    powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-alekov.ps1 -Port 5190
    powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-alekov.ps1 -Background
  -ExecutionPolicy Bypass 는 이 한 번의 실행에만 적용되며 컴퓨터 설정을 바꾸지 않습니다.
#>
[CmdletBinding()]
param(
  [ValidateRange(1024, 65535)][int]$Port = 5189,
  [switch]$Demo,
  [switch]$Background,
  [string]$NativeHostConfig,
  [switch]$NoNativeHost,
  [string]$SdpHostConfig,
  [ValidateRange(1, 120)][int]$WaitSeconds = 20
)
Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

function Say([string]$text) { Write-Host $text }
function Stop-With([string]$text, [int]$code = 1) { Write-Host $text -ForegroundColor Yellow; exit $code }

# 1) 폴더 확인: 이 스크립트가 있는 tools 의 상위가 앱 폴더여야 합니다.
$root = Split-Path -Parent $PSScriptRoot
$server = Join-Path $root 'src\server.mjs'
$package = Join-Path $root 'package.json'
foreach ($path in @($root, $server, $package)) {
  if (-not (Test-Path -LiteralPath $path)) { Stop-With "앱 폴더가 아닙니다. 받은 시작 틀의 on-client 폴더 안에서 tools\start-alekov.ps1 을 실행해 주세요. (없는 파일: $path)" }
  $item = Get-Item -LiteralPath $path -Force
  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { Stop-With "바로가기(링크)로 연결된 폴더나 파일에서는 실행하지 않습니다. 실제 앱 폴더(on-client)에서 실행해 주세요. ($path)" }
}
try { $meta = Get-Content -LiteralPath $package -Raw -Encoding UTF8 | ConvertFrom-Json } catch { Stop-With 'package.json 을 읽지 못했습니다. 시작 틀을 다시 받아 주세요.' }
if ($meta.name -ne 'alekov-client-starter') { Stop-With '시작 틀 폴더가 아닙니다. 받은 시작 틀의 on-client 폴더에서 실행해 주세요.' }

# 계정 연결용 로컬 보관소만 자동 준비한다. 로그인·승인·AI 요청은 학생이 화면에서 직접 한다.
if ($NoNativeHost -and $PSBoundParameters.ContainsKey('NativeHostConfig')) { Stop-With 'NoNativeHost와 NativeHostConfig는 함께 사용할 수 없습니다.' }
if (-not $Demo -and -not $NoNativeHost -and -not $PSBoundParameters.ContainsKey('NativeHostConfig')) {
  $projectRoot = Split-Path -Parent $root
  # 패키지 앱에서 LocalAppData 쓰기는 별도 가상 경로로 바뀔 수 있다. 사용자 홈의 고정 개인 경로를 쓴다.
  $profileRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
  if ([string]::IsNullOrWhiteSpace($profileRoot)) { Stop-With 'Windows 사용자 폴더를 확인하지 못했습니다. 사용자 계정의 개인 폴더를 확인해 주세요.' }
  $hasher = [Security.Cryptography.SHA256]::Create()
  try { $projectKey = ([BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($projectRoot.ToLowerInvariant())))).Replace('-','').ToLowerInvariant() } finally { $hasher.Dispose() }
  $hostRoot = Join-Path $profileRoot ('.aleph-keshev-' + $projectKey)
  $preparer = Join-Path $PSScriptRoot 'prepare-native-host.ps1'
  if (-not (Test-Path -LiteralPath $preparer -PathType Leaf)) { Stop-With '계정 연결 준비 도구가 빠졌습니다. 기존 작업을 보존한 채 최신 시작 틀로 갱신해 주세요.' }
  $preparedText = & 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $preparer -ProjectRoot $projectRoot -HostRoot $hostRoot -Create -ReuseExisting
  $preparedExit = $LASTEXITCODE
  try { $prepared = ($preparedText | Out-String) | ConvertFrom-Json } catch { Stop-With '계정 연결 설정을 확인하지 못했습니다. 기존 설정과 학생 작업은 그대로 두었습니다.' }
  if ($preparedExit -ne 0 -or $prepared.ok -ne $true) { Stop-With ('계정 연결 설정을 준비하지 못했습니다. 기존 설정과 학생 작업은 그대로 두었습니다. ' + $prepared.error.code + ' / ' + $prepared.stage) }
  $expectedConfig = Join-Path $hostRoot 'native.json'
  if (-not [string]::Equals($prepared.configurationPath,$expectedConfig,[StringComparison]::OrdinalIgnoreCase)) { Stop-With '계정 연결 설정 경로가 일치하지 않습니다. 기존 설정은 변경하지 않았습니다.' }
  $NativeHostConfig = $expectedConfig
  $PSBoundParameters['NativeHostConfig'] = $NativeHostConfig
  Say '계정 연결 준비가 끝났습니다. 앱에서 확인 번호로 로그인·승인을 진행하세요.'
}

# 명시한 설정 파일만 전달한다. 내용·소유 SID·보호 ACL은 native startup이 최종 확인한다.
$nativeArgument = ''
if ($PSBoundParameters.ContainsKey('NativeHostConfig')) {
  if ([string]::IsNullOrWhiteSpace($NativeHostConfig) -or $NativeHostConfig -notmatch '^[A-Za-z]:\\' -or
      $NativeHostConfig -match '["\x00-\x1f\x7f]' -or $NativeHostConfig.Substring(2).Contains(':')) {
    Stop-With 'NativeHostConfig에는 따옴표·제어문자·대체 스트림이 없는 Windows 절대 파일 경로를 지정해 주세요.'
  }
  try {
    $absoluteConfig = [IO.Path]::GetFullPath($NativeHostConfig)
    if (-not [string]::Equals($absoluteConfig, $NativeHostConfig, [StringComparison]::OrdinalIgnoreCase)) { throw 'PATH_NOT_CANONICAL' }
    $configItem = Get-Item -LiteralPath $absoluteConfig -Force
    if ($configItem -isnot [IO.FileInfo]) { throw 'CONFIG_NOT_FILE' }
    for ($currentItem = $configItem; $null -ne $currentItem; $currentItem = $(if ($currentItem -is [IO.FileInfo]) { $currentItem.Directory } else { $currentItem.Parent })) {
      if ($currentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'CONFIG_LINK_REJECTED' }
    }
  } catch { Stop-With 'NativeHostConfig 파일이나 상위 경로를 확인하지 못했습니다. 실제 일반 파일의 정규화된 절대 경로를 지정해 주세요.' }
  $nativeArgument = ' --native-host-config "' + $absoluteConfig + '"'
}

# SDP 개인 자격은 별도 설정 파일로 선택한다. 이 도구는 파일 내용을 읽지 않는다.
$sdpArgument = ''
if ($PSBoundParameters.ContainsKey('SdpHostConfig')) {
  if ($Demo) { Stop-With 'SDP 연결과 예제 모드는 함께 실행할 수 없습니다.' }
  if ([string]::IsNullOrWhiteSpace($SdpHostConfig) -or $SdpHostConfig -notmatch '^[A-Za-z]:\\' -or
      $SdpHostConfig -match '["\x00-\x1f\x7f]' -or $SdpHostConfig.Substring(2).Contains(':')) {
    Stop-With 'SdpHostConfig에는 따옴표·제어문자·대체 스트림이 없는 Windows 절대 파일 경로를 지정해 주세요.'
  }
  try {
    $sdpConfigPath = [IO.Path]::GetFullPath($SdpHostConfig)
    if (-not [string]::Equals($sdpConfigPath, $SdpHostConfig, [StringComparison]::OrdinalIgnoreCase)) { throw 'PATH_NOT_CANONICAL' }
    $sdpConfigItem = Get-Item -LiteralPath $sdpConfigPath -Force
    if ($sdpConfigItem -isnot [IO.FileInfo]) { throw 'CONFIG_NOT_FILE' }
    for ($sdpCurrent = $sdpConfigItem; $null -ne $sdpCurrent; $sdpCurrent = $(if ($sdpCurrent -is [IO.FileInfo]) { $sdpCurrent.Directory } else { $sdpCurrent.Parent })) {
      if ($sdpCurrent.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'CONFIG_LINK_REJECTED' }
    }
  } catch { Stop-With 'SDP 설정 파일과 상위 경로를 확인하지 못했습니다. 실제 일반 파일의 정규화된 절대 경로를 지정해 주세요.' }
  $sdpArgument = ' --sdp-host-config "' + $sdpConfigPath + '"'
}

# 2) Node.js 확인: 설치하지 않고 안내만 합니다.
$node = Get-Command node -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $node) { Stop-With 'Node.js 가 없습니다. https://nodejs.org 에서 Node.js 24.19.0(LTS)을 설치한 뒤 새 PowerShell 창에서 다시 실행해 주세요.' }
$versionText = (& $node.Source --version 2>$null | Out-String).Trim()
if ($versionText -notmatch '^v(\d+)\.(\d+)\.(\d+)$') { Stop-With "Node.js 버전을 확인하지 못했습니다($versionText). Node.js 24.19.0 을 설치해 주세요." }
$major = [int]$Matches[1]
if ($major -lt 22 -or $major -gt 24) { Stop-With "지금 Node.js 는 $versionText 입니다. 앱은 Node.js 22~24 에서 실행합니다. Node.js 24.19.0 을 권장합니다." }
if ($versionText -ne 'v24.19.0') { Say "참고: 지금 Node.js 는 $versionText 입니다. 수업 기준은 v24.19.0 입니다." }

# 3) 포트 확인: 사용 중이면 다른 프로그램을 끄지 않고 다른 번호를 안내합니다.
$busy = $false
try {
  $probe = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
  $probe.Start(); $probe.Stop()
} catch { $busy = $true }
if ($busy) { Stop-With "포트 $Port 를 다른 프로그램이 쓰고 있습니다. 그 프로그램은 그대로 두고, 다른 번호로 실행해 주세요. 예: -Port $($Port + 1)" }

# 4) 실행: 셸(cmd·PowerShell)을 거치지 않고 node 를 직접 실행합니다. 비밀로 보이는 환경변수는 넘기지 않습니다.
$info = [Diagnostics.ProcessStartInfo]::new()
$info.FileName = $node.Source
$info.WorkingDirectory = $root
$info.UseShellExecute = $false
# Windows 경로에는 큰따옴표가 들어갈 수 없으므로 경로를 큰따옴표로 감싸 한 인자로 넘깁니다(공백·한글 경로 포함).
$info.Arguments = '"' + $server + '"' + $(if ($Demo) { ' --demo' } else { '' }) + $nativeArgument + $sdpArgument
$secret = '(?i)(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|^ON_AI_|^OPENAI|^ANTHROPIC|^SUPABASE)'
foreach ($name in @($info.EnvironmentVariables.Keys)) { if ($name -match $secret) { $info.EnvironmentVariables.Remove($name) } }
$info.EnvironmentVariables['ON_PORT'] = [string]$Port
if ($Background) {
  $info.CreateNoWindow = $true
  $info.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
}
$process = [Diagnostics.Process]::Start($info)
$url = "http://127.0.0.1:$Port/"

# 5) 뜰 때까지 기다린 뒤 주소를 알려 줍니다. 서버가 응답한 것만 확인하며, AI 연결 성공을 뜻하지 않습니다.
$ready = $false
$deadline = (Get-Date).AddSeconds($WaitSeconds)
while ((Get-Date) -lt $deadline -and -not $process.HasExited) {
  try {
    $response = Invoke-WebRequest -UseBasicParsing -Uri $url -TimeoutSec 2
    if ($response.StatusCode -eq 200) { $ready = $true; break }
  } catch { Start-Sleep -Milliseconds 300 }
}
if (-not $ready) {
  if (-not $process.HasExited) { $process.Kill() }
  Stop-With "앱 서버가 $WaitSeconds 초 안에 뜨지 않았습니다. 이 창의 메시지를 담당 강사에게 보여 주세요."
}
Say "케셰브가 켜졌습니다. 브라우저에서 $url 을 여세요."
Say '서버가 응답한 것만 확인했습니다. AI 연결 상태는 화면에서 따로 확인해 주세요.'
if ($Background) {
  Say "뒤에서 실행 중입니다(프로세스 번호 $($process.Id)). 끄려면 이 번호의 node 를 작업 관리자에서 종료하세요."
  exit 0
}
Say '끄려면 이 창에서 Ctrl+C 를 누르세요.'
$process.WaitForExit()
exit $process.ExitCode
