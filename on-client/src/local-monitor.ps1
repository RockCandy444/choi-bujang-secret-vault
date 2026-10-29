$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$result = [ordered]@{}

# Fixed, read-only queries. No names, addresses, event messages or credentials leave this process.
try {
  $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
  if ($profiles.Count -ne 3) { throw 'IncompleteProfiles' }
  foreach ($profile in $profiles) {
    if ([string]$profile.Enabled -notin @('True', 'False')) { throw 'UnverifiedProfile' }
  }
  $result.firewall = @{ status = 'ok'; profiles = @($profiles | ForEach-Object {
    @{ name = [string]$_.Name; enabled = ([string]$_.Enabled -eq 'True') }
  }) }
} catch { $result.firewall = @{ status = 'unknown'; reason = '방화벽 설정을 읽지 못했습니다. Windows 보안에서 직접 확인하세요.' } }

$logs = @()
foreach ($log in @('System', 'Application')) {
  try {
    $entries = @(Get-WinEvent -FilterHashtable @{ LogName = $log; Level = @(2, 3); StartTime = (Get-Date).AddHours(-24) } -MaxEvents 2001 -ErrorAction Stop)
    $limited = $entries.Count -gt 2000
    $entries = @($entries | Select-Object -First 2000)
    $logs += @{ name = $log; status = 'ok'; errors = @($entries | Where-Object Level -eq 2).Count; warnings = @($entries | Where-Object Level -eq 3).Count; truncated = $limited }
  } catch {
    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
      $logs += @{ name = $log; status = 'ok'; errors = 0; warnings = 0; truncated = $false }
    } else {
      $logs += @{ name = $log; status = 'unknown'; reason = '이 기록을 읽지 못했습니다. 이벤트 뷰어에서 직접 확인하세요.' }
    }
  }
}
$result.events = @{ status = 'ok'; logs = $logs; windowHours = 24; limitPerLog = 2000 }
$result.checkedAt = [DateTime]::UtcNow.ToString('o')
$result | ConvertTo-Json -Depth 5 -Compress
