import os from 'node:os';
import { statfs } from 'node:fs/promises';
import { parse, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';

const exec = promisify(execFile);
const unknown = reason => ({ status: 'unknown', reason });
const count = value => Number.isSafeInteger(value) && value >= 0;
const stamp = () => new Date().toISOString();

export function normalizeWindows(input) {
  const fallback = unknown('Windows 조회 결과를 확인할 수 없습니다. Windows 보안·이벤트 뷰어에서 확인하세요.');
  const profiles = input?.firewall?.profiles;
  const validProfiles = Array.isArray(profiles) && profiles.length === 3
    && ['Domain', 'Private', 'Public'].every(name => profiles.filter(row => row?.name === name && typeof row.enabled === 'boolean').length === 1);
  const firewall = input?.firewall?.status === 'ok' && validProfiles
    ? { status: 'ok', profiles: profiles.map(({name, enabled}) => ({name, enabled})) } : fallback;
  const sourceLogs = Array.isArray(input?.events?.logs) ? input.events.logs : [];
  const logs = ['System', 'Application'].map(name => {
    const row = sourceLogs.find(item => item?.name === name);
    return row?.status === 'ok' && count(row.errors) && count(row.warnings)
      && row.errors + row.warnings <= 2000 && typeof row.truncated === 'boolean'
      ? { name, status: 'ok', errors: row.errors, warnings: row.warnings, truncated: row.truncated }
      : { name, ...unknown('이 기록을 읽지 못했습니다. 이벤트 뷰어에서 확인하세요.') };
  });
  return { firewall, events: {status: logs.every(row => row.status === 'ok') ? 'ok' : 'partial', logs, windowHours: 24, limitPerLog: 2000} };
}

async function readWindows() {
  if (process.platform !== 'win32') return {
    firewall: unknown('Windows에서만 조회할 수 있습니다.'),
    events: unknown('Windows에서만 조회할 수 있습니다.'), checkedAt: stamp(),
  };
  try {
    // A fixed executable, script and arguments; requests cannot choose a command or path.
    const executable = join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
    const {stdout} = await exec(executable, ['-NoLogo', '-NoProfile', '-NonInteractive', '-File', fileURLToPath(new URL('./local-monitor.ps1', import.meta.url))],
      {windowsHide: true, timeout: 8500, maxBuffer: 32768, encoding: 'utf8'});
    const input = JSON.parse(stdout.replace(/^\uFEFF/, '').trim());
    return {...normalizeWindows(input), checkedAt: stamp()};
  } catch {
    return {firewall: unknown('조회가 거부되었거나 제한 시간을 넘겼습니다. Windows 보안에서 확인하세요.'),
      events: unknown('조회하지 못했습니다. 이벤트 뷰어에서 확인하세요. 관리자 권한을 자동으로 요청하지 않습니다.'), checkedAt: stamp()};
  }
}

async function readResources() {
  let cpu = unknown('CPU 사용 시간을 읽지 못했습니다. 다시 조회하세요.');
  try {
    const before = os.cpus();
    const started = performance.now();
    await delay(400);
    const after = os.cpus();
    if (!before.length || before.length !== after.length) throw Error('CPU_SAMPLE');
    let idle = 0, total = 0;
    for (let i = 0; i < before.length; i++) {
      for (const key of ['user', 'nice', 'sys', 'idle', 'irq']) {
        const diff = after[i].times[key] - before[i].times[key];
        if (!Number.isFinite(diff) || diff < 0) throw Error('CPU_SAMPLE');
        total += diff;
        if (key === 'idle') idle += diff;
      }
    }
    if (total <= 0) throw Error('CPU_SAMPLE');
    cpu = {status: 'ok', percent: Math.round((1 - idle / total) * 1000) / 10, sampleMs: Math.round(performance.now() - started), checkedAt: stamp()};
  } catch { /* Unknown stays unknown, never a fabricated zero. */ }
  let memory = unknown('메모리 정보를 읽지 못했습니다. 다시 조회하세요.');
  try {
    const totalBytes = os.totalmem(), availableBytes = os.freemem();
    if (!(totalBytes > 0 && availableBytes >= 0 && availableBytes <= totalBytes)) throw Error('MEMORY_SAMPLE');
    memory = {status: 'ok', totalBytes, usedBytes: totalBytes - availableBytes, percent: Math.round((1 - availableBytes / totalBytes) * 1000) / 10, checkedAt: stamp()};
  } catch { /* No fallback value. */ }
  let disk = unknown('시스템 디스크 공간을 읽지 못했습니다. 저장소 설정에서 확인하세요.');
  try {
    const drive = process.platform === 'win32' && /^[A-Za-z]:$/.test(process.env.SystemDrive || '') ? `${process.env.SystemDrive}\\` : parse(process.cwd()).root;
    const fs = await statfs(drive);
    const totalBytes = fs.blocks * fs.bsize, freeBytes = fs.bavail * fs.bsize;
    if (!(totalBytes > 0 && freeBytes >= 0 && freeBytes <= totalBytes)) throw Error('DISK_SAMPLE');
    disk = {status: 'ok', totalBytes, freeBytes, percent: Math.round((1 - freeBytes / totalBytes) * 1000) / 10, checkedAt: stamp()};
  } catch { /* No paths or OS errors are returned to the browser. */ }
  let network = unknown('네트워크 인터페이스를 읽지 못했습니다. 네트워크 설정에서 확인하세요.');
  try {
    const groups = Object.values(os.networkInterfaces()).filter(rows => rows?.some(row => !row.internal));
    network = {status: 'ok', interfaces: groups.length, ipv4: groups.filter(rows => rows.some(row => !row.internal && row.family === 'IPv4')).length,
      ipv6: groups.filter(rows => rows.some(row => !row.internal && row.family === 'IPv6')).length, checkedAt: stamp()};
  } catch { /* No addresses, MACs or interface names are returned. */ }
  return {cpu, memory, disk, network};
}

export function createLocalMonitor({resources = readResources, windows = readWindows, cacheMs = 10000} = {}) {
  let pending, cached, savedAt = 0;
  return async function read() {
    if (cached && Date.now() - savedAt < cacheMs) return cached;
    if (pending) return pending;
    pending = Promise.all([resources(), windows()]).then(([local, security]) => {
      cached = {schema: 'heimdall.local.v1', source: 'local', ...local, ...security, checkedAt: stamp()};
      savedAt = Date.now();
      return cached;
    }).finally(() => { pending = null; });
    return pending;
  };
}
