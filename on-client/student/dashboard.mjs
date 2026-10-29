// Student dashboard: no remote services, credentials, storage or security-setting writes.
const $ = id => document.getElementById(id);
const finite = value => typeof value === 'number' && Number.isFinite(value);
const percent = value => finite(value) && value >= 0 && value <= 100;
const time = value => Number.isFinite(Date.parse(value))
  ? new Intl.DateTimeFormat('ko-KR', {timeZone: 'Asia/Seoul', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false}).format(new Date(value)) : '시각 확인 불가';
const gib = value => (value / 1024 ** 3).toLocaleString('ko-KR', {maximumFractionDigits: 1});
const node = (tag, text, cls) => {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (cls) element.className = cls;
  return element;
};
const history = [];
const series = {cpu: true, memory: true};
let pending = false, interval, currentData;

async function request(path) {
  const response = await fetch(path, {signal: AbortSignal.timeout(12000), credentials: 'omit', cache: 'no-store'});
  if (!response.ok) throw Error('READ_FAILED');
  const body = await response.json();
  if (body?.ok !== true || !body.data) throw Error('READ_FAILED');
  return body;
}

function setMetric(key, resource, value, unit, note, source) {
  const target = $(`${key}-value`);
  target.replaceChildren();
  if (resource?.status !== 'ok' || value === null) {
    target.textContent = '확인 불가';
    target.classList.add('text-value');
    $(`${key}-meter`).style.width = '0%';
    $(`${key}-note`).textContent = resource?.reason || '값을 읽지 못했습니다. 다시 조회하거나 OS 설정에서 확인하세요.';
    $(`${key}-time`).textContent = `출처 · ${source}`;
    return;
  }
  target.classList.remove('text-value');
  target.append(document.createTextNode(value), node('span', unit, 'unit'));
  $(`${key}-meter`).style.width = `${resource.percent}%`;
  $(`${key}-note`).textContent = note;
  $(`${key}-time`).textContent = `${time(resource.checkedAt)} · ${source}`;
}

function renderMetrics(data) {
  const {cpu, memory, disk, firewall} = data || {};
  setMetric('cpu', cpu, percent(cpu?.percent) ? cpu.percent.toFixed(1) : null, '%',
    `전체 논리 CPU · ${cpu?.sampleMs ?? '—'}ms 구간 실측`, 'OS CPU 시간 차이');
  setMetric('memory', memory, percent(memory?.percent) && finite(memory?.usedBytes) && memory.usedBytes >= 0 && memory.usedBytes <= memory.totalBytes ? gib(memory.usedBytes) : null, 'GiB',
    `전체 ${gib(memory?.totalBytes || 0)} GiB 중 ${memory?.percent ?? '—'}% 사용`, 'OS 메모리');
  setMetric('disk', disk, percent(disk?.percent) && finite(disk?.freeBytes) && disk.freeBytes >= 0 && disk.freeBytes <= disk.totalBytes ? gib(disk.freeBytes) : null, 'GiB',
    `전체 ${gib(disk?.totalBytes || 0)} GiB · ${disk?.percent ?? '—'}% 사용`, '시스템 드라이브');
  $('firewall-profiles').replaceChildren();
  if (firewall?.status === 'ok' && Array.isArray(firewall.profiles) && firewall.profiles.length === 3) {
    const enabled = firewall.profiles.filter(row => row.enabled === true).length;
    $('firewall-value').textContent = enabled === 3 ? '모든 프로필 켜짐' : `${3 - enabled}개 프로필 꺼짐`;
    $('firewall-value').classList.toggle('warning-text', enabled !== 3);
    for (const row of firewall.profiles) $('firewall-profiles').append(node('span', `${row.name} ${row.enabled ? 'ON' : 'OFF'}`, row.enabled ? '' : 'off'));
    $('firewall-note').textContent = '프로필 설정 값 · 실제 방어 효과 판정 아님';
    $('firewall-time').textContent = `${time(data.checkedAt)} · Get-NetFirewallProfile`;
  } else {
    $('firewall-value').textContent = '확인 불가';
    $('firewall-value').classList.remove('warning-text');
    $('firewall-note').textContent = firewall?.reason || '읽지 못했습니다. Windows 보안에서 확인하세요.';
    $('firewall-time').textContent = '출처 · Get-NetFirewallProfile';
  }
  const notices = [];
  if (disk?.status === 'ok' && percent(disk.percent) && disk.percent >= 90) notices.push('시스템 디스크 여유가 10% 이하입니다. 저장소 설정에서 사용량을 확인하세요.');
  if (memory?.status === 'ok' && percent(memory.percent) && memory.percent >= 90) notices.push('메모리 사용률이 90% 이상입니다. 작업 관리자에서 사용량을 확인하세요.');
  if (firewall?.status === 'ok' && firewall.profiles?.some(row => row.enabled === false)) notices.push('꺼진 방화벽 프로필이 있습니다. 현재 네트워크와 조직 정책을 Windows 보안에서 직접 확인하세요.');
  $('attention').textContent = notices.join(' ');
  $('attention').hidden = !notices.length;
  renderNetwork(data?.network);
  renderEvents(data?.events, data?.checkedAt);
}

function renderNetwork(network) {
  const ok = network?.status === 'ok' && Number.isSafeInteger(network.interfaces) && network.interfaces >= 0;
  $('network-value').textContent = ok ? `주소 구성 인터페이스 ${network.interfaces}개` : '확인 불가';
  $('network-badge').textContent = ok ? '실측' : '확인 불가';
  $('network-badge').className = `badge${ok ? ' good' : ''}`;
  $('network-note').textContent = ok
    ? `IPv4 ${network.ipv4}개 · IPv6 ${network.ipv6}개 · ${time(network.checkedAt)}. 인터넷 접속 성공을 뜻하지는 않습니다.`
    : network?.reason || '인터페이스를 읽지 못했습니다. Windows 네트워크 설정에서 확인하세요.';
}

function renderConnection(body) {
  const mode = body?.data?.engine?.mode;
  const text = {disconnected: 'SDP 미연결', demo: '예제 실행 · 실제 연결 아님', connected: '어댑터 설정됨 · 접속 미검증'};
  $('sdp-value').textContent = text[mode] || '연결 상태 확인 불가';
  $('sdp-badge').textContent = mode === 'disconnected' ? '미연결' : mode === 'demo' ? '예제' : '확인 필요';
  $('sdp-badge').className = 'badge';
  $('sdp-note').textContent = mode === 'disconnected'
    ? '현재 실행의 SDP 연결은 설정되지 않았습니다. PC 실측은 별도로 사용할 수 있습니다.'
    : mode === 'demo' ? '기존 Agent는 예제 자료를 사용합니다. 이 관제 화면의 PC 값은 현재 PC 실측입니다.'
    : '진단은 연결 설정만 확인합니다. 실제 계정·세션·서버 응답은 기존 Agent에서 별도로 확인하세요.';
}

function renderEvents(events, checkedAt) {
  $('event-rows').replaceChildren();
  for (const name of ['System', 'Application']) {
    const item = events?.logs?.find(row => row.name === name);
    const ok = item?.status === 'ok';
    const row = node('tr');
    row.append(node('td', name), node('td', ok ? item.warnings.toLocaleString('ko-KR') : '—'), node('td', ok ? item.errors.toLocaleString('ko-KR') : '—'));
    const status = node('td');
    status.append(node('span', ok ? item.truncated ? '일부 집계' : '조회 완료' : '확인 불가', `badge${ok && !item.truncated ? ' good' : ''}`));
    row.append(status);
    $('event-rows').append(row);
  }
  const partial = events?.logs?.some(row => row.truncated);
  const failed = events?.status !== 'ok';
  $('events-note').textContent = `${checkedAt ? `${time(checkedAt)} · ` : ''}${partial ? '2,000건을 넘는 채널은 최근 2,000건만 집계했습니다. 전체 건수가 아닙니다.' : '최근 24시간 · 채널별 경고·오류 최대 2,000건 · 이벤트 본문 수집 안 함.'}${failed ? ` ${events?.reason || '읽지 못한 채널은 이벤트 뷰어에서 확인하세요.'}` : ''}`;
}

const svgNode = (tag, attributes = {}, text) => {
  const element = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, String(value));
  if (text !== undefined) element.textContent = text;
  return element;
};
function renderChart() {
  const chart = $('chart');
  chart.replaceChildren(svgNode('title', {id:'chart-title'}, 'CPU·메모리 사용률 추이'), svgNode('desc', {id:'chart-description'},
    `${history.length}회 실제 조회. CPU는 민트색, 메모리는 보라색입니다. 아래 실측 기록 표에서도 확인할 수 있습니다.`));
  for (const value of [0, 25, 50, 75, 100]) {
    const y = 18 + (100 - value) / 100 * 158;
    chart.append(svgNode('line', {x1:38, y1:y, x2:664, y2:y, stroke:'#293649', 'stroke-dasharray':'3 5', 'stroke-width':.7}),
      svgNode('text', {x:28, y:y+3, fill:'#7c91a9', 'font-size':9, 'text-anchor':'end'}, `${value}%`));
  }
  const start = Date.parse(history[0]?.at), end = Date.parse(history.at(-1)?.at);
  const x = row => history.length === 1 ? 351 : 42 + (Date.parse(row.at)-start) / Math.max(1,end-start)*614;
  for (const [key, color] of [['cpu','#5de0b7'], ['memory','#b09afa']]) {
    if (!series[key]) continue;
    let path = '', connected = false;
    for (const item of history) {
      if (!percent(item[key])) { connected = false; continue; }
      const px = x(item), y = 18 + (100-item[key])/100*158;
      path += `${connected ? ' L' : ' M'}${px},${y}`;
      connected = true;
      const point = svgNode('circle', {cx:px, cy:y, r:history.length === 1 ? 4 : 2.5, fill:color, stroke:'#121b27','stroke-width':1.5});
      point.append(svgNode('title', {}, `${time(item.at)} · ${key === 'cpu' ? 'CPU' : '메모리'} ${item[key]}%`));
      chart.append(point);
    }
    if (path) chart.prepend(svgNode('path', {d:path, fill:'none', stroke:color, 'stroke-width':2, 'stroke-linejoin':'round'}));
  }
  const ticks = history.length > 1 ? [history[0], history[Math.floor((history.length-1)/2)], history.at(-1)] : history;
  for (const item of new Set(ticks)) chart.append(svgNode('text', {x:x(item), y:201, fill:'#7c91a9', 'font-size':9,'text-anchor':'middle'}, time(item.at)));
  const available = history.some(row => (series.cpu && percent(row.cpu)) || (series.memory && percent(row.memory)));
  $('chart-empty').hidden = available;
  $('chart-empty').textContent = !series.cpu && !series.memory ? '위에서 표시할 지표를 선택하세요.' : history.length ? '사용률을 읽지 못했습니다. 다시 조회하세요.' : '아직 실측 기록이 없습니다.';
  $('sample-count').textContent = `${history.length}회 조회${history.length === 1 ? ' · 두 번째 조회부터 추이 표시' : ''}`;
  $('history-rows').replaceChildren(...history.slice().reverse().map(row => {
    const tr = node('tr');
    tr.append(node('td', time(row.at)), node('td', percent(row.cpu) ? `${row.cpu}%` : '확인 불가'), node('td', percent(row.memory) ? `${row.memory}%` : '확인 불가'));
    return tr;
  }));
}

function activity(message, at = new Date().toISOString()) {
  const list = $('activity');
  list.querySelector('.activity-placeholder')?.remove();
  const item = node('li', message);
  item.append(node('small', `${time(at)} KST`));
  list.prepend(item);
  while (list.children.length > 6) list.lastElementChild.remove();
}

async function refresh() {
  if (pending) return;
  pending = true;
  $('refresh-local').disabled = true;
  $('metrics').setAttribute('aria-busy', 'true');
  $('query-error').hidden = true;
  $('query-status').textContent = currentData ? 'PC 상태를 읽는 중입니다. 표시된 값은 직전 실측입니다.' : 'PC 상태를 읽는 중입니다. 아직 현재 실측 값이 없습니다.';
  const [local, diagnostics] = await Promise.allSettled([request('/api/local-status'), request('/api/diagnostics')]);
  renderConnection(diagnostics.status === 'fulfilled' ? diagnostics.value : null);
  const data = local.status === 'fulfilled' ? local.value.data : null;
  if (data?.schema === 'heimdall.local.v1' && data.source === 'local' && Number.isFinite(Date.parse(data.checkedAt))) {
    const same = currentData?.checkedAt === data.checkedAt;
    currentData = data;
    renderMetrics(data);
    if (!same) {
      history.push({at:data.checkedAt, cpu:data.cpu?.status === 'ok' ? data.cpu.percent : null, memory:data.memory?.status === 'ok' ? data.memory.percent : null});
      if (history.length > 24) history.shift();
    }
    renderChart();
    const partial = ['cpu','memory','disk','firewall','network','events'].some(key => data[key]?.status !== 'ok');
    $('query-status').textContent = same ? '최근 10초 이내의 실측 결과입니다. 새 실측은 다음 조회에 반영됩니다.' : partial ? 'PC 조회 완료 · 읽지 못한 항목은 확인 불가로 표시했습니다.' : 'PC 조회 완료 · 모든 값은 이 PC에서 읽었습니다.';
    $('updated').textContent = `마지막 실측 ${time(data.checkedAt)} KST`;
    activity(same ? '최근 실측 결과 재사용' : partial ? 'PC 실측 완료 · 일부 항목 확인 불가' : 'PC 실측 완료', data.checkedAt);
  } else {
    currentData = null;
    renderMetrics(null);
    $('query-error').textContent = 'PC 상태를 불러오지 못했습니다. 실행 창에서 서버가 켜져 있는지 확인한 뒤 「다시 조회」를 누르세요. 실측 이력은 이전 기록으로 보존됩니다.';
    $('query-error').hidden = false;
    $('query-status').textContent = '조회 실패 · 현재 값을 확인할 수 없습니다.';
    $('updated').textContent = '현재 실측 없음';
    activity('PC 조회 실패 · 현재 값 초기화');
    if ($('interval').value !== '0') {
      $('interval').value = '0';
      clearInterval(interval);
      activity('조회 실패로 자동 조회 중지');
    }
  }
  pending = false;
  $('refresh-local').disabled = false;
  $('metrics').setAttribute('aria-busy', 'false');
}

function init() {
  const details = node('details');
  details.className = 'history-details';
  details.append(node('summary', '실측 기록을 표로 보기'));
  const table = node('table');
  const head = node('thead'), row = node('tr');
  for (const label of ['조회 시각 (KST)','CPU 사용률','메모리 사용률']) {
    const th = node('th', label); th.scope = 'col'; row.append(th);
  }
  head.append(row);
  const body = node('tbody'); body.id = 'history-rows';
  table.append(head,body); details.append(table); $('resources').append(details);
  $('refresh-local').addEventListener('click', refresh);
  $('interval').addEventListener('change', () => {
    clearInterval(interval);
    const seconds = Number($('interval').value);
    if ([30,60].includes(seconds)) interval = setInterval(() => {if (!document.hidden && !pending) void refresh();}, seconds * 1000);
    activity(seconds ? `${seconds}초 자동 조회 설정 · 화면이 보일 때만` : '자동 조회 끔');
  });
  for (const button of document.querySelectorAll('[data-series]')) button.addEventListener('click', () => {
    series[button.dataset.series] = !series[button.dataset.series];
    button.setAttribute('aria-pressed', String(series[button.dataset.series]));
    renderChart();
  });
  $('help-open').addEventListener('click', () => $('help').showModal());
  $('help-close').addEventListener('click', () => $('help').close());
  addEventListener('pagehide', () => clearInterval(interval));
  renderChart();
  void refresh();
}
if (typeof document !== 'undefined' && $('refresh-local')) init();
