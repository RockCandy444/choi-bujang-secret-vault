import test from 'node:test';
import assert from 'node:assert/strict';
import {createLocalMonitor, normalizeWindows} from '../src/local-monitor.mjs';
import {createOnServer} from '../src/server.mjs';

test('Windows output keeps only aggregate allowlisted fields; unreadable channels stay unknown', () => {
  const output = normalizeWindows({firewall:{status:'ok', profiles:[
    {name:'Domain', enabled:true, ignored:'not-public'}, {name:'Private', enabled:false}, {name:'Public', enabled:true},
  ]}, events:{logs:[{name:'System', status:'ok', errors:0, warnings:2, truncated:false, ignored:'not-public'},
    {name:'Application', status:'unknown', errors:0, warnings:0}]}});
  assert.equal(output.firewall.profiles[1].enabled, false);
  assert.equal(output.events.status, 'partial');
  assert.equal(output.events.logs[1].status, 'unknown');
  assert.equal(Object.hasOwn(output.events.logs[1], 'errors'), false);
  assert.equal(JSON.stringify(output).includes('not-public'), false);
});

test('missing profiles and invalid event counts cannot become a healthy or empty result', () => {
  const output = normalizeWindows({firewall:{status:'ok', profiles:[{name:'Public', enabled:true}]},
    events:{logs:[{name:'System',status:'ok',errors:-1,warnings:0,truncated:false}]}});
  assert.equal(output.firewall.status, 'unknown');
  assert.equal(output.events.logs[0].status, 'unknown');
  assert.equal(output.events.logs[1].status, 'unknown');
});

test('concurrent requests share one collector and cached results keep their original measurement time', async () => {
  let calls = 0;
  let release;
  const wait = new Promise(resolve => {release=resolve;});
  const read = createLocalMonitor({resources:async()=>{calls++;await wait;return {cpu:{status:'unknown'}};}, windows:async()=>({}), cacheMs:1000});
  const first = read(), second = read(); release();
  const [a,b] = await Promise.all([first,second]);
  assert.strictEqual(a,b);
  assert.strictEqual(await read(),a);
  assert.equal(calls,1);
});

test('failed collection can be retried; no failed result is cached as success', async () => {
  let calls = 0;
  const read = createLocalMonitor({resources:async()=>{if (++calls === 1) throw Error('unavailable');return {};},windows:async()=>({})});
  await assert.rejects(read());
  assert.equal((await read()).source,'local');
  assert.equal(calls,2);
});

test('HTTP dashboard, original Agent and local-only read contract', async t => {
  const server = createOnServer();
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(()=>new Promise(resolve=>{server.closeAllConnections();server.close(resolve);}));
  const base = `http://127.0.0.1:${server.address().port}`;
  assert.match(await (await fetch(base)).text(), /헤임달/);
  assert.match(await (await fetch(`${base}/agent`)).text(), /student-identity/);
  assert.match(await (await fetch(`${base}/student/dashboard.mjs`)).text(), /local-status/);
  assert.equal((await fetch(`${base}/api/local-status`,{headers:{Origin:'https://example.invalid'}})).status,403);
  assert.equal((await fetch(`${base}/api/local-status`,{headers:{'Sec-Fetch-Site':'cross-site'}})).status,403);
  assert.equal((await fetch(`${base}/api/local-status?command=anything`)).status,400);
  assert.equal((await fetch(`${base}/api/local-status`,{method:'POST',headers:{Origin:base}})).status,405);
  const response = await fetch(`${base}/api/local-status`);
  assert.equal(response.status,200);
  const body = await response.json();
  assert.equal(body.data.source,'local');
  assert.equal(body.data.schema,'heimdall.local.v1');
  assert.equal(body.meta.mode,'disconnected');
  assert.equal((await fetch(`${base}/api/me`)).status,503);
  const denied = await fetch(`${base}/api/access`,{method:'POST',headers:{Origin:'https://example.invalid','Content-Type':'application/json'},body:'{}'});
  assert.equal(denied.status,403);
});
