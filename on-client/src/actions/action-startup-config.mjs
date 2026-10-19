import {openSync,closeSync,readSync,fstatSync,lstatSync,realpathSync} from 'node:fs';
import {isAbsolute,resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {existingDatabasePath} from './store.mjs';

// C4 SOURCE (2026-10-15, 로컬 전용): 실제 CLI 의 --alekov-actions-config 를 읽는 host 전용 닫힌 설정 reader.
// - 학생 body·header·student engine 모듈은 이 설정을 고를 수 없다. CLI 가 명시적으로 켰을 때만 읽는다.
// - 설정 파일: schema·databasePath·policy 세 key 만 담은 JSON.stringify(object) 한 줄 + LF 하나(UTF-8, BOM·공백 재포맷·중복 key 불가).
// - databasePath: 이미 있는 SQLite 파일(단일 링크·symlink 아님·SQLite 헤더). 자동 생성·탐색·이전·open 하지 않는다(헤더 16 bytes 만 읽는다).
// - policy: action service 의 닫힌 정책 계약과 같은 조건 + SDP host 가 아는 조치(device:revoke·grant:remove)만. 불완전하면 조용히
//   unsupported 로 떨어지지 않고 시작을 거절한다.
// - 반환값의 proof(설정 bytes SHA256·파일 identity·DB 파일 identity)는 root RAW 보존용이며 권위·승인을 뜻하지 않는다.
export const ACTION_STARTUP_SCHEMA='alekov.on-client.action-startup.v1';
const SDP_ACTIONS=Object.freeze(['device:revoke','grant:remove']);
const POLICY_KEYS=['appId','audience','accessPolicyId','allowedActions','confirmationTtlMs','timeoutMs'];
const MAX_CONFIG_BYTES=8192;
const SQLITE_HEADER=Buffer.from('SQLite format 3\0','latin1');
const fail=()=>{throw Object.assign(Error('INVALID_ACTION_STARTUP_CONFIGURATION'),{code:'INVALID_ACTION_STARTUP_CONFIGURATION'});};
const plain=v=>v!==null&&typeof v==='object'&&!Array.isArray(v)&&Object.getPrototypeOf(v)===Object.prototype;
const identifier=v=>typeof v==='string'&&/^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$/.test(v);
const positive=v=>Number.isSafeInteger(v)&&v>0;
const samePath=(a,b)=>process.platform==='win32'?a.toLowerCase()===b.toLowerCase():a===b;
const identity=s=>[s.dev,s.ino,s.birthtimeNs,s.size,s.mtimeNs,s.ctimeNs,s.nlink].map(String).join(':');

function canonicalFile(path){
  if(typeof path!=='string'||!path||!isAbsolute(path)||path!==resolve(path)||/[\0-\x1f\x7f]/.test(path))fail();
  let real;try{real=realpathSync.native(path);}catch{fail();}
  if(!samePath(real,path))fail();
  let s;try{s=lstatSync(path,{bigint:true});}catch{fail();}
  if(!s.isFile()||s.isSymbolicLink()||s.nlink!==1n)fail();
  return s;
}
function readStable(path,max){
  const named=canonicalFile(path);
  if(named.size<1n||named.size>BigInt(max))fail();
  let fd;try{fd=openSync(path,'r');}catch{fail();}
  try{
    const before=fstatSync(fd,{bigint:true});if(identity(before)!==identity(named))fail();
    const bytes=Buffer.alloc(Number(before.size));let at=0;
    while(at<bytes.length){const n=readSync(fd,bytes,at,bytes.length-at,at);if(n<=0)fail();at+=n;}
    if(identity(fstatSync(fd,{bigint:true}))!==identity(before)||identity(canonicalFile(path))!==identity(before))fail();
    return {bytes,identity:identity(before)};
  }finally{closeSync(fd);}
}
function databaseProof(path,configPath){
  if(samePath(path,configPath)||!existingDatabasePath(path))fail();
  const named=canonicalFile(path);if(named.size<BigInt(SQLITE_HEADER.length))fail();
  let fd;try{fd=openSync(path,'r');}catch{fail();}
  try{
    const before=fstatSync(fd,{bigint:true});if(identity(before)!==identity(named))fail();
    const header=Buffer.alloc(SQLITE_HEADER.length);
    if(readSync(fd,header,0,header.length,0)!==header.length||!header.equals(SQLITE_HEADER))fail();
    if(identity(fstatSync(fd,{bigint:true}))!==identity(before))fail();
    // SQLite 는 쓰기마다 mtime/size 를 바꾸므로 시작 후 비교용으로는 dev·ino·birth 만 남긴다.
    return [before.dev,before.ino,before.birthtimeNs].map(String).join(':');
  }finally{closeSync(fd);}
}
function validPolicy(policy){
  return plain(policy)&&Reflect.ownKeys(policy).every(k=>typeof k==='string'&&POLICY_KEYS.includes(k))
    &&['appId','audience','accessPolicyId','allowedActions','confirmationTtlMs'].every(k=>Object.hasOwn(policy,k))
    &&policy.appId==='aleph-on'&&policy.audience==='on-client'&&identifier(policy.accessPolicyId)
    &&Array.isArray(policy.allowedActions)&&policy.allowedActions.length>0&&policy.allowedActions.every(a=>SDP_ACTIONS.includes(a))
    &&new Set(policy.allowedActions).size===policy.allowedActions.length
    &&positive(policy.confirmationTtlMs)&&(!Object.hasOwn(policy,'timeoutMs')||positive(policy.timeoutMs));
}

/** Host-only reader. Returns {sdpActionStartup:{databasePath,policy}, proof}. Never opens the DB with SQLite. */
export function readActionStartupConfiguration(path){
  const {bytes,identity:configIdentity}=readStable(path,MAX_CONFIG_BYTES);
  let raw,config;
  try{raw=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);config=JSON.parse(raw);}catch{fail();}
  if(!plain(config)||Reflect.ownKeys(config).length!==3||!['schema','databasePath','policy'].every(k=>Object.hasOwn(config,k))
    ||raw!==JSON.stringify(config)+'\n'||config.schema!==ACTION_STARTUP_SCHEMA||!validPolicy(config.policy))fail();
  const databaseIdentity=databaseProof(config.databasePath,path);
  // 전달 직전 설정 파일이 바뀌지 않았는지 한 번 더 확인한다(원자적 잠금을 주장하지 않는다).
  const again=readStable(path,MAX_CONFIG_BYTES);if(again.identity!==configIdentity||!again.bytes.equals(bytes))fail();
  const policy=structuredClone(config.policy);
  return Object.freeze({
    sdpActionStartup:Object.freeze({databasePath:config.databasePath,policy}),
    proof:Object.freeze({configSha256:createHash('sha256').update(bytes).digest('hex'),configIdentity,databaseIdentity})});
}
