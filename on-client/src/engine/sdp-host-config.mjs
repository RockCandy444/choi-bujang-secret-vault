// 서버 전용 SDP 설정/자격 경계. import만으로 파일·환경·네트워크에 접근하지 않는다.
import {lstatSync,realpathSync,openSync,fstatSync,readSync,closeSync} from 'node:fs';
import {resolve,dirname,parse} from 'node:path';
import {createHash} from 'node:crypto';
import {isIP} from 'node:net';
import {request as httpsRequest} from 'node:https';
import {types} from 'node:util';

const configurations=new WeakMap(),snapshots=new WeakMap();
const CONFIG_KEYS=['schema','projectId','host','port','servername','caFile','certFile','keyFile','tokenFile'];
const CODES=new Set(['ENGINE_NOT_CONNECTED','ENGINE_RESULT_UNVERIFIED','SUBJECT_SCOPE_UNVERIFIED','ENGINE_TIMEOUT','REQUEST_CANCELLED']);
const MAX_RESPONSE=65536;
// C2-R2b SOURCE(운영 비활성): relay 조치 전용 경로 /alekov/actions/*. host 소유 조치 engine 만 부른다.
const ACTION_BASE=['appId','audience','projectId','sessionId'],ACTION_COMMAND=[...ACTION_BASE,'requestId','eventId','actionId','targetId','targetGeneration','snapshotDigest'];
const ACTION_KEYS=Object.freeze({'action-context':ACTION_BASE,'action-events':ACTION_BASE,'action-authorize':ACTION_COMMAND,
  'action-execute':[...ACTION_COMMAND,'fingerprint','identityVersion'],'action-result':[...ACTION_BASE,'requestId']});
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
export function sdpHostError(code){const safe=CODES.has(code)?code:'ENGINE_NOT_CONNECTED';return Object.assign(new Error(safe),{code:safe,safeMessage:'SDP 연결과 현재 권한을 확인할 수 없습니다.',status:503});}
export function sdpHostRecord(value,keys,optional=[]){
  if(!value||typeof value!=='object'||types.isProxy(value)||![Object.prototype,null].includes(Object.getPrototypeOf(value)))throw sdpHostError('ENGINE_RESULT_UNVERIFIED');
  const descriptors=Object.getOwnPropertyDescriptors(value),names=Reflect.ownKeys(descriptors);
  if(names.some(k=>typeof k!=='string'||!keys.includes(k)&&!optional.includes(k))||keys.some(k=>!Object.hasOwn(descriptors,k)))throw sdpHostError('ENGINE_RESULT_UNVERIFIED');
  const copy=Object.create(null);
  for(const key of names){const d=descriptors[key];if(!Object.hasOwn(d,'value')||!d.enumerable)throw sdpHostError('ENGINE_RESULT_UNVERIFIED');copy[key]=d.value;}
  return Object.freeze(copy);
}
export function sdpHostSignal(value){
  if(value===undefined)return undefined;
  try{
    if(types.isProxy(value)||Object.getPrototypeOf(value)!==AbortSignal.prototype||['aborted','reason','addEventListener','removeEventListener','dispatchEvent'].some(k=>Object.hasOwn(value,k)))throw 0;
    Object.getOwnPropertyDescriptor(AbortSignal.prototype,'aborted').get.call(value);
    return value;
  }catch{throw sdpHostError('ENGINE_RESULT_UNVERIFIED');}
}
// JSON.parse의 reviver는 중복 키를 볼 수 없으므로, 키를 소거하기 전에 검사한다.
export function parseSdpHostJson(source){
  let at=0;
  const fail=()=>{throw sdpHostError('ENGINE_RESULT_UNVERIFIED');};
  const white=()=>{while(at<source.length&&/[\x20\t\r\n]/.test(source[at]))at++;};
  function string(){
    if(source[at]!=='"')return fail();const start=at++;
    while(at<source.length){const c=source[at++];if(c==='"'){try{return JSON.parse(source.slice(start,at));}catch{return fail();}}if(c==='\\'){if(at>=source.length)return fail();at++;}else if(c.charCodeAt(0)<32)return fail();}
    return fail();
  }
  function value(depth){
    if(depth>16)return fail();white();const c=source[at];
    if(c==='"')return string();
    if(c==='{'){
      at++;white();const out=Object.create(null),seen=new Set();if(source[at]==='}'){at++;return out;}
      while(at<source.length){white();const key=string();if(seen.has(key)||['__proto__','prototype','constructor'].includes(key))return fail();seen.add(key);white();if(source[at++]!==':')return fail();out[key]=value(depth+1);white();const end=source[at++];if(end==='}')return out;if(end!==',')return fail();}
      return fail();
    }
    if(c==='['){at++;white();const out=[];if(source[at]===']'){at++;return out;}while(at<source.length){out.push(value(depth+1));white();const end=source[at++];if(end===']')return out;if(end!==',')return fail();}return fail();}
    for(const literal of ['true','false','null'])if(source.startsWith(literal,at)){at+=literal.length;return literal==='true'?true:literal==='false'?false:null;}
    const number=/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(source.slice(at));
    if(!number)return fail();at+=number[0].length;const n=Number(number[0]);if(!Number.isFinite(n))return fail();return n;
  }
  if(typeof source!=='string')return fail();const result=value(0);white();if(at!==source.length)return fail();return result;
}
const samePath=(a,b)=>process.platform==='win32'?a.toLowerCase()===b.toLowerCase():a===b;
function under(file,root){const separator=process.platform==='win32'?'\\':'/';return samePath(file,root)||(process.platform==='win32'?file.toLowerCase().startsWith(root.toLowerCase()+separator):file.startsWith(root+separator));}
function absolutePath(raw){
  if(typeof raw!=='string'||!raw||raw.length>4096||/[\x00-\x1f\x7f]/.test(raw)||!samePath(resolve(raw),raw)||raw===parse(raw).root)throw sdpHostError('ENGINE_NOT_CONNECTED');
  if(process.platform==='win32'&&(!/^[A-Za-z]:\\/.test(raw)||raw.slice(2).includes(':')||raw.slice(3).split('\\').some(p=>!p||/[. ]$/.test(p))))throw sdpHostError('ENGINE_NOT_CONNECTED');
  if(process.platform!=='win32'&&!raw.startsWith('/'))throw sdpHostError('ENGINE_NOT_CONNECTED');return raw;
}
const identity=s=>[s.dev,s.ino,s.birthtimeNs].map(String).join(':');
const fileState=s=>[identity(s),s.size,s.mtimeNs,s.ctimeNs,s.nlink].map(String).join(':');
function directoryProof(path){
  const chain=[];let current=path;
  for(let count=0;;count++){
    if(count>256)throw sdpHostError('ENGINE_NOT_CONNECTED');
    const s=lstatSync(current,{bigint:true});if(!s.isDirectory()||s.isSymbolicLink()||!samePath(realpathSync.native(current),current))throw sdpHostError('ENGINE_NOT_CONNECTED');
    chain.push([current,identity(s)]);const parent=dirname(current);if(parent===current)break;current=parent;
  }
  return JSON.stringify(chain);
}
function readFileEvidence(path,limit){
  let fd;
  try{
    const parent=directoryProof(dirname(path)),named=lstatSync(path,{bigint:true});
    if(!named.isFile()||named.isSymbolicLink()||named.nlink!==1n||named.size<1n||named.size>BigInt(limit)||!samePath(realpathSync.native(path),path))throw sdpHostError('ENGINE_NOT_CONNECTED');
    fd=openSync(path,'r');const before=fstatSync(fd,{bigint:true});
    if(!before.isFile()||before.nlink!==1n||fileState(before)!==fileState(named))throw sdpHostError('ENGINE_NOT_CONNECTED');
    const buffer=Buffer.alloc(limit+1);let offset=0;
    while(offset<buffer.length){const n=readSync(fd,buffer,offset,buffer.length-offset,offset);if(n===0)break;offset+=n;}
    const after=fstatSync(fd,{bigint:true}),afterNamed=lstatSync(path,{bigint:true});
    if(offset>limit||BigInt(offset)!==before.size||fileState(before)!==fileState(after)||!afterNamed.isFile()||afterNamed.isSymbolicLink()||fileState(before)!==fileState(afterNamed)
      ||!samePath(realpathSync.native(path),path)||directoryProof(dirname(path))!==parent)throw sdpHostError('ENGINE_NOT_CONNECTED');
    const bytes=buffer.subarray(0,offset),text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);
    return {text,proof:Object.freeze({path,parent,state:fileState(before),digest:hash(bytes)})};
  }catch{throw sdpHostError('ENGINE_NOT_CONNECTED');}finally{if(fd!==undefined)closeSync(fd);}
}
const sameProof=(a,b)=>a.path===b.path&&a.parent===b.parent&&a.state===b.state&&a.digest===b.digest;
function tokenOf(text){if(!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?:\r?\n)?$/.test(text))throw sdpHostError('ENGINE_NOT_CONNECTED');return text.replace(/\r?\n$/,'');}
function dns(value){return typeof value==='string'&&value.length<=253&&value.length>0&&value.split('.').every(label=>/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label));}
function pem(text,kind){if(kind==='key'?!/-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/.test(text):!/-----BEGIN CERTIFICATE-----/.test(text))throw sdpHostError('ENGINE_NOT_CONNECTED');return text;}
function getConfiguration(configuration){if(!configuration||types.isProxy(configuration)||!configurations.has(configuration))throw sdpHostError('ENGINE_NOT_CONNECTED');return configurations.get(configuration);}
function currentFiles(state){
  try{
    if(directoryProof(state.projectRoot)!==state.projectProof)throw 0;
    for(const entry of state.fixed){const current=readFileEvidence(entry.proof.path,entry.limit);if(!sameProof(current.proof,entry.proof))throw 0;}
    const token=readFileEvidence(state.profile.tokenFile,8192);
    if(directoryProof(state.projectRoot)!==state.projectProof)throw 0;
    return {token:tokenOf(token.text),proof:token.proof};
  }catch{throw sdpHostError('ENGINE_NOT_CONNECTED');}
}
export async function readSdpHostConfiguration(file,options){
  try{
    const {projectRoot:rawProject}=sdpHostRecord(options,['projectRoot']),projectRoot=absolutePath(rawProject),configPath=absolutePath(file),projectProof=directoryProof(projectRoot);
    if(under(configPath,projectRoot))throw 0;
    // c1(#968): receiptPort(선택) — 자기 기기 철회 본인 영수증 전용 SDP listener 포트. 없으면 그 경로는 꺼져 있다.
    const initial=readFileEvidence(configPath,8192),profile=sdpHostRecord(parseSdpHostJson(initial.text),CONFIG_KEYS,['receiptPort']);
    if(profile.schema!=='alekov.sdp.host.v1'||typeof profile.projectId!=='string'||!/^[a-z][a-z0-9_-]{0,63}$/.test(profile.projectId)
      ||typeof profile.host!=='string'||!(isIP(profile.host)||dns(profile.host))||!dns(profile.servername)||isIP(profile.servername)
      ||!Number.isSafeInteger(profile.port)||profile.port<1||profile.port>65535
      ||Object.hasOwn(profile,'receiptPort')&&(!Number.isSafeInteger(profile.receiptPort)||profile.receiptPort<1||profile.receiptPort>65535||profile.receiptPort===profile.port))throw 0;
    for(const field of ['caFile','certFile','keyFile','tokenFile']){absolutePath(profile[field]);if(under(profile[field],projectRoot))throw 0;}
    const ca=readFileEvidence(profile.caFile,65536),cert=readFileEvidence(profile.certFile,65536),key=readFileEvidence(profile.keyFile,65536);
    const state={profile,projectRoot,projectProof,ca:pem(ca.text,'ca'),cert:pem(cert.text,'cert'),key:pem(key.text,'key'),fixed:[{proof:initial.proof,limit:8192},{proof:ca.proof,limit:65536},{proof:cert.proof,limit:65536},{proof:key.proof,limit:65536}]};
    currentFiles(state);
    const configuration=Object.freeze(Object.create(null));configurations.set(configuration,state);return configuration;
  }catch{throw sdpHostError('ENGINE_NOT_CONNECTED');}
}
// 같은 서버 전용 엔진에서만 사용한다. 반환값에는 PEM/JWT/경로를 넣지 않는다.
export function getSdpHostProjectId(configuration){return getConfiguration(configuration).profile.projectId;}
export function captureSdpHostCredentials(configuration){
  const state=getConfiguration(configuration),token=currentFiles(state),snapshot=Object.freeze(Object.create(null));
  snapshots.set(snapshot,{state,token:token.token,tokenProof:token.proof});return snapshot;
}
function getSnapshot(snapshot){if(!snapshot||types.isProxy(snapshot)||!snapshots.has(snapshot))throw sdpHostError('ENGINE_NOT_CONNECTED');return snapshots.get(snapshot);}
export function verifySdpHostCredentials(snapshot){const entry=getSnapshot(snapshot),now=currentFiles(entry.state);if(!sameProof(now.proof,entry.tokenProof))throw sdpHostError('SUBJECT_SCOPE_UNVERIFIED');}
export function closeSdpHostCredentials(snapshot){snapshots.delete(snapshot);}
export function postSdpHostAdmission(snapshot,kind,body,call){
  const entry=getSnapshot(snapshot),{signal}=sdpHostRecord(call,['signal']);sdpHostSignal(signal);
  const keys=kind==='context'?['appId','audience','projectId']:['apps','events','devices','sessions'].includes(kind)?['appId','audience','projectId','sessionId']:kind==='decision'?['appId','audience','projectId','sessionId','targetAppId','clientRequestId']:kind==='ai-binding'?['appId','audience','projectId','sessionId','requestNonce']
    :Object.hasOwn(ACTION_KEYS,kind)?ACTION_KEYS[kind]:null;
  if(!keys)throw sdpHostError('ENGINE_RESULT_UNVERIFIED');const input=sdpHostRecord(body,keys);
  if(input.appId!=='aleph-on'||input.audience!=='on-client'||input.projectId!==entry.state.profile.projectId)throw sdpHostError('SUBJECT_SCOPE_UNVERIFIED');
  const bytes=Buffer.from(JSON.stringify(input));if(bytes.length>4096)throw sdpHostError('ENGINE_RESULT_UNVERIFIED');
  return new Promise((resolvePromise,reject)=>{
    let req,res,timer,settled=false;const deadline={wall:Date.now()+5000,monotonic:performance.now()+5000};
    const expired=()=>Date.now()>=deadline.wall||performance.now()>=deadline.monotonic;
    const cleanup=()=>{clearTimeout(timer);signal.removeEventListener('abort',onAbort);};
    const fail=code=>{if(settled)return;settled=true;cleanup();res?.destroy();req?.destroy();reject(sdpHostError(code));};
    const onAbort=()=>fail('REQUEST_CANCELLED');
    if(signal.aborted){onAbort();return;}
    signal.addEventListener('abort',onAbort,{once:true});timer=setTimeout(()=>fail('ENGINE_TIMEOUT'),5000);
    try{
      const {profile,ca,cert,key}=entry.state;
      req=httpsRequest({hostname:profile.host,port:profile.port,servername:profile.servername,path:Object.hasOwn(ACTION_KEYS,kind)?'/alekov/actions/'+kind.slice('action-'.length):'/alekov/'+kind,method:'POST',agent:false,rejectUnauthorized:true,
        ca,cert,key,maxHeaderSize:8192,headers:{'content-type':'application/json','accept':'application/json','content-length':String(bytes.length),'authorization':'Bearer '+entry.token}},response=>{
        res=response;if(settled){res.destroy();return;}
        res.on('error',()=>fail('ENGINE_NOT_CONNECTED'));res.once('aborted',()=>fail('ENGINE_NOT_CONNECTED'));
        const status=res.statusCode;
        if(status!==200){fail(status===409?'SUBJECT_SCOPE_UNVERIFIED':status===408||status===504?'ENGINE_TIMEOUT':'ENGINE_NOT_CONNECTED');return;}
        const headers=Object.create(null);
        for(let i=0;i<res.rawHeaders.length;i+=2){const name=res.rawHeaders[i].toLowerCase();if(['content-type','content-length','content-encoding','x-sdp-request-id'].includes(name)){if(Object.hasOwn(headers,name)){fail('ENGINE_RESULT_UNVERIFIED');return;}headers[name]=res.rawHeaders[i+1];}}
        if(!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(headers['content-type']??'')||headers['content-encoding']!==undefined&&headers['content-encoding']!=='identity'
          ||typeof headers['x-sdp-request-id']!=='string'||headers['content-length']!==undefined&&(!/^[0-9]+$/.test(headers['content-length'])||Number(headers['content-length'])>MAX_RESPONSE)){fail('ENGINE_RESULT_UNVERIFIED');return;}
        let size=0;const chunks=[];
        res.on('data',chunk=>{if(settled)return;size+=chunk.length;if(size>MAX_RESPONSE){fail('ENGINE_RESULT_UNVERIFIED');return;}chunks.push(chunk);});
        res.once('end',()=>{
          if(settled)return;if(signal.aborted){onAbort();return;}if(expired()){fail('ENGINE_TIMEOUT');return;}
          try{if(!res.complete||headers['content-length']!==undefined&&Number(headers['content-length'])!==size)throw 0;
            const data=parseSdpHostJson(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(Buffer.concat(chunks,size)));
            if(expired()){fail('ENGINE_TIMEOUT');return;}settled=true;cleanup();resolvePromise({data,engineRequestId:headers['x-sdp-request-id'],receivedAtMs:Date.now()});
          }catch{fail('ENGINE_RESULT_UNVERIFIED');}
        });
        res.once('close',()=>{if(!settled)fail('ENGINE_NOT_CONNECTED');});
      });
      req.on('error',()=>fail(signal.aborted?'REQUEST_CANCELLED':'ENGINE_NOT_CONNECTED'));
      if(signal.aborted){onAbort();return;}if(expired()){fail('ENGINE_TIMEOUT');return;}req.end(bytes);
    }catch{fail('ENGINE_NOT_CONNECTED');}
  });
}
// c1(#968) 자기 기기 철회 본인 영수증 전용 SDP listener(receiptPort) 호출. 같은 기기 CA·인증서·키로 mTLS 접속하고 Bearer·proxy header 는 보내지 않는다.
// begin {requestId} → 201, finish {challengeId, ticket} → 200. 응답은 {ok:true,data} 닫힌 JSON. 결과 해석은 sdp-host 가 한다.
export const SDP_HOST_RECEIPT_PATHS=Object.freeze({begin:'/alekov/receipts/own/begin',finish:'/alekov/receipts/own/finish'});
export function sdpHostReceiptEnabled(snapshot){return Object.hasOwn(getSnapshot(snapshot).state.profile,'receiptPort');}
export function postSdpHostOwnReceipt(snapshot,kind,body,call){
  const entry=getSnapshot(snapshot),{signal}=sdpHostRecord(call,['signal']);sdpHostSignal(signal);
  const keys=kind==='begin'?['requestId']:kind==='finish'?['challengeId','ticket']:null;if(!keys)throw sdpHostError('ENGINE_RESULT_UNVERIFIED');
  const {profile,ca,cert,key}=entry.state;if(!Object.hasOwn(profile,'receiptPort'))throw sdpHostError('ENGINE_NOT_CONNECTED');
  const input=sdpHostRecord(body,keys);if(Object.values(input).some(v=>typeof v!=='string'))throw sdpHostError('ENGINE_RESULT_UNVERIFIED');
  const bytes=Buffer.from(JSON.stringify(input));if(bytes.length>1024)throw sdpHostError('ENGINE_RESULT_UNVERIFIED');
  const expectedStatus=kind==='begin'?201:200;
  return new Promise((resolvePromise,reject)=>{
    let req,res,timer,settled=false;
    const cleanup=()=>{clearTimeout(timer);signal.removeEventListener('abort',onAbort);};
    const fail=code=>{if(settled)return;settled=true;cleanup();res?.destroy();req?.destroy();reject(sdpHostError(code));};
    const onAbort=()=>fail('REQUEST_CANCELLED');
    if(signal.aborted){onAbort();return;}
    signal.addEventListener('abort',onAbort,{once:true});timer=setTimeout(()=>fail('ENGINE_TIMEOUT'),10000);
    try{
      req=httpsRequest({hostname:profile.host,port:profile.receiptPort,servername:profile.servername,path:SDP_HOST_RECEIPT_PATHS[kind],method:'POST',agent:false,rejectUnauthorized:true,
        ca,cert,key,maxHeaderSize:8192,headers:{'content-type':'application/json','accept':'application/json','content-length':String(bytes.length)}},response=>{
        res=response;if(settled){res.destroy();return;}
        res.on('error',()=>fail('ENGINE_NOT_CONNECTED'));
        // 404·400 은 권한·존재를 구분하지 않는 거절, 503 은 소비 여부를 모르는 UNKNOWN 이다.
        if(res.statusCode!==expectedStatus){fail(res.statusCode===503?'ENGINE_RESULT_UNVERIFIED':'SUBJECT_SCOPE_UNVERIFIED');return;}
        if(!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(res.headers['content-type']??'')||res.headers['content-encoding']!==undefined){fail('ENGINE_RESULT_UNVERIFIED');return;}
        let size=0;const chunks=[];
        res.on('data',chunk=>{if(settled)return;size+=chunk.length;if(size>MAX_RESPONSE){fail('ENGINE_RESULT_UNVERIFIED');return;}chunks.push(chunk);});
        res.once('end',()=>{if(settled)return;try{const parsed=parseSdpHostJson(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks,size)));
          const envelope=sdpHostRecord(parsed,['ok','data']);if(envelope.ok!==true)throw 0;settled=true;cleanup();resolvePromise(envelope.data);}catch{fail('ENGINE_RESULT_UNVERIFIED');}});
        res.once('close',()=>{if(!settled)fail('ENGINE_NOT_CONNECTED');});
      });
      req.on('error',()=>fail(signal.aborted?'REQUEST_CANCELLED':'ENGINE_NOT_CONNECTED'));req.end(bytes);
    }catch{fail('ENGINE_NOT_CONNECTED');}
  });
}
