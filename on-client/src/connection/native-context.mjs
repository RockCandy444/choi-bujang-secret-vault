// 원 native 로그인 capability와 실제 디렉터리·별도 registry·원 Vault를 결속한다.
import {lstatSync,realpathSync,openSync,readFileSync,fstatSync,closeSync} from 'node:fs';
import {resolve,dirname,parse} from 'node:path';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {randomUUID,createHash} from 'node:crypto';
import {types} from 'node:util';
import {createAppCredentialVault} from '../ai/credential-vault.mjs';
import {CLCO_GATEWAY_ORIGIN,ALEPH_PORTAL_ORIGIN} from '../ai/connection.mjs';
import {createNativeLogin,nativeFault,nativeOwn,nativeSignal,openNativeOperation,refreshNativeOperation,assertNativeOperation,nativeOperationBinding,closeNativeOperation,issueNativeReceiptTicket} from './native-login.mjs';

const hosts=new WeakMap(),operations=new WeakMap(),configurations=new WeakMap();
const HELPER=fileURLToPath(new URL('../../tools/native-host-registry.ps1',import.meta.url));
const POWERSHELL='C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
const HASH=/^[a-f0-9]{64}$/;
const credentialKeys=['schema','appId','audience','subjectId','alephUserId','siteId','identityVersion','projectId','grantId','grantVersion','credentialId','policyVersion','accessPolicyId','baseUrl','token','expiresAt'];
const sha=v=>createHash('sha256').update(v).digest('hex');
const canonical=v=>JSON.stringify(Object.fromEntries(Object.keys(v).sort().map(k=>[k,v[k]])));
function physical(path){
  const result=[];let p=path;while(true){const s=lstatSync(p,{bigint:true});if(!s.isDirectory()||s.isSymbolicLink()||realpathSync.native(p).toLowerCase()!==p.toLowerCase())throw nativeFault('UNVERIFIED');
    result.push(Object.freeze({path:p,dev:String(s.dev),ino:String(s.ino),birth:String(s.birthtimeNs)}));const parent=dirname(p);if(parent===p)break;p=parent;}
  return JSON.stringify(result);
}
function path(value){if(typeof value!=='string'||! /^[A-Za-z]:\\/.test(value)||value.includes('\0')||value.slice(2).includes(':')||value!==resolve(value)||value===parse(value).root)throw nativeFault('INPUT_INVALID');physical(value);return value;}
function configurationFile(file){if(typeof file!=='string'||! /^[A-Za-z]:\\/.test(file)||file!==resolve(file)||file.slice(2).includes(':'))throw nativeFault('INPUT_INVALID');physical(dirname(file));const fd=openSync(file,'r');
  try{const a=fstatSync(fd,{bigint:true}),b=lstatSync(file,{bigint:true});if(!a.isFile()||b.isSymbolicLink()||a.dev!==b.dev||a.ino!==b.ino||a.size>8192n||realpathSync.native(file).toLowerCase()!==file.toLowerCase())throw nativeFault('UNVERIFIED');
    const bytes=readFileSync(fd),after=fstatSync(fd,{bigint:true}),named=lstatSync(file,{bigint:true});if(a.dev!==after.dev||a.ino!==after.ino||a.size!==after.size||a.mtimeNs!==after.mtimeNs||a.ctimeNs!==after.ctimeNs||a.dev!==named.dev||a.ino!==named.ino)throw nativeFault('CONTEXT_CHANGED');
    return {bytes,proof:Object.freeze({path:file,digest:sha(bytes),identity:[String(a.dev),String(a.ino),String(a.birthtimeNs)].join(':')})};
  }finally{closeSync(fd);}}
export async function readNativeHostConfiguration(file){const captured=configurationFile(file);let raw;try{raw=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(captured.bytes));}catch{throw nativeFault('INPUT_INVALID');}
  const o=nativeOwn(raw,['enabled','registryRoot','vaultRoot','projectRoot','gatewayOrigin','portalOrigin']);if(o.enabled!==true)throw nativeFault('INPUT_INVALID');
  const config=primitiveOptions(o),startup={config,configFile:captured.proof,closed:false,children:new Set()};
  // 명시적 CLI만 실제 SID·ACL과 registry를 확인한다. 원격 로그인 요청보다 먼저 끝난다.
  await registry(startup,{action:'select',deadline:Date.now()+config.timeoutMs,binding:null},undefined,async value=>{nativeOwn(value,['projectId','directoryInstance','registryRevision']);return {outcome:'read',value:null};});
  configurations.set(o,captured.proof);return o;}
export function captureNativeHostConfiguration(raw){const copy=nativeOwn(raw,['enabled','registryRoot','vaultRoot','projectRoot'],['gatewayOrigin','portalOrigin','fetchImpl','clock','timeoutMs']);const proof=configurations.get(raw);if(proof)configurations.set(copy,proof);return copy;}
function primitiveOptions(raw){const o=nativeOwn(raw,['enabled','registryRoot','vaultRoot','projectRoot'],['gatewayOrigin','portalOrigin','fetchImpl','clock','timeoutMs']);
  if(o.enabled!==true||process.platform!=='win32')throw nativeFault('DISABLED');
  const registryRoot=path(o.registryRoot),vaultRoot=path(o.vaultRoot),projectRoot=path(o.projectRoot);
  const under=(a,b)=>a.toLowerCase()===b.toLowerCase()||a.toLowerCase().startsWith(b.toLowerCase()+'\\');
  if(under(registryRoot,projectRoot)||under(vaultRoot,projectRoot)||under(registryRoot,vaultRoot)||under(vaultRoot,registryRoot))throw nativeFault('INPUT_INVALID');
  if(o.gatewayOrigin!==undefined&&o.gatewayOrigin!==CLCO_GATEWAY_ORIGIN||o.portalOrigin!==undefined&&o.portalOrigin!==ALEPH_PORTAL_ORIGIN)throw nativeFault('INPUT_INVALID');
  if(o.fetchImpl!==undefined&&(typeof o.fetchImpl!=='function'||types.isProxy(o.fetchImpl))||o.clock!==undefined&&(typeof o.clock!=='function'||types.isProxy(o.clock)))throw nativeFault('INPUT_INVALID');
  const timeoutMs=o.timeoutMs??10000;if(!Number.isSafeInteger(timeoutMs)||timeoutMs<1||timeoutMs>15000)throw nativeFault('INPUT_INVALID');return Object.freeze({...o,registryRoot,vaultRoot,projectRoot,timeoutMs});
}
export function createNativeHostContext(configuration){
  const config=primitiveOptions(configuration),login=createNativeLogin({enabled:true,gatewayOrigin:CLCO_GATEWAY_ORIGIN,portalOrigin:ALEPH_PORTAL_ORIGIN,
    ...(config.fetchImpl?{fetchImpl:config.fetchImpl}:{}),...(config.clock?{clock:config.clock}:{}),timeoutMs:config.timeoutMs});
  const s={config,configFile:configurations.get(configuration)??null,login,project:null,projectGeneration:0,closed:false,operations:new Set(),children:new Set()};
  const api=Object.freeze({login,close(){if(s.closed)return;s.closed=true;login.close();for(const op of s.operations)closeNativeHostOperation(op);for(const child of s.children)child.kill();}});hosts.set(api,s);return api;
}
export const isNativeHostContext=value=>!!value&&!types.isProxy(value)&&hosts.has(value);
function state(host){const s=hosts.get(host);if(!s||s.closed)throw nativeFault('UNVERIFIED');return s;}
function operation(host,cap){const s=state(host),op=operations.get(cap);if(!op||op.host!==host||op.closed||op.signal.aborted)throw nativeFault('CONTEXT_CHANGED');return {s,op};}

// 고정 helper만 실행한다. 임의 executable·argv·IPC factory는 제공하지 않는다.
async function registry(s,request,signal,work){
  if(s.configFile){const current=configurationFile(s.configFile.path).proof;if(current.digest!==s.configFile.digest||current.identity!==s.configFile.identity)throw nativeFault('CONTEXT_CHANGED');}
  nativeSignal(signal);if(signal?.aborted)throw nativeFault('CANCELLED');const before={registry:physical(s.config.registryRoot),vault:physical(s.config.vaultRoot),project:physical(s.config.projectRoot)};
  const nonce=randomUUID(),deadline=Math.min(request.deadline,Date.now()+s.config.timeoutMs),remainingMs=deadline-Date.now();if(remainingMs<=0)throw nativeFault('EXPIRED');
  const child=spawn(POWERSHELL,['-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',HELPER],{windowsHide:true,shell:false,stdio:['pipe','pipe','pipe'],cwd:s.config.registryRoot,env:{SystemRoot:'C:\\Windows',WINDIR:'C:\\Windows'}});s.children.add(child);
  return await new Promise((resolvePromise,reject)=>{
    let stage='starting',buffer='',bytes=0,result,workValue,error=null,settled=false;const mono=performance.now()+remainingMs;
    const alive=()=>{if(signal?.aborted)throw nativeFault('CANCELLED');if(Date.now()>=deadline||performance.now()>=mono)throw nativeFault('EXPIRED');if(s.closed)throw nativeFault('CANCELLED');};
    const fail=e=>{if(!error)error=e;child.stdin.destroy();if(child.exitCode===null)child.kill();};
    const timer=setTimeout(()=>fail(nativeFault('TIMEOUT')),remainingMs),abort=()=>fail(nativeFault('CANCELLED'));signal?.addEventListener('abort',abort,{once:true});
    child.on('error',()=>fail(nativeFault('UNVERIFIED')));child.stdin.on('error',()=>fail(nativeFault('OUTCOME_UNKNOWN')));child.stderr.on('data',()=>{});
    child.stdout.on('data',chunk=>{if(error)return;bytes+=chunk.length;if(bytes>32768)return fail(nativeFault('RESPONSE_INVALID'));buffer+=chunk.toString('utf8');let at;
      while((at=buffer.indexOf('\n'))>=0){const line=buffer.slice(0,at);buffer=buffer.slice(at+1);let frame;try{alive();frame=JSON.parse(line);if(frame.stage==='error')throw nativeFault('UNVERIFIED');
          if(stage==='starting'){const d=nativeOwn(frame,['stage','nonce','result']);if(d.stage!=='ready'||d.nonce!==nonce)throw nativeFault('RESPONSE_INVALID');result=d.result;stage='working';
            const pending=Promise.resolve().then(()=>{alive();return work(result);}).then(v=>{workValue=v.value;alive();stage='committing';child.stdin.end(JSON.stringify({nonce,outcome:v.outcome})+'\n');},e=>{error=e;stage='committing';if(child.stdin.writable)child.stdin.end(JSON.stringify({nonce,outcome:'unknown'})+'\n');else fail(e);});pending.catch(fail);
          }else if(stage==='committing'){const d=nativeOwn(frame,['stage','nonce']);if(d.stage!=='done'||d.nonce!==nonce)throw nativeFault('RESPONSE_INVALID');stage='finished';}else throw nativeFault('RESPONSE_INVALID');
        }catch(e){fail(e);}}
    });
    child.once('close',code=>{if(settled)return;settled=true;clearTimeout(timer);signal?.removeEventListener('abort',abort);s.children.delete(child);
      try{if(error)throw error;alive();if(code!==0||stage!=='finished'||buffer.trim())throw nativeFault('OUTCOME_UNKNOWN');
        if(before.registry!==physical(s.config.registryRoot)||before.vault!==physical(s.config.vaultRoot)||before.project!==physical(s.config.projectRoot))throw nativeFault('CONTEXT_CHANGED');resolvePromise(workValue);
      }catch(e){reject(e);}
    });
    const message={schema:'alekov.native-registry.request.v1',action:request.action,registryRoot:s.config.registryRoot,vaultRoot:s.config.vaultRoot,projectRoot:s.config.projectRoot,configurationFile:s.configFile,deadline,remainingMs,nonce,binding:request.binding};
    child.stdin.write(JSON.stringify(message)+'\n');if(signal?.aborted)abort();
  });
}
export async function openNativeHostOperation(host,call={}){
  const o=nativeOwn(call,[],['signal','timeoutMs']),signal=nativeSignal(o.signal),s=state(host),timeoutMs=o.timeoutMs??10000;
  const loginCap=await openNativeOperation(s.login,{signal,timeoutMs}),binding=nativeOperationBinding(loginCap);
  try{
    const selected=await registry(s,{action:'select',deadline:binding.deadline,binding:null},binding.signal,async raw=>{
      const d=nativeOwn(raw,['projectId','directoryInstance','registryRevision']);if(typeof d.projectId!=='string'||typeof d.directoryInstance!=='string'||!Number.isSafeInteger(d.registryRevision))throw nativeFault('RESPONSE_INVALID');await refreshNativeOperation(loginCap);return {outcome:'read',value:d};});
    const instance=physical(s.config.projectRoot);if(!s.project||s.project.directoryInstance!==selected.directoryInstance||s.project.nodeInstance!==instance){s.projectGeneration++;s.project={...selected,nodeInstance:instance};}
    const cap=Object.freeze(Object.create(null)),op={host,loginCap,operationId:randomUUID(),binding,project:Object.freeze({...s.project}),projectGeneration:s.projectGeneration,signal:binding.signal,closed:false};operations.set(cap,op);s.operations.add(cap);assertNativeHostOperation(host,cap);return cap;
  }catch(e){closeNativeOperation(loginCap);throw e;}
}
export function assertNativeHostOperation(host,cap){const {s,op}=operation(host,cap),c=assertNativeOperation(op.loginCap);
  if(s.configFile){const current=configurationFile(s.configFile.path).proof;if(current.digest!==s.configFile.digest||current.identity!==s.configFile.identity)throw nativeFault('CONTEXT_CHANGED');}
  if(s.projectGeneration!==op.projectGeneration||s.project?.directoryInstance!==op.project.directoryInstance||physical(s.config.projectRoot)!==op.project.nodeInstance)throw nativeFault('CONTEXT_CHANGED');
  const final=assertNativeOperation(op.loginCap);if(Object.keys(c).some(k=>c[k]!==final[k]))throw nativeFault('CONTEXT_CHANGED');
  return Object.freeze({subjectId:final.canonicalStudentId,alephUserId:final.alephUserId,siteId:final.siteId,identityVersion:final.identityVersion,projectId:op.project.projectId});
}
export async function readNativeHostOperation(host,cap){operation(host,cap);await refreshNativeOperation(operations.get(cap).loginCap);return assertNativeHostOperation(host,cap);}
// 완료된 flow의 표시는 새로 확인한 operation과 같은 로그인·프로젝트일 때만 유지한다.
// 닫힌 과거 capability는 비교에만 쓰며 저장·요청 권위로 되살리지 않는다.
export function assertNativeHostContinuity(host,previous,current){
  const prior=operations.get(previous),{op}=operation(host,current);
  if(!prior||prior.host!==host||prior.binding.nativeInstance!==op.binding.nativeInstance||prior.binding.generation!==op.binding.generation
    ||prior.projectGeneration!==op.projectGeneration||prior.project.directoryInstance!==op.project.directoryInstance||prior.project.nodeInstance!==op.project.nodeInstance
    ||prior.project.projectId!==op.project.projectId)throw nativeFault('CONTEXT_CHANGED');
  return assertNativeHostOperation(host,current);
}
// c1(#968) genuine host receipt ticket: SDP 영수증 begin 이 돌려준 서명 대응표 nativeProjectId 를 이 host 의 현재 native project 와 대조한 뒤에만
// 같은 operation 의 login closure 로 ticket 을 받는다(canonical4 대조는 gateway 쪽, nativeProject 대조는 이 host 쪽 — 서로 다른 증거).
export async function issueNativeHostReceipt(host,cap,input){
  const x=nativeOwn(input,['challengeId','contextDigest','nativeProjectId']);
  if(typeof x.nativeProjectId!=='string'||!x.nativeProjectId||x.nativeProjectId.length>200)throw nativeFault('INPUT_INVALID');
  const {op}=operation(host,cap);
  const before=await readNativeHostOperation(host,cap);
  if(before.projectId!==x.nativeProjectId)throw nativeFault('CONTEXT_CHANGED'); // 대응표의 native project 가 아님: ticket 발급 0
  const ticket=await issueNativeReceiptTicket(op.loginCap,{challengeId:x.challengeId,contextDigest:x.contextDigest});
  const after=assertNativeHostOperation(host,cap);
  if(Object.keys(before).some(k=>before[k]!==after[k]))throw nativeFault('CONTEXT_CHANGED');
  return ticket;
}
export function closeNativeHostOperation(cap){const op=operations.get(cap);if(!op||op.closed)return;op.closed=true;closeNativeOperation(op.loginCap);hosts.get(op.host)?.operations.delete(cap);}
export function createNativeOperationVault(host,cap){const {s,op}=operation(host,cap);
  const execute=async(action,input,options={})=>{
    const call=nativeOwn(options,[],['signal']),signal=nativeSignal(call.signal);if(signal?.aborted)throw nativeFault('CANCELLED');
    const merged=signal?AbortSignal.any([op.signal,signal]):op.signal;
    const expected=nativeOwn(input,action==='save'?['expectedContext','connectionId','credential']:action==='remove'?['expectedContext','credentialFingerprint']:['expectedContext']);
    const copied=nativeOwn(expected.expectedContext,['subjectId','alephUserId','siteId','identityVersion','projectId']);
    let credential=null,tokenDigest='0'.repeat(64),credentialDigest='0'.repeat(64);
    if(action==='save'){credential=nativeOwn(expected.credential,credentialKeys);if(credentialKeys.some(k=>!['string','number'].includes(typeof credential[k]))||typeof credential.token!=='string'||!/^sk-on-[A-Za-z0-9_-]{43}$/.test(credential.token))throw nativeFault('INPUT_INVALID');tokenDigest=sha(credential.token);credentialDigest=sha(canonical(credential));}
    if(action==='remove'){if(typeof expected.credentialFingerprint!=='string'||!HASH.test(expected.credentialFingerprint))throw nativeFault('INPUT_INVALID');tokenDigest=expected.credentialFingerprint;}
    const context=await readNativeHostOperation(host,cap);if(canonical(copied)!==canonical(context))throw nativeFault('CONTEXT_CHANGED');
    const source=nativeOperationBinding(op.loginCap),contextDigest=sha(canonical(context));
    const binding={operationId:op.operationId,nativeInstance:source.nativeInstance,generation:source.generation,projectGeneration:op.projectGeneration,directoryInstance:op.project.directoryInstance,contextDigest,tokenDigest,credentialDigest,expectedRevision:0};
    const vault=createAppCredentialVault({vaultRoot:s.config.vaultRoot,baseUrl:CLCO_GATEWAY_ORIGIN+'/api/apps/aleph-on/v1',timeoutMs:s.config.timeoutMs,
      resolveCurrentContext:async()=>{if(merged.aborted)throw nativeFault('CANCELLED');const current=await readNativeHostOperation(host,cap);if(merged.aborted)throw nativeFault('CANCELLED');return current;}});
    const result=await registry(s,{action,deadline:source.deadline,binding},merged,async raw=>{
      const fence=nativeOwn(raw,['operationId','nativeInstance','generation','projectGeneration','directoryInstance','contextDigest','tokenDigest','credentialDigest','state','revision','vault','deadline']);
      if(action!=='save'&&(fence.state!=='accepted'&&action!=='remove'||fence.nativeInstance!==source.nativeInstance||fence.generation!==source.generation||fence.projectGeneration!==op.projectGeneration||fence.directoryInstance!==op.project.directoryInstance||fence.contextDigest!==contextDigest))throw nativeFault('CONTEXT_CHANGED');
      await readNativeHostOperation(host,cap);if(merged.aborted)throw nativeFault('CANCELLED');let value;
      if(action==='save')value=await vault.persistCredential({connectionId:expected.connectionId,expectedContext:context,credential},{signal:merged});
      else if(action==='load'){value=await vault.load({expectedContext:context},{signal:merged});if(value===null||sha(value.token)!==fence.tokenDigest||sha(canonical(nativeOwn(value,credentialKeys)))!==fence.credentialDigest)throw nativeFault('CONTEXT_CHANGED');}
      else value=await vault.remove({expectedContext:context,credentialFingerprint:tokenDigest},{signal:merged});
      await readNativeHostOperation(host,cap);if(merged.aborted)throw nativeFault('CANCELLED');assertNativeHostOperation(host,cap);
      return {outcome:action==='save'?'accepted':action==='remove'?'removed':'read',value};
    });
    if(merged.aborted)throw nativeFault('CANCELLED');assertNativeHostOperation(host,cap);return result;
  };
  return Object.freeze({persistCredential:(input,call)=>execute('save',input,call),load:(input,call)=>execute('load',input,call),remove:(input,call)=>execute('remove',input,call)});
}
