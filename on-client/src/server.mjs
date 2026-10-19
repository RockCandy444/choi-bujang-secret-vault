import http from 'node:http';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {randomUUID} from 'node:crypto';
import {AsyncLocalStorage} from 'node:async_hooks';
import {types} from 'node:util';
import {createActionService} from './actions/service.mjs';
import {createSdpActionConfiguration} from './actions/sdp-action-engine.mjs';
import {readActionStartupConfiguration} from './actions/action-startup-config.mjs';
import {engineMethod,engineError,loadEngine,demoEngine} from './engine.mjs';
import {readSdpHostConfiguration} from './engine/sdp-host-config.mjs';
import {createSdpHostEngine,isOwnedSdpHostEngine,openSdpIncidentOperation,readSdpIncidentOperation,assertSdpIncidentOperation,closeSdpIncidentOperation} from './engine/sdp-host.mjs';
import {createOnAiService,validateLearnerSupportGuide} from './ai/service.mjs';
import {prepareLearnerSupportRequest} from './ai/learner-support-contract.mjs';
import {createVaultOnAiService} from './ai/vault-service.mjs';
import {createConnectionManager} from './connection/manager.mjs';
import {createProjectScanner} from './vulnerabilities/project-scan.mjs';
import {buildLocalLearnerSupportGuide,isLearnerSupportProblemKind,readLocalLearnerSupportObservation} from './learner-support/service.mjs';
import {nativeOwn,nativePublicError} from './connection/native-login.mjs';
import {createNativeHostContext,captureNativeHostConfiguration,readNativeHostConfiguration,openNativeHostOperation,readNativeHostOperation,assertNativeHostOperation,createNativeOperationVault,closeNativeHostOperation} from './connection/native-context.mjs';

const root=fileURLToPath(new URL('../',import.meta.url));
const id=value=>typeof value==='string'&&/^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$/.test(value);
const record=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const text=value=>typeof value==='string'&&value.length<=2000;
const files=new Map([['/','public/index.html'],['/index.html','public/index.html'],['/app.js','public/app.js'],['/style.css','public/style.css'],['/vulnerabilities-view.mjs','public/vulnerabilities-view.mjs'],['/student/extension.mjs','student/extension.mjs'],
  ['/ai-connect.mjs','public/ai-connect.mjs'],
  ...['alekov-ai-explain','alekov-app-icon','alekov-connect-approval','alekov-connection-unknown','alekov-empty-records'].map(name=>[`/assets/alekov/${name}.webp`,`public/assets/alekov/${name}.webp`])]);
const connectionRoutes=new Map(['start','finish','status','cancel'].map(kind=>[`/api/ai/connect/${kind}`,kind]));
const safeErrors=Object.freeze({
  ENGINE_NOT_CONNECTED:[503,'기존 서버·에이전트의 연결을 확인할 수 없습니다. 연결 어댑터를 먼저 확인하세요.'],
  ENGINE_ADAPTER_INVALID:[503,'기존 서버 연결 어댑터의 형식을 확인하세요.'],
  ENGINE_RESULT_UNVERIFIED:[503,'서버 응답을 확인할 수 없습니다. 정상으로 판단하지 말고 연결 계약을 확인하세요.'],
  ENGINE_TIMEOUT:[503,'기존 서버의 응답 시간이 초과됐습니다. 다시 확인하세요.'],
  SUBJECT_SCOPE_UNVERIFIED:[503,'현재 로그인과 사건·프로젝트의 연결을 확인할 수 없습니다.'],
  JSON_REQUIRED:[415,'JSON 요청 형식을 확인하세요.'],REQUEST_TOO_LARGE:[413,'요청이 너무 큽니다.'],
  INVALID_JSON:[400,'요청 형식을 확인하세요.'],REQUEST_INVALID:[400,'요청에 필요한 항목만 보내세요.'],
  HOST_REJECTED:[403,'로컬 실행 주소를 확인하세요.'],QUERY_REJECTED:[400,'지원하지 않는 요청입니다.'],
  ORIGIN_REJECTED:[403,'앱 화면에서 다시 요청하세요.'],EVENT_NOT_FOUND:[404,'본인 기록에서 사건을 찾을 수 없습니다.'],
  APP_NOT_FOUND:[404,'업무 앱을 찾을 수 없습니다.'],
  REQUEST_CANCELLED:[499,'연결이 종료되어 요청을 취소했습니다.'],
  REQUEST_TIMEOUT:[503,'요청 처리 시간이 초과됐습니다. 연결 상태를 확인한 뒤 다시 시도하세요.'],
  ON_AI_PROVISIONING_PENDING:[503,'학생 앱의 현재 계정 연결과 앱 전용 AI 이용 권한을 담당자에게 확인하세요.'],
  SERVICE_UNAVAILABLE:[503,'연결 상태를 확인할 수 없습니다. 잠시 후 다시 시도하세요.'],
});
const aiErrorMessages=Object.freeze({
  ON_AI_PROVISIONING_PENDING:'학생 앱의 현재 계정 연결과 앱 전용 AI 이용 권한을 담당자에게 확인하세요.',
  MODEL_NOT_CONFIGURED:'앱 서버에 허용된 AI 모델을 설정하세요.',
  ON_AI_AUTHORIZATION_CHANGED:'AI 이용 권한 내용이 점검 도중 바뀌었습니다. 다시 점검하기 전에 담당자에게 현재 권한을 확인하세요.',
  ON_AI_MODEL_LIST_EMPTY:'현재 앱 권한으로 쓸 수 있는 AI 모델이 없습니다. 담당자에게 모델 허용 설정을 확인하세요.',
  ON_AI_INVALID_INPUT:'사건의 근거와 현재 상태를 확인하세요.',ON_AI_INVALID_OUTPUT:'AI 설명의 근거와 형식을 확인할 수 없습니다.',
  ON_AI_TRANSPORT_PENDING:'공통 AI 연결을 준비 중입니다.',
  WB_CLCO_AUTH_REQUIRED:'앱 전용 열쇠를 확인하세요.',WB_CLCO_ACCESS_BLOCKED:'학생 앱의 이용 권한을 담당자에게 확인하세요.',
  WB_CLCO_SESSION_CLOSED:'현재 AI 이용 시간을 확인하세요.',WB_CLCO_COHORT_BUDGET_EXHAUSTED:'반의 AI 사용량을 담당자에게 확인하세요.',
  WB_CLCO_RATE_LIMITED:'AI 요청이 잠시 제한됐습니다.',WB_CLCO_LIMIT_REACHED:'AI 이용 한도를 확인하세요.',
  WB_CLCO_SERVER_UNAVAILABLE:'AI 서버가 응답하지 않습니다.',WB_CLCO_TIMEOUT:'AI 요청 시간이 초과됐습니다.',
  WB_CLCO_NETWORK_ERROR:'AI 서버 연결을 확인하세요.',WB_CLCO_CANCELLED:'AI 요청을 취소했습니다.',
  WB_CLCO_INVALID_URL:'AI 서버 주소를 확인하세요.',WB_CLCO_INVALID_TOKEN:'앱 전용 열쇠 형식을 확인하세요.',
  WB_CLCO_INVALID_LIMIT:'AI 요청 제한 시간을 확인하세요.',WB_CLCO_INVALID_RESPONSE:'AI 서버 응답을 확인할 수 없습니다.',
  WB_CLCO_INVALID_CONTENT_TYPE:'AI 서버 응답 형식을 확인하세요.',WB_CLCO_RESPONSE_TOO_LARGE:'AI 서버 응답이 너무 큽니다.',
  WB_CLCO_REDIRECT_BLOCKED:'AI 서버 주소가 다른 곳으로 이동했습니다.',WB_CLCO_REQUEST_FAILED:'AI 요청을 처리하지 못했습니다.',
});
// native /api/ai/check 응답의 retryable: 기다리거나 다시 요청하면 풀릴 수 있다고 원인이 확인된 것만 true.
// 권한·구성·검증 불가(PENDING)·허용 밖 모델·응답 계약 위반·원인 불명은 false(자동 재시도는 어디서도 하지 않는다).
const AI_RETRYABLE=new Set(['WB_CLCO_RATE_LIMITED','WB_CLCO_SERVER_UNAVAILABLE','WB_CLCO_TIMEOUT','WB_CLCO_NETWORK_ERROR','WB_CLCO_CANCELLED','REQUEST_TIMEOUT','REQUEST_CANCELLED']);
const exact=(value,keys)=>record(value)&&Object.keys(value).length===keys.length&&keys.every(key=>Object.hasOwn(value,key));
const uuid=value=>typeof value==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
const confirmation=value=>typeof value==='string'&&/^ac-on-[A-Za-z0-9_-]{43}$/.test(value);
const actionErrors=Object.freeze({
  ACTION_UNSUPPORTED:[503,'현재 원천 서버의 조치 연결과 권한 확인을 지원하지 않습니다.'],
  ACTION_INPUT_INVALID:[400,'조치 요청 항목을 확인하세요.'],ACTION_SCOPE_UNVERIFIED:[403,'현재 사용자와 조치 권한의 연결을 확인할 수 없습니다.'],
  ACTION_SCOPE_CHANGED:[403,'사용자·프로젝트·세션 또는 권한이 변경됐습니다. 현재 기록에서 다시 확인하세요.'],
  ACTION_EVENT_UNAVAILABLE:[404,'현재 본인 기록에서 사건을 확인할 수 없습니다.'],ACTION_DENIED:[403,'현재 원천 정책이 이 조치를 허용하지 않습니다.'],
  ACTION_SNAPSHOT_CHANGED:[409,'사건의 대상·근거·상태가 변경됐습니다. 다시 준비하고 확인하세요.'],
  ACTION_CONFIRMATION_INVALID:[400,'이 조치의 확인 정보를 확인하세요.'],ACTION_CONFIRMATION_EXPIRED:[409,'조치 확인 시간이 지났습니다. 다시 준비하세요.'],
  ACTION_STORE_FAILED:[503,'조치 기록을 확인할 수 없습니다. 자동 집행하지 말고 결과를 확인하세요.'],
  ACTION_TIMEOUT:[503,'조치 결과를 확인하지 못했습니다. 효과가 없다고 판단하지 말고 결과만 다시 조회하세요.'],
  ACTION_CANCELLED:[499,'요청이 취소됐습니다. 이미 전달된 조치의 결과는 별도로 확인하세요.'],
  ACTION_RESULT_UNVERIFIED:[503,'조치 처리 결과를 확인할 수 없습니다. 정상 처리로 판단하지 마세요.'],
});
function projectAction(output,method,input) {
  if(output?.ok!==true){
    const code=Object.hasOwn(actionErrors,output?.error?.code)?output.error.code:'ACTION_RESULT_UNVERIFIED';
    const [status,message]=actionErrors[code];return {status,body:{ok:false,error:{code,message,retryable:false}}};
  }
  const d=output.data;
  if(!record(d)||!uuid(d.requestId)||!['prepared','pending','succeeded','denied','failed','unknown'].includes(d.status)
    ||method!=='prepare'&&d.requestId!==input.requestId)throw engineError('SERVICE_UNAVAILABLE','');
  const data={requestId:d.requestId,status:d.status};
  if(d.receiptId!==undefined){
    if(!uuid(d.receiptId)||!id(d.eventId)||!id(d.actionId)||!Number.isSafeInteger(d.version)||d.version<=0||typeof d.replayed!=='boolean')throw engineError('SERVICE_UNAVAILABLE','');
    Object.assign(data,{receiptId:d.receiptId,eventId:d.eventId,actionId:d.actionId,version:d.version,replayed:d.replayed});
  }else if(d.status!=='unknown')throw engineError('SERVICE_UNAVAILABLE','');
  if(method==='prepare'){
    if(d.status!=='prepared'||d.eventId!==input.eventId||d.actionId!==input.actionId||!confirmation(d.confirmationId)
      ||typeof d.confirmationExpiresAt!=='string'||!Number.isFinite(Date.parse(d.confirmationExpiresAt))||!exact(d.target,['id','generation'])
      ||typeof d.target.id!=='string'||!/^(?:device|subject):[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$/.test(d.target.id)
      ||!Number.isSafeInteger(d.target.generation)||d.target.generation<=0)throw engineError('SERVICE_UNAVAILABLE','');
    Object.assign(data,{confirmationId:d.confirmationId,confirmationExpiresAt:d.confirmationExpiresAt,target:{id:d.target.id,generation:d.target.generation}});
  }
  if(d.observation!==undefined){
    if(!exact(d.observation,['observedAt','effectApplied'])||typeof d.observation.observedAt!=='string'||!Number.isFinite(Date.parse(d.observation.observedAt))
      ||typeof d.observation.effectApplied!=='boolean'||d.status==='succeeded'&&d.observation.effectApplied!==true)throw engineError('SERVICE_UNAVAILABLE','');
    data.observation={observedAt:d.observation.observedAt,effectApplied:d.observation.effectApplied};
  }
  if(d.status==='succeeded'&&!data.observation)throw engineError('SERVICE_UNAVAILABLE','');
  if(d.superseded===true&&d.status==='unknown')data.superseded=true;
  return {status:200,body:{ok:true,data}};
}
const opaque=value=>typeof value==='string'&&/^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/.test(value);
const canonicalSubject=value=>typeof value==='string'&&value.length>0&&value.length<=200&&value===value.trim()&&!/[\u0000-\u001f\u007f]/.test(value);
const AI_BINDING_KEYS=['schema','sourceSubjectId','canonicalStudentId','alephUserId','siteId','identityVersion','projectId','sessionId'];
function assertAiBinding(binding,source) {
  if(!exact(binding,AI_BINDING_KEYS)||binding.schema!=='aleph.on.ai-identity.v1'||!canonicalSubject(binding.canonicalStudentId)
    || !opaque(binding.alephUserId)||!opaque(binding.siteId)||!Number.isSafeInteger(binding.identityVersion)||binding.identityVersion<=0
    || binding.sourceSubjectId!==source.sourceSubjectId||binding.projectId!==source.projectId||binding.sessionId!==source.sessionId)
    throw engineError('ON_AI_PROVISIONING_PENDING','');
  return Object.freeze({...binding});
}
function aiFailure(output) {
  const code=Object.hasOwn(aiErrorMessages,output?.error?.code)?output.error.code:'WB_CLCO_REQUEST_FAILED';
  return {code,message:aiErrorMessages[code],retryable:true};
}
function aiHelp(output) {
  const value=output?.help;
  const allowed=['ON_AI_APP_AUTHORIZATION_VERIFIED','ON_AI_TEST_TRANSPORT_ONLY'];
  if(!record(value)||value.component!=='on-ai'||!allowed.includes(value.code)||typeof value.appCredentialsConfigured!=='boolean'
    || !['verified','pending'].includes(value.provisioning)||value.automaticRetries!==0||value.workbenchRequiredAtRuntime!==false)
    throw engineError('SERVICE_UNAVAILABLE','');
  if(output.audienceAuthorization==='verified'&&(value.code!=='ON_AI_APP_AUTHORIZATION_VERIFIED'||value.provisioning!=='verified')
    || output.audienceAuthorization==='test'&&(value.code!=='ON_AI_TEST_TRANSPORT_ONLY'||value.provisioning!=='pending'))throw engineError('SERVICE_UNAVAILABLE','');
  return {component:'on-ai',code:value.code,appCredentialsConfigured:value.appCredentialsConfigured,provisioning:value.provisioning,
    automaticRetries:0,workbenchRequiredAtRuntime:false};
}
function assertExplanation(explanation,event,secrets) {
  const safe=(value,max)=>typeof value==='string'&&value.trim().length>0&&value.length<=max
    && !/(?:Bearer\s+\S+|sk-(?:on-|proj-|ant-)?[A-Za-z0-9_-]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/i.test(value)
    && !secrets.some(secret=>secret&&value.includes(secret));
  const evidenceIds=new Set(event.evidence.map(row=>row.id));
  const references=value=>Array.isArray(value)&&value.length>0&&new Set(value).size===value.length&&value.every(ref=>evidenceIds.has(ref));
  if(!exact(explanation,['summary','evidenceIds','proposals','requiresHumanConfirmation','executed'])||!safe(explanation.summary,1500)
    || explanation.requiresHumanConfirmation!==true||explanation.executed!==false||!references(explanation.evidenceIds)||explanation.evidenceIds.length!==evidenceIds.size
    || !Array.isArray(explanation.proposals)||explanation.proposals.length>3||explanation.proposals.some(row=>!exact(row,['action','evidenceIds','reason'])
      || !event.supportedActions.includes(row.action)||!references(row.evidenceIds)||!safe(row.reason,500)))throw engineError('SERVICE_UNAVAILABLE','');
  return {summary:explanation.summary,evidenceIds:[...explanation.evidenceIds],proposals:explanation.proposals.map(row=>({action:row.action,evidenceIds:[...row.evidenceIds],reason:row.reason})),requiresHumanConfirmation:true,executed:false};
}
function assertData(kind,data) {
  let valid=false;
  if(kind==='identity') valid=record(data)&&[data.user,data.device,data.session].every(row=>record(row)&&id(row.id))&&text(data.user.label)&&text(data.device.label)&&['compliant','noncompliant','unknown'].includes(data.device.status)&&['active','expired','revoked','unknown'].includes(data.session.status);
  if(kind==='apps') valid=Array.isArray(data)&&data.length<=100&&data.every(row=>record(row)&&id(row.id)&&text(row.name))&&new Set(data.map(row=>row.id)).size===data.length;
  if(kind==='decision') valid=record(data)&&id(data.appId)&&['allow','deny','challenge','unknown'].includes(data.decision)&&text(data.reason)&&Number.isFinite(Date.parse(data.checkedAt));
  if(kind==='events') valid=Array.isArray(data)&&data.length<=500&&data.every(row=>record(row)&&id(row.id)&&['access','xdr'].includes(row.kind)&&Number.isFinite(Date.parse(row.at))&&text(row.summary)&&Array.isArray(row.evidence)&&row.evidence.length<=20&&row.evidence.every(e=>record(e)&&id(e.id)&&text(e.text))&&Array.isArray(row.rules)&&row.rules.length<=20&&row.rules.every(r=>record(r)&&id(r.id)&&text(r.text))&&record(row.state)&&['allowed','denied','unknown'].includes(row.state.access)&&['active','expired','revoked','unknown'].includes(row.state.session)&&['compliant','noncompliant','unknown'].includes(row.state.device)&&Array.isArray(row.supportedActions)&&row.supportedActions.every(id))&&new Set(data.map(row=>row.id)).size===data.length;
  if(kind==='devices') valid=Array.isArray(data)&&data.length<=100&&data.every(row=>record(row)&&id(row.id)&&text(row.label)&&['compliant','noncompliant','unknown'].includes(row.status));
  if(kind==='sessions') valid=Array.isArray(data)&&data.length<=100&&data.every(row=>record(row)&&id(row.id)&&['active','expired','revoked','unknown'].includes(row.status));
  if(!valid) throw engineError('ENGINE_RESULT_UNVERIFIED','서버 응답을 확인할 수 없습니다. 정상으로 판단하지 말고 연결 계약을 확인하세요.');
  // 어댑터 원본의 토큰·인증서·추가 내부 필드를 브라우저로 내보내지 않는다.
  const device=row=>({id:row.id,label:row.label,status:row.status});
  const session=row=>({id:row.id,status:row.status});
  if(kind==='identity')return {user:{id:data.user.id,label:data.user.label},device:device(data.device),session:session(data.session)};
  if(kind==='apps')return data.map(row=>({id:row.id,name:row.name}));
  if(kind==='decision')return {appId:data.appId,decision:data.decision,reason:data.reason,checkedAt:data.checkedAt};
  if(kind==='events')return data.map(row=>({id:row.id,kind:row.kind,at:row.at,appId:id(row.appId)?row.appId:null,summary:row.summary,evidence:row.evidence.map(e=>({id:e.id,text:e.text})),rules:row.rules.map(r=>({id:r.id,text:r.text})),state:{access:row.state.access,session:row.state.session,device:row.state.device},supportedActions:[...row.supportedActions]}));
  if(kind==='devices')return data.map(device);
  if(kind==='sessions')return data.map(session);
  throw engineError('ENGINE_RESULT_UNVERIFIED','서버 결과 형식을 확인할 수 없습니다.');
}
// 본인 조회의 범위·생략 여부는 원 배열의 데이터 속성에서만 읽는다.
// 기존 어댑터에 이 정보가 없으면 기존 응답을 유지한다.
function collectionCoverage(kind,rows) {
  const specs={events:['own-recorded-events',40],devices:['own-registered-devices',100],sessions:['current-verified-connection',1]};
  if(!Object.hasOwn(specs,kind))return null;
  if(!Array.isArray(rows)||types.isProxy(rows))throw engineError('ENGINE_RESULT_UNVERIFIED','');
  const descriptor=Object.getOwnPropertyDescriptor(rows,'coverage');
  if(!descriptor)return null;
  if(!Object.hasOwn(descriptor,'value'))throw engineError('ENGINE_RESULT_UNVERIFIED','');
  const value=descriptor.value,keys=['schema','kind','scope','limit','total','returned','truncated','observedAtMs'];
  if(!value||typeof value!=='object'||types.isProxy(value)||![Object.prototype,null].includes(Object.getPrototypeOf(value)))throw engineError('ENGINE_RESULT_UNVERIFIED','');
  const fields=Object.getOwnPropertyDescriptors(value);
  if(Reflect.ownKeys(fields).length!==keys.length||keys.some(key=>!Object.hasOwn(fields,key)||!Object.hasOwn(fields[key],'value')))throw engineError('ENGINE_RESULT_UNVERIFIED','');
  const c=Object.fromEntries(keys.map(key=>[key,fields[key].value])),[scope,limit]=specs[kind];
  if(c.schema!=='alekov.sdp.coverage.v1'||c.kind!==kind||c.scope!==scope||c.limit!==limit
    ||!Number.isSafeInteger(c.total)||c.total<0||!Number.isSafeInteger(c.returned)||c.returned!==rows.length||c.returned>limit||c.total<c.returned
    ||c.truncated!==(c.total>c.returned)||!Number.isSafeInteger(c.observedAtMs)||c.observedAtMs<=0
    ||c.observedAtMs>Date.now()+5000||c.observedAtMs<Date.now()-20000
    ||kind==='sessions'&&(c.total!==1||c.returned!==1))throw engineError('ENGINE_RESULT_UNVERIFIED','');
  return Object.freeze(c);
}
async function jsonBody(req,keys,validate=(key,value)=>id(value)) {
  if(!/^application\/json(?:;|$)/i.test(req.headers['content-type']??''))throw engineError('JSON_REQUIRED','JSON 요청 형식을 확인하세요.',415);
  let size=0;const chunks=[];
  for await(const chunk of req){size+=chunk.length;if(size>8192)throw engineError('REQUEST_TOO_LARGE','요청이 너무 큽니다.',413);chunks.push(chunk);}
  let body;try{body=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)));}catch{throw engineError('INVALID_JSON','요청 형식을 확인하세요.',400);}
  if(!record(body)||Object.keys(body).length!==keys.length||keys.some(key=>!Object.hasOwn(body,key)||!validate(key,body[key])))throw engineError('REQUEST_INVALID','요청에 필요한 항목만 보내세요.',400);
  return body;
}
export function createOnServer(serverOptions={}) {
  if(!serverOptions||typeof serverOptions!=='object'||types.isProxy(serverOptions))throw Error('INVALID_SERVER_AI_CONFIGURATION');
  const sdpDescriptor=Object.getOwnPropertyDescriptor(serverOptions,'sdpHostEngine');let sdpHostEngine=null;
  if(sdpDescriptor){
    if(!Object.hasOwn(sdpDescriptor,'value')||!sdpDescriptor.enumerable||sdpDescriptor.value!==undefined&&!isOwnedSdpHostEngine(sdpDescriptor.value))throw Error('INVALID_SERVER_AI_CONFIGURATION');
    sdpHostEngine=sdpDescriptor.value??null;
  }else for(let p=Object.getPrototypeOf(serverOptions);p;p=Object.getPrototypeOf(p)){if(types.isProxy(p)||Object.getOwnPropertyDescriptor(p,'sdpHostEngine'))throw Error('INVALID_SERVER_AI_CONFIGURATION');}
  const nativeDescriptor=Object.getOwnPropertyDescriptor(serverOptions,'nativeHostConfiguration');let nativeConfiguration=null;
  if(nativeDescriptor){if(!Object.hasOwn(nativeDescriptor,'value')||!nativeDescriptor.enumerable)throw Error('INVALID_SERVER_AI_CONFIGURATION');
    nativeConfiguration=captureNativeHostConfiguration(nativeDescriptor.value);}
  else for(let p=Object.getPrototypeOf(serverOptions);p;p=Object.getPrototypeOf(p)){if(types.isProxy(p)||Object.getOwnPropertyDescriptor(p,'nativeHostConfiguration'))throw Error('INVALID_SERVER_AI_CONFIGURATION');}
  const {engine={evidenceMode:'disconnected'},actionConfiguration:givenActionConfiguration,sdpActionStartup,ai,resolveAiIdentity,readLearnerSupportIdentity,aiEnv=process.env,appCredentialVault,vaultAiConfiguration,aiConnectionConfiguration,allowLoopbackAiHttp=false,aiTimeoutMs=10000,
    scanner=createProjectScanner(),assetsRoot=root,clock=()=>new Date(),readTimeoutMs=10000,requestTimeoutMs=15000}=serverOptions;
  if(nativeConfiguration&&(ai!==undefined||resolveAiIdentity!==undefined||readLearnerSupportIdentity!==undefined||appCredentialVault!==undefined||vaultAiConfiguration!==undefined||aiConnectionConfiguration!==undefined||typeof aiEnv.ON_AI_APP_KEY==='string'&&aiEnv.ON_AI_APP_KEY))throw Error('INVALID_SERVER_AI_CONFIGURATION');
  const nativeHost=nativeConfiguration?createNativeHostContext(nativeConfiguration):null;
  // c2(#978): host 가 sdpActionStartup({databasePath, policy})을 주면, 이 서버가 만든 SDP host engine 과 genuine native host 를
  // createSdpActionConfiguration 에 그대로 넘긴다(자기 철회 뒤 본인 영수증 포함). identityVersion 은 같은 native host operation 에서 읽는다.
  // 학생 body·header 로 DB·정책·engine·nativeHost 를 고를 수 없다. actionConfiguration 과 함께 주거나 SDP·native host 가 없으면 거절한다.
  let actionConfiguration=givenActionConfiguration;
  if(sdpActionStartup!==undefined){
    // C4: 이 분기에서 거절되면 방금 만든 nativeHost 를 닫고 실패한다(서버 객체가 없어 close 이벤트로 정리되지 않는다).
    try{
      if(givenActionConfiguration!==undefined||!sdpHostEngine||!nativeHost||!record(sdpActionStartup)||Object.keys(sdpActionStartup).some(key=>!['databasePath','policy'].includes(key)))throw Error('INVALID_SERVER_ACTION_CONFIGURATION');
      const readIdentityVersion=async({signal}={})=>{
        const cap=await openNativeHostOperation(nativeHost,{signal,timeoutMs:10000});
        try{return (await readNativeHostOperation(nativeHost,cap)).identityVersion;}finally{closeNativeHostOperation(cap);}
      };
      actionConfiguration=createSdpActionConfiguration({sdpHost:sdpHostEngine,nativeHost,readIdentityVersion,databasePath:sdpActionStartup.databasePath,policy:sdpActionStartup.policy});
    }catch(error){nativeHost?.close();throw error;}
  }
  if(!Number.isSafeInteger(requestTimeoutMs)||requestTimeoutMs<=0||requestTimeoutMs>120000||resolveAiIdentity!==undefined&&typeof resolveAiIdentity!=='function'
    ||readLearnerSupportIdentity!==undefined&&(typeof readLearnerSupportIdentity!=='function'||types.isProxy(readLearnerSupportIdentity))
    ||appCredentialVault!==undefined&&(typeof appCredentialVault?.load!=='function'||ai!==undefined||typeof aiEnv.ON_AI_APP_KEY==='string'&&aiEnv.ON_AI_APP_KEY.length>0))throw Error('INVALID_SERVER_AI_CONFIGURATION');
  const defaultAi=ai??(appCredentialVault?createVaultOnAiService({appAuthorization:{},...vaultAiConfiguration,enabled:true,vault:appCredentialVault,timeoutMs:aiTimeoutMs}):createOnAiService({env:aiEnv,allowLoopbackHttp:allowLoopbackAiHttp,timeoutMs:aiTimeoutMs}));
  let mappedAi=appCredentialVault?defaultAi:ai;
  const aiSecrets=!appCredentialVault&&typeof aiEnv.ON_AI_APP_KEY==='string'?[aiEnv.ON_AI_APP_KEY]:[];
  const mappedService=()=>mappedAi??(mappedAi=createOnAiService({env:aiEnv,allowLoopbackHttp:allowLoopbackAiHttp,timeoutMs:aiTimeoutMs,appAuthorization:{}}));
  const mode=['connected','demo','disconnected'].includes(engine.evidenceMode)?engine.evidenceMode:'disconnected';
  const connectionConfigKeys=['enabled','fetchImpl','clock','startTimeoutMs','scopeTimeoutMs','finishTimeoutMs','pollIntervalMs','maxFlows','retainMs'];
  if(!Number.isSafeInteger(readTimeoutMs)||readTimeoutMs<=0||readTimeoutMs>120000
    || aiConnectionConfiguration!==undefined&&(!record(aiConnectionConfiguration)||Object.keys(aiConnectionConfiguration).some(key=>!connectionConfigKeys.includes(key))
      || typeof aiConnectionConfiguration.enabled!=='boolean'
      || aiConnectionConfiguration.enabled&&(mode!=='connected'||typeof appCredentialVault?.load!=='function'||typeof appCredentialVault?.persistCredential!=='function'
        || !resolveAiIdentity&&typeof engine.readAiIdentity!=='function')))throw Error('INVALID_SERVER_CONNECTION_CONFIGURATION');
  // Shared identity/binding logic, parameterized by an operation's own readers.
  // The manager never retains the lifetime or reader of an HTTP request.
  function sourceReader({call,bounded,assertAlive}) {
    async function captureSource(){
      const identity=assertData('identity',await call('readIdentity'));
      const source=Object.freeze({sourceSubjectId:identity.user.id,projectId:engine.projectId,sessionId:identity.session.id});
      if(!id(source.projectId)||identity.session.status!=='active')throw engineError('SUBJECT_SCOPE_UNVERIFIED','');
      return {identity,source};
    }
    async function assertCurrent(source){
      const identity=assertData('identity',await call('readIdentity'));
      if(identity.user.id!==source.sourceSubjectId||identity.session.id!==source.sessionId||identity.session.status!=='active'||engine.projectId!==source.projectId)
        throw engineError('SUBJECT_SCOPE_UNVERIFIED','');
    }
    async function readMapping(source){
      if(!resolveAiIdentity&&typeof engine.readAiIdentity!=='function')throw engineError('ON_AI_PROVISIONING_PENDING','');
      let raw;
      try {raw=resolveAiIdentity?await bounded(signal=>resolveAiIdentity(source,{signal})):await call('readAiIdentity',source);}
      catch(error){if(['REQUEST_TIMEOUT','REQUEST_CANCELLED','ENGINE_TIMEOUT'].includes(error?.code))throw error;throw engineError('ON_AI_PROVISIONING_PENDING','');}
      let snapshot;try{snapshot=structuredClone(raw);}catch{throw engineError('ON_AI_PROVISIONING_PENDING','');}
      await assertCurrent(source);
      return assertAiBinding(snapshot,source);
    }
    async function finishMapping(source,binding){
      let after;
      try{after=await readMapping(source);}catch(error){if(error?.code==='ON_AI_PROVISIONING_PENDING')throw engineError('SUBJECT_SCOPE_UNVERIFIED','');throw error;}
      if(AI_BINDING_KEYS.some(key=>after[key]!==binding[key]))throw engineError('SUBJECT_SCOPE_UNVERIFIED','');
      assertAlive();
    }
    return {captureSource,assertCurrent,readMapping,finishMapping};
  }
  const connectionReads=new Set();
  async function readConnectionScope() {
    const controller=new AbortController();connectionReads.add(controller);
    let timer,stop;
    const assertAlive=()=>{if(controller.signal.aborted)throw engineError('ENGINE_TIMEOUT','');};
    const stopped=new Promise((_,reject)=>{
      stop=()=>reject(engineError('ENGINE_TIMEOUT',''));
      controller.signal.addEventListener('abort',stop,{once:true});
      timer=setTimeout(()=>controller.abort(),readTimeoutMs);
    });
    const bounded=async work=>{
      assertAlive();const value=await Promise.race([Promise.resolve().then(()=>{assertAlive();return work(controller.signal);}),stopped]);assertAlive();return value;
    };
    const call=(name,...args)=>bounded(signal=>engineMethod(engine,name)(...args,{signal}));
    try {
      const reader=sourceReader({call,bounded,assertAlive});
      const {source}=await reader.captureSource(),binding=await reader.readMapping(source);
      await reader.finishMapping(source,binding);assertAlive();return binding;
    } finally {clearTimeout(timer);controller.signal.removeEventListener('abort',stop);controller.abort();connectionReads.delete(controller);}
  }
  const connections=nativeHost?createConnectionManager({enabled:true,nativeHost,...(nativeConfiguration.fetchImpl?{fetchImpl:nativeConfiguration.fetchImpl}:{}),...(nativeConfiguration.clock?{clock:nativeConfiguration.clock}: {})}):createConnectionManager(aiConnectionConfiguration?.enabled===true
    ? {...aiConnectionConfiguration,readServerScope:readConnectionScope,vault:appCredentialVault}:{});
  if(aiConnectionConfiguration?.enabled===true&&!connections.available)throw Error('INVALID_SERVER_CONNECTION_CONFIGURATION');
  // Only the local server owner can supply this configuration. The browser
  // cannot choose a DB, policy, engine, resolver, actor or command body.
  const actionRequests=new AsyncLocalStorage();
  const actionContextKeys=['subjectId','projectId','sessionId','identityVersion','appId','audience','accessPolicyId','engineGeneration','sourcePolicyVersion'];
  // C2-R2b: host 가 조치 전용 engine 을 주면 그것만 쓴다(학생 모듈 engine 은 조치에 쓰지 않음). 없으면 기존 동작 그대로.
  const actionEngine=actionConfiguration&&Object.hasOwn(actionConfiguration,'engine')?actionConfiguration.engine:engine;
  const actions=createActionService({engine:actionEngine,databasePath:actionConfiguration?.databasePath,policy:actionConfiguration?.policy,clock:actionConfiguration?.clock,
    resolveContext:typeof actionConfiguration?.resolveContext==='function'?async({signal})=>{
      const request=actionRequests.getStore();if(!request)throw Error('ACTION_SCOPE_UNVERIFIED');
      await request.assertCurrent(request.source);
      const raw=await actionConfiguration.resolveContext({signal});
      const snapshot=structuredClone(raw);
      await request.assertCurrent(request.source);
      if(snapshot?.subjectId!==request.source.sourceSubjectId||snapshot?.projectId!==request.source.projectId||snapshot?.sessionId!==request.source.sessionId)
        throw Object.assign(Error('ACTION_SCOPE_CHANGED'),{code:'ACTION_SCOPE_CHANGED'});
      if(!request.actionContext)request.actionContext=Object.freeze(structuredClone(snapshot));
      return snapshot;
    }:undefined});
  const meta=()=>({mode,checkedAt:clock().toISOString(),starterVersion:'0.1.0'});
  const server=http.createServer(async(req,res)=>{
    // Register before identity/events reads: disconnects during preparation must
    // cancel the later AI operation, even when an adapter ignores cancellation.
    const lifetime=new AbortController();
    const requestStartedAt={wall:Date.now(),monotonic:performance.now()};
    let requestTimedOut=false;
    let nativeAiCheck=false;
    let supportTimer;
    let supportDeadline;
    const disconnect=()=>lifetime.abort();
    res.once('close',disconnect);req.once('aborted',disconnect);
    const requestTimer=setTimeout(()=>{requestTimedOut=true;lifetime.abort();},requestTimeoutMs);
    function assertAlive(){if(supportDeadline&&(Date.now()>=supportDeadline.wall||performance.now()>=supportDeadline.monotonic)){requestTimedOut=true;lifetime.abort();}if(requestTimedOut)throw engineError('REQUEST_TIMEOUT','');if(lifetime.signal.aborted||res.destroyed)throw engineError('REQUEST_CANCELLED','');}
    async function bounded(work){
      assertAlive();let cancel;
      const stopped=new Promise((_,reject)=>{
        cancel=()=>reject(engineError(requestTimedOut?'REQUEST_TIMEOUT':'REQUEST_CANCELLED',''));
        lifetime.signal.addEventListener('abort',cancel,{once:true});
      });
      try {const value=await Promise.race([Promise.resolve().then(()=>{assertAlive();return work(lifetime.signal);}),stopped]);assertAlive();return value;}
      finally {lifetime.signal.removeEventListener('abort',cancel);}
    }
    async function call(name,...args){
      assertAlive();
      let timer,cancel;const controller=new AbortController();
      const stopped=new Promise((_,reject)=>{
        cancel=()=>{controller.abort();reject(engineError(requestTimedOut?'REQUEST_TIMEOUT':'REQUEST_CANCELLED',''));};
        lifetime.signal.addEventListener('abort',cancel,{once:true});
        timer=setTimeout(()=>{controller.abort();reject(engineError('ENGINE_TIMEOUT',''));},readTimeoutMs);
      });
      try{const value=await Promise.race([engineMethod(engine,name)(...args,{signal:controller.signal}),stopped]);assertAlive();return value;}
      finally{clearTimeout(timer);lifetime.signal.removeEventListener('abort',cancel);controller.abort();}
    }
    const requestId=randomUUID();
    let actionRequest=false;
    const send=(status,body)=>{if(res.destroyed||res.writableEnded)return;res.writeHead(status,{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff','x-on-request-id':requestId});res.end(JSON.stringify({...body,meta:meta()}));};
    const {captureSource,assertCurrent,readMapping,finishMapping}=sourceReader({call,bounded,assertAlive});
    const authOptions=(binding)=>({expectedScope:Object.freeze({subjectId:binding.canonicalStudentId,projectId:binding.projectId,appId:'aleph-on',audience:'on-client'}),
      expectedContext:Object.freeze({alephUserId:binding.alephUserId,siteId:binding.siteId,identityVersion:binding.identityVersion}),signal:lifetime.signal});
    try{
      const address=server.address();const port=typeof address==='object'?address.port:0;
      const allowedHosts=[`127.0.0.1:${port}`,`localhost:${port}`];
      const host=req.headers.host;
      if(!allowedHosts.includes(host))throw engineError('HOST_REJECTED','로컬 실행 주소를 확인하세요.',403);
      const url=new URL(req.url,`http://${host}`);
      if(url.search)throw engineError('QUERY_REJECTED','지원하지 않는 요청입니다.',400);
      if(url.pathname.startsWith('/api/')&&req.headers['sec-fetch-site']==='cross-site')throw engineError('ORIGIN_REJECTED','');
      if(req.method==='POST'&&req.headers.origin!==`http://${host}`)throw engineError('ORIGIN_REJECTED','앱 화면에서 다시 요청하세요.',403);
      if(url.pathname.startsWith('/api/native-login/')){
        const kind=url.pathname.slice('/api/native-login/'.length);
        if(req.method!=='POST'||!['start','status','redeem','current','cancel'].includes(kind)){send(404,{ok:false,error:{code:'NOT_FOUND',message:'지원하지 않는 주소입니다.',retryable:false}});return;}
        if(!nativeHost){send(503,{ok:false,error:{code:'NATIVE_HOST_DISABLED',message:'호스트 로그인 연결을 먼저 준비하세요.',retryable:false}});return;}
        if(req.headers.authorization!==undefined||['x-clco-mode','x-clco-work-mode','x-clco-eval-run-id','x-clco-eval-run-nonce','x-clco-capacity-run'].some(name=>req.headers[name]!==undefined))throw engineError('REQUEST_INVALID','');
        if(Number(req.headers['content-length']??0)>8192)throw engineError('REQUEST_TOO_LARGE','',413);
        await bounded(()=>jsonBody(req,[]));
        try{const data=await bounded(signal=>nativeHost.login[kind]({}, {signal}));assertAlive();send(200,{ok:true,data});}
        catch(error){const code=nativePublicError(error);send(code==='NATIVE_HOST_INPUT_INVALID'?400:code==='NATIVE_HOST_EXPIRED'?410:409,{ok:false,error:{code,message:'현재 로그인 연결을 확인하세요. 자동으로 재시도하지 않습니다.',retryable:false}});}
        return;
      }
      if(req.method==='GET'&&files.has(url.pathname)){
        const data=await readFile(resolve(assetsRoot,files.get(url.pathname)));
        const type=url.pathname.endsWith('.webp')?'image/webp':url.pathname.endsWith('.css')?'text/css':url.pathname.endsWith('.js')||url.pathname.endsWith('.mjs')?'text/javascript':'text/html';
        res.writeHead(200,{'content-type':type==='image/webp'?type:`${type}; charset=utf-8`,'cache-control':'no-store','content-security-policy':"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'",'x-content-type-options':'nosniff'});res.end(data);return;
      }
      if(req.method==='POST'&&connectionRoutes.has(url.pathname)){
        const kind=connectionRoutes.get(url.pathname),keys=kind==='start'?[]:['connectionId'];
        // Reject a declared oversized body before the stream iterator can abort
        // the request and turn the intended 413 into a disconnect result.
        if(/^\d+$/.test(req.headers['content-length']??'')&&Number(req.headers['content-length'])>8192)throw engineError('REQUEST_TOO_LARGE','');
        const input=await bounded(()=>jsonBody(req,keys,(_key,value)=>typeof value==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value)));
        const output=await bounded(signal=>connections[kind](input,{signal}));
        send(output.status,output.body);return;
      }
      const gets=new Map([['/api/me',['readIdentity','identity']],['/api/apps',['readApps','apps']],['/api/events',['readEvents','events']],['/api/devices',['readDevices','devices']],['/api/sessions',['readSessions','sessions']]]);
      if(req.method==='GET'&&gets.has(url.pathname)){
        const [name,kind]=gets.get(url.pathname);
        let raw;
        if(mode==='connected'&&kind!=='identity'){
          const identity=assertData('identity',await call('readIdentity'));
          const scope=Object.freeze({subjectId:identity.user.id,projectId:engine.projectId,appId:'aleph-on',audience:'on-client'});
          if(!id(scope.projectId)||identity.session.status!=='active')throw engineError('SUBJECT_SCOPE_UNVERIFIED','');
          raw=await call(name,scope);
          if(!Array.isArray(raw)||raw.some(row=>row.subjectId!==scope.subjectId||row.projectId!==scope.projectId))throw engineError('SUBJECT_SCOPE_UNVERIFIED','');
          const after=assertData('identity',await call('readIdentity'));
          if(after.user.id!==identity.user.id||after.session.id!==identity.session.id||after.session.status!=='active'||engine.projectId!==scope.projectId)throw engineError('SUBJECT_SCOPE_UNVERIFIED','');
        }else raw=await call(name);
        const data=assertData(kind,raw),coverage=collectionCoverage(kind,raw);send(200,{ok:true,data,...(coverage?{coverage}:{})});return;
      }
      if(req.method==='POST'&&url.pathname==='/api/access'){
        const input=await bounded(()=>jsonBody(req,['appId']));let raw;
        if(mode==='connected'){
          const identity=assertData('identity',await call('readIdentity'));
          const scope=Object.freeze({subjectId:identity.user.id,projectId:engine.projectId,appId:'aleph-on',audience:'on-client'});
          if(!id(scope.projectId)||identity.session.status!=='active')throw engineError('SUBJECT_SCOPE_UNVERIFIED','');
          raw=await call('decideAccess',Object.freeze({...input,requestId}),scope);
          if(!record(raw)||raw.subjectId!==scope.subjectId||raw.projectId!==scope.projectId||raw.requestId!==requestId)throw engineError('SUBJECT_SCOPE_UNVERIFIED','');
          const after=assertData('identity',await call('readIdentity'));
          if(after.user.id!==identity.user.id||after.session.id!==identity.session.id||after.session.status!=='active'||engine.projectId!==scope.projectId)throw engineError('SUBJECT_SCOPE_UNVERIFIED','');
        }else raw=await call('decideAccess',input);
        const data=assertData('decision',raw);
        if(data.appId!==input.appId)throw engineError('ENGINE_RESULT_UNVERIFIED','접속 판정 대상이 요청한 업무 앱과 일치하지 않습니다.');
        send(200,{ok:true,data});return;
      }
      const actionRoutes=new Map([['/api/actions/prepare',['prepare',['eventId','actionId']]],['/api/actions/execute',['execute',['requestId','confirmationId']]],['/api/actions/result',['readResult',['requestId']]]]);
      if(req.method==='POST'&&actionRoutes.has(url.pathname)){
        actionRequest=true;
        const [method,keys]=actionRoutes.get(url.pathname);
        const input=await bounded(()=>jsonBody(req,keys,(key,value)=>key==='confirmationId'?confirmation(value):key==='requestId'?uuid(value):id(value)));
        // A confirmation ticket supplies no authority. Capture the current
        // source identity even for a replay; service also rechecks all generations.
        if(!actionConfiguration){const projected=projectAction({ok:false,error:{code:'ACTION_UNSUPPORTED'}},method,input);send(projected.status,projected.body);return;}
        let source;
        try{({source}=await captureSource());}
        catch(error){
          // c2(#978): 이 기기를 스스로 철회한 뒤에는 현재 SDP identity 를 읽을 수 없다. 결과 조회이고 엔진이 본인 영수증 경로를 줄 때만
          // 현재 context 없이 서비스로 넘긴다. 서비스는 소비된 device:revoke 행만 본인 영수증(철회 기기 인증서·native canonical4·host project)으로 읽고,
          // 그 밖의 행·조치는 기존 오류 그대로다. 현재 context 가 없으므로 마지막 9필드 재대조는 하지 않는다(현재 권한을 주장하지 않는 영수증).
          // 철회된 기기의 relay 거절이 어떤 코드로 오는지(SUBJECT_SCOPE_UNVERIFIED·ENGINE_NOT_CONNECTED 등)는 relay 경로마다 다르므로 코드로 고르지 않고,
          // 취소·시간 초과만 제외한다. 권한은 아래 본인 영수증 경로가 스스로 증명해야 하며 여기서 넓어지지 않는다.
          if(method!=='readResult'||typeof actionEngine?.readOwnRevokedReceipt!=='function'||lifetime.signal.aborted
            ||['REQUEST_TIMEOUT','REQUEST_CANCELLED','ENGINE_TIMEOUT'].includes(error?.code))throw error;
          const ownScope={source:null,assertCurrent:async()=>{throw Object.assign(Error('ACTION_SCOPE_UNVERIFIED'),{code:'ACTION_SCOPE_UNVERIFIED'});},actionContext:null};
          let ownRaw;
          try{ownRaw=await actionRequests.run(ownScope,()=>bounded(signal=>actions.readResult(input,{signal})));}
          catch(failure){if(failure?.code==='REQUEST_TIMEOUT'){const projected=projectAction({ok:false,error:{code:'ACTION_TIMEOUT'}},method,input);send(projected.status,projected.body);return;}throw failure;}
          assertAlive();
          const projected=projectAction(structuredClone(ownRaw),'result',input);send(projected.status,projected.body);return;
        }
        let raw;
        const actionRequestScope={source,assertCurrent,actionContext:null};
        try{raw=await actionRequests.run(actionRequestScope,()=>bounded(signal=>actions[method](input,{signal})));}
        catch(error){
          if(error?.code==='REQUEST_TIMEOUT'){
            const projected=projectAction({ok:false,error:{code:'ACTION_TIMEOUT'}},method,input);send(projected.status,projected.body);return;
          }
          throw error;
        }
        const snapshot=structuredClone(raw);
        await assertCurrent(source);assertAlive();
        // The last identity read can yield after the module has committed. Bind
        // the public receipt to the full current authority, not just stable IDs.
        if(snapshot?.ok===true){
          const current=await bounded(async signal=>structuredClone(await actionConfiguration.resolveContext({signal})));
          const captured=actionRequestScope.actionContext;
          if(!captured||!exact(current,actionContextKeys)||actionContextKeys.some(key=>current[key]!==captured[key])){
            const projected=projectAction({ok:false,error:{code:'ACTION_SCOPE_CHANGED'}},method,input);
            send(projected.status,projected.body);return;
          }
        }
        const projected=projectAction(snapshot,method==='readResult'?'result':method,input);
        send(projected.status,projected.body);return;
      }
      if(req.method==='POST'&&url.pathname==='/api/ai/explain'&&nativeHost){
        if(!Number.isSafeInteger(aiTimeoutMs)||aiTimeoutMs<=0||aiTimeoutMs>120000){
          send(503,{ok:false,error:{code:'WB_CLCO_INVALID_LIMIT',message:aiErrorMessages.WB_CLCO_INVALID_LIMIT,retryable:false}});return;
        }
        const routeLimit=Math.min(aiTimeoutMs,requestTimeoutMs);
        supportDeadline={wall:requestStartedAt.wall+routeLimit,monotonic:requestStartedAt.monotonic+routeLimit};
        const remaining=()=>{assertAlive();return Math.max(1,Math.floor(Math.min(supportDeadline.wall-Date.now(),supportDeadline.monotonic-performance.now())));};
        supportTimer=setTimeout(()=>{requestTimedOut=true;lifetime.abort();},remaining());
        let nativeOperation=null,sourceOperation=null;
        const sourceCall=async work=>{try{return await bounded(work);}catch(error){assertAlive();if(['REQUEST_TIMEOUT','REQUEST_CANCELLED'].includes(error?.code))throw error;throw engineError('ON_AI_PROVISIONING_PENDING','');}};
        try{
          if(Number(req.headers['content-length']??0)>8192)throw engineError('REQUEST_TOO_LARGE','',413);
          const input=await bounded(()=>jsonBody(req,['eventId']));
          if(!isOwnedSdpHostEngine(sdpHostEngine))throw engineError('ON_AI_PROVISIONING_PENDING','');
          nativeOperation=await sourceCall(signal=>openNativeHostOperation(nativeHost,{signal,timeoutMs:remaining()}));
          const readHost=async signal=>{if(signal.aborted)throw engineError('REQUEST_CANCELLED','');const current=await sourceCall(()=>readNativeHostOperation(nativeHost,nativeOperation));assertAlive();if(signal.aborted)throw engineError('REQUEST_CANCELLED','');return current;};
          const identity=await readHost(lifetime.signal);
          sourceOperation=await sourceCall(signal=>openSdpIncidentOperation(sdpHostEngine,input,{signal,timeoutMs:remaining()}));
          const initial=assertSdpIncidentOperation(sdpHostEngine,sourceOperation),event=initial.event;
          const sameIdentity=source=>{if(Object.keys(identity).some(key=>source.binding.ai[key]!==identity[key]))throw engineError('ON_AI_PROVISIONING_PENDING','');};
          sameIdentity(initial);
          const recheck=async({signal})=>{
            if(signal.aborted)throw engineError('REQUEST_CANCELLED','');
            const current=await sourceCall(()=>readSdpIncidentOperation(sdpHostEngine,sourceOperation,{signal}));
            const native=await readHost(signal);
            if(Object.keys(identity).some(key=>native[key]!==identity[key])||current.eventHash!==initial.eventHash)throw engineError('ON_AI_PROVISIONING_PENDING','');
            sameIdentity(current);assertAlive();
            try{assertSdpIncidentOperation(sdpHostEngine,sourceOperation);assertNativeHostOperation(nativeHost,nativeOperation);}catch{throw engineError('ON_AI_PROVISIONING_PENDING','');}
            if(current.validUntilMs<=Date.now())throw engineError('ON_AI_PROVISIONING_PENDING','');
            if(signal.aborted)throw engineError('REQUEST_CANCELLED','');assertAlive();
          };
          const service=createVaultOnAiService({enabled:true,vault:createNativeOperationVault(nativeHost,nativeOperation),timeoutMs:remaining(),
            appAuthorization:nativeConfiguration.fetchImpl?{fetchImpl:nativeConfiguration.fetchImpl}:{}});
          const options=Object.freeze({signal:lifetime.signal,
            expectedScope:Object.freeze({subjectId:identity.subjectId,projectId:identity.projectId,appId:'aleph-on',audience:'on-client'}),
            expectedContext:Object.freeze({alephUserId:identity.alephUserId,siteId:identity.siteId,identityVersion:identity.identityVersion}),
            beforeDispatch:recheck,beforePublish:recheck});
          const incident={incidentId:event.id,evidence:event.evidence.map(row=>({id:row.id,summary:row.text})),rules:event.rules.map(row=>({id:row.id,description:row.text})),currentState:event.state,supportedActions:event.supportedActions};
          const raw=await bounded(()=>service.explainIncident(incident,options));
          const capture=(value,keys)=>{
            if(value===null||typeof value!=='object'||types.isProxy(value)||Object.getPrototypeOf(value)!==Object.prototype)throw engineError('SERVICE_UNAVAILABLE','');
            const descriptors=Object.getOwnPropertyDescriptors(value);
            if(Reflect.ownKeys(descriptors).length!==keys.length||keys.some(key=>!Object.hasOwn(descriptors,key)||!Object.hasOwn(descriptors[key],'value')))throw engineError('SERVICE_UNAVAILABLE','');
            return Object.fromEntries(keys.map(key=>[key,descriptors[key].value]));
          };
          if(raw===null||typeof raw!=='object'||types.isProxy(raw))throw engineError('SERVICE_UNAVAILABLE','');
          const ok=Object.getOwnPropertyDescriptor(raw,'ok');if(!ok||!Object.hasOwn(ok,'value')||typeof ok.value!=='boolean')throw engineError('SERVICE_UNAVAILABLE','');
          if(ok.value===false){const output=capture(raw,['ok','error','help']),error=capture(output.error,['code','message']);
            const code=Object.hasOwn(aiErrorMessages,error.code)?error.code:'WB_CLCO_REQUEST_FAILED';assertAlive();send(503,{ok:false,error:{code,message:aiErrorMessages[code],retryable:true}});return;}
          const output=capture(raw,['ok','transportChecked','audienceAuthorization','explanation','authorizationValidUntilMs','help']);
          if(output.transportChecked!==true||output.audienceAuthorization!=='verified'||!Number.isSafeInteger(output.authorizationValidUntilMs)||output.authorizationValidUntilMs<=Date.now())throw engineError('ON_AI_PROVISIONING_PENDING','');
          aiHelp({audienceAuthorization:'verified',help:capture(output.help,['component','code','appCredentialsConfigured','provisioning','automaticRetries','workbenchRequiredAtRuntime'])});
          const explanation=assertExplanation(capture(output.explanation,['summary','evidenceIds','proposals','requiresHumanConfirmation','executed']),event,[]);
          const body=JSON.stringify({ok:true,data:{explanation},meta:meta()});
          assertAlive();let current;
          try{current=assertSdpIncidentOperation(sdpHostEngine,sourceOperation);assertNativeHostOperation(nativeHost,nativeOperation);}catch{throw engineError('ON_AI_PROVISIONING_PENDING','');}
          sameIdentity(current);
          if(current.eventHash!==initial.eventHash||current.validUntilMs<=Date.now()||output.authorizationValidUntilMs<=Date.now())throw engineError('ON_AI_PROVISIONING_PENDING','');
          assertAlive();res.writeHead(200,{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff','x-on-request-id':requestId});res.end(body);return;
        }finally{closeSdpIncidentOperation(sourceOperation);closeNativeHostOperation(nativeOperation);}
      }
      if(req.method==='POST'&&url.pathname==='/api/ai/explain'){
        const {eventId}=await bounded(()=>jsonBody(req,['eventId']));
        const identity=assertData('identity',await call('readIdentity'));
        const expectedScope=Object.freeze({subjectId:identity.user.id,projectId:engine.projectId,appId:'aleph-on',audience:'on-client'});
        if(mode==='connected'&&(!id(expectedScope.projectId)||identity.session.status!=='active'))throw engineError('SUBJECT_SCOPE_UNVERIFIED','');
        const rawEvents=await call('readEvents',expectedScope);
        if(mode==='connected'&&(!Array.isArray(rawEvents)||rawEvents.some(event=>event.subjectId!==expectedScope.subjectId||event.projectId!==expectedScope.projectId)))throw engineError('SUBJECT_SCOPE_UNVERIFIED','');
        const events=assertData('events',rawEvents);const event=events.find(row=>row.id===eventId);
        if(!event)throw engineError('EVENT_NOT_FOUND','본인 기록에서 사건을 찾을 수 없습니다.',404);
        const after=assertData('identity',await call('readIdentity'));
        if(after.user.id!==identity.user.id||after.session.id!==identity.session.id||after.session.status!=='active'||engine.projectId!==expectedScope.projectId)throw engineError('SUBJECT_SCOPE_UNVERIFIED','');
        if(lifetime.signal.aborted||res.destroyed)throw engineError('REQUEST_CANCELLED','');
        const source=Object.freeze({sourceSubjectId:identity.user.id,projectId:expectedScope.projectId,sessionId:identity.session.id});
        const binding=await readMapping(source);
        const output=await bounded(()=>mappedService().explainIncident({incidentId:event.id,evidence:event.evidence.map(e=>({id:e.id,summary:e.text})),rules:event.rules.map(r=>({id:r.id,description:r.text})),currentState:event.state,supportedActions:event.supportedActions},authOptions(binding)));
        await finishMapping(source,binding);
        if(!output?.ok){send(503,{ok:false,error:aiFailure(output)});return;}
        send(200,{ok:true,data:{explanation:assertExplanation(output.explanation,event,aiSecrets)}});return;
      }
      if(req.method==='POST'&&url.pathname==='/api/ai/check'&&nativeHost){
        nativeAiCheck=true; // 이 요청의 바깥 catch 도 같은 retryable 정책을 쓴다(서버가 정한 표시, 요청마다 새로 만든다).
        if(!Number.isSafeInteger(aiTimeoutMs)||aiTimeoutMs<=0||aiTimeoutMs>120000){
          send(503,{ok:false,error:{code:'WB_CLCO_INVALID_LIMIT',message:aiErrorMessages.WB_CLCO_INVALID_LIMIT,retryable:false}});return;
        }
        // One deadline covers the body, original native operation, vault, models and every recheck.
        const routeLimit=Math.min(aiTimeoutMs,requestTimeoutMs);
        supportDeadline={wall:requestStartedAt.wall+routeLimit,monotonic:requestStartedAt.monotonic+routeLimit};
        const remaining=()=>{assertAlive();return Math.max(1,Math.floor(Math.min(supportDeadline.wall-Date.now(),supportDeadline.monotonic-performance.now())));};
        supportTimer=setTimeout(()=>{requestTimedOut=true;lifetime.abort();},remaining());
        let nativeOperation=null;
        try{
          if(Number(req.headers['content-length']??0)>8192)throw engineError('REQUEST_TOO_LARGE','',413);
          await bounded(()=>jsonBody(req,[]));
          try{nativeOperation=await bounded(signal=>openNativeHostOperation(nativeHost,{signal,timeoutMs:remaining()}));}
          catch(error){assertAlive();if(['REQUEST_TIMEOUT','REQUEST_CANCELLED'].includes(error?.code))throw error;throw engineError('ON_AI_PROVISIONING_PENDING','');}
          const readHost=async(signal=lifetime.signal)=>{
            assertAlive();if(signal.aborted)throw engineError('REQUEST_CANCELLED','');
            try{const value=await bounded(()=>readNativeHostOperation(nativeHost,nativeOperation));assertAlive();if(signal.aborted)throw engineError('REQUEST_CANCELLED','');return value;}
            catch(error){assertAlive();if(['REQUEST_TIMEOUT','REQUEST_CANCELLED'].includes(error?.code))throw error;throw engineError('ON_AI_PROVISIONING_PENDING','');}
          };
          const identity=await readHost();
          const currentHost=async({signal})=>{const current=await readHost(signal);if(Object.keys(identity).some(key=>current[key]!==identity[key]))throw engineError('ON_AI_PROVISIONING_PENDING','');};
          const service=createVaultOnAiService({enabled:true,vault:createNativeOperationVault(nativeHost,nativeOperation),timeoutMs:remaining(),
            appAuthorization:nativeConfiguration.fetchImpl?{fetchImpl:nativeConfiguration.fetchImpl}:{}});
          const options=Object.freeze({signal:lifetime.signal,
            expectedScope:Object.freeze({subjectId:identity.subjectId,projectId:identity.projectId,appId:'aleph-on',audience:'on-client'}),
            expectedContext:Object.freeze({alephUserId:identity.alephUserId,siteId:identity.siteId,identityVersion:identity.identityVersion}),
            beforeDispatch:currentHost,beforePublish:currentHost});
          const raw=await bounded(()=>service.checkConnection(options));
          const capture=(value,keys)=>{
            if(value===null||typeof value!=='object'||types.isProxy(value)||Object.getPrototypeOf(value)!==Object.prototype)throw engineError('SERVICE_UNAVAILABLE','');
            const descriptors=Object.getOwnPropertyDescriptors(value);
            if(Reflect.ownKeys(descriptors).length!==keys.length||keys.some(key=>!Object.hasOwn(descriptors,key)||!Object.hasOwn(descriptors[key],'value')))throw engineError('SERVICE_UNAVAILABLE','');
            return Object.fromEntries(keys.map(key=>[key,descriptors[key].value]));
          };
          if(raw===null||typeof raw!=='object'||types.isProxy(raw))throw engineError('SERVICE_UNAVAILABLE','');
          const ok=Object.getOwnPropertyDescriptor(raw,'ok');
          if(!ok||!Object.hasOwn(ok,'value')||typeof ok.value!=='boolean')throw engineError('SERVICE_UNAVAILABLE','');
          if(ok.value===false){
            const output=capture(raw,['ok','error','help']),error=capture(output.error,['code','message']);
            const code=Object.hasOwn(aiErrorMessages,error.code)?error.code:'WB_CLCO_REQUEST_FAILED';
            assertAlive();send(503,{ok:false,error:{code,message:aiErrorMessages[code],retryable:AI_RETRYABLE.has(code)}});return;
          }
          const output=capture(raw,['ok','transportChecked','audienceAuthorization','modelCount','authorizationValidUntilMs','help']);
          if(output.transportChecked!==true||output.audienceAuthorization!=='verified'||!Number.isSafeInteger(output.modelCount)||output.modelCount<1||output.modelCount>64)throw engineError('SERVICE_UNAVAILABLE','');
          const help=aiHelp({audienceAuthorization:'verified',help:capture(output.help,['component','code','appCredentialsConfigured','provisioning','automaticRetries','workbenchRequiredAtRuntime'])});
          if(!Number.isSafeInteger(output.authorizationValidUntilMs)||output.authorizationValidUntilMs<=Date.now())throw engineError('ON_AI_PROVISIONING_PENDING','');
          // Finish metadata/serialization before the last synchronous proof and deadline checks.
          // This proves only app model access; no SDP identity is inferred.
          const body=JSON.stringify({ok:true,data:{transportChecked:true,audienceAuthorization:'verified',modelCount:output.modelCount,help},meta:meta()});
          assertAlive();try{assertNativeHostOperation(nativeHost,nativeOperation);}catch{throw engineError('ON_AI_PROVISIONING_PENDING','');}
          if(output.authorizationValidUntilMs<=Date.now())throw engineError('ON_AI_PROVISIONING_PENDING','');
          assertAlive();
          res.writeHead(200,{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff','x-on-request-id':requestId});res.end(body);return;
        }finally{closeNativeHostOperation(nativeOperation);}
      }
      if(req.method==='POST'&&url.pathname==='/api/ai/check'){
        await bounded(()=>jsonBody(req,[]));
        const {source}=await captureSource();const binding=await readMapping(source);
        const output=await bounded(()=>mappedService().checkConnection(authOptions(binding)));
        await finishMapping(source,binding);
        if(!output?.ok){send(503,{ok:false,error:aiFailure(output)});return;}
        if(output.transportChecked!==true||!['verified','test'].includes(output.audienceAuthorization)||!Number.isSafeInteger(output.modelCount)||output.modelCount<0)
          throw engineError('SERVICE_UNAVAILABLE','');
        send(200,{ok:true,data:{transportChecked:true,audienceAuthorization:output.audienceAuthorization,modelCount:output.modelCount,help:aiHelp(output)}});return;
      }
      if(req.method==='POST'&&url.pathname==='/api/learner-support'){
        if(Number(req.headers['content-length']??0)>8192)throw engineError('REQUEST_TOO_LARGE','',413);
        const input=await bounded(()=>jsonBody(req,['problemKind'],(key,value)=>isLearnerSupportProblemKind(value)));
        const guide=await bounded(signal=>buildLocalLearnerSupportGuide(input,
          readLocalLearnerSupportObservation(mode,mappedAi??defaultAi),{signal}));
        assertAlive();send(200,{ok:true,data:guide});return;
      }
      if(req.method==='POST'&&url.pathname==='/api/learner-support/gpt'){
        if(!Number.isSafeInteger(aiTimeoutMs)||aiTimeoutMs<=0||aiTimeoutMs>120000){
          send(503,{ok:false,error:{code:'WB_CLCO_INVALID_LIMIT',message:aiErrorMessages.WB_CLCO_INVALID_LIMIT,retryable:false}});return;
        }
        // One route deadline includes body, host identity, vault, pre/post auth and transport.
        supportDeadline={wall:Date.now()+aiTimeoutMs,monotonic:performance.now()+aiTimeoutMs};
        supportTimer=setTimeout(()=>{requestTimedOut=true;lifetime.abort();},aiTimeoutMs);
        if(Number(req.headers['content-length']??0)>8192)throw engineError('REQUEST_TOO_LARGE','',413);
        const input=await bounded(()=>jsonBody(req,['problemKind'],(_key,value)=>isLearnerSupportProblemKind(value)));
        let nativeOperation=null;
        if(nativeHost){try{nativeOperation=await bounded(signal=>openNativeHostOperation(nativeHost,{signal,timeoutMs:aiTimeoutMs}));}catch{throw engineError('ON_AI_PROVISIONING_PENDING','');}}
        try{
        const readHost=async(signal=lifetime.signal)=>{
          if(nativeHost){if(signal?.aborted)throw engineError('REQUEST_CANCELLED','');try{const value=await bounded(()=>readNativeHostOperation(nativeHost,nativeOperation));assertAlive();return value;}catch(error){if(['REQUEST_TIMEOUT','REQUEST_CANCELLED'].includes(error?.code))throw error;throw engineError('ON_AI_PROVISIONING_PENDING','');}}
          if(!readLearnerSupportIdentity)throw engineError('ON_AI_PROVISIONING_PENDING','');
          let raw;try{raw=await bounded(()=>readLearnerSupportIdentity({signal}));}
          catch(error){if(['REQUEST_TIMEOUT','REQUEST_CANCELLED'].includes(error?.code))throw error;throw engineError('ON_AI_PROVISIONING_PENDING','');}
          if(raw===null||typeof raw!=='object'||types.isProxy(raw)||![Object.prototype,null].includes(Object.getPrototypeOf(raw)))throw engineError('ON_AI_PROVISIONING_PENDING','');
          const keys=['subjectId','alephUserId','siteId','identityVersion','projectId'],descriptors=Object.getOwnPropertyDescriptors(raw);
          if(Reflect.ownKeys(descriptors).length!==keys.length||keys.some(key=>!Object.hasOwn(descriptors,key)||!Object.hasOwn(descriptors[key],'value')))throw engineError('ON_AI_PROVISIONING_PENDING','');
          const hostIdentity=Object.freeze(Object.fromEntries(keys.map(key=>[key,descriptors[key].value])));
          if(!canonicalSubject(hostIdentity.subjectId)||!opaque(hostIdentity.alephUserId)||!opaque(hostIdentity.siteId)||!opaque(hostIdentity.projectId)
            ||!Number.isSafeInteger(hostIdentity.identityVersion)||hostIdentity.identityVersion<=0)throw engineError('ON_AI_PROVISIONING_PENDING','');
          assertAlive();return hostIdentity;
        };
        const identity=await readHost(),service=nativeHost?createVaultOnAiService({enabled:true,vault:createNativeOperationVault(nativeHost,nativeOperation),timeoutMs:aiTimeoutMs,
          appAuthorization:nativeConfiguration.fetchImpl?{fetchImpl:nativeConfiguration.fetchImpl}:{}}):mappedService();
        const observation=readLocalLearnerSupportObservation(mode,service);
        const prepared=prepareLearnerSupportRequest(input,observation,{signal:lifetime.signal});
        if(service===null||typeof service!=='object'||types.isProxy(service))throw engineError('ON_AI_PROVISIONING_PENDING','');
        const method=Object.getOwnPropertyDescriptor(service,'explainLearningSupport');
        if(!method||!Object.hasOwn(method,'value')||typeof method.value!=='function'||types.isProxy(method.value))throw engineError('ON_AI_PROVISIONING_PENDING','');
        const options={signal:lifetime.signal,expectedScope:Object.freeze({subjectId:identity.subjectId,projectId:identity.projectId,appId:'aleph-on',audience:'on-client'}),
          expectedContext:Object.freeze({alephUserId:identity.alephUserId,siteId:identity.siteId,identityVersion:identity.identityVersion}),
          beforeDispatch:async({signal})=>{const current=await readHost(signal);if(Object.keys(identity).some(key=>current[key]!==identity[key]))throw engineError('ON_AI_PROVISIONING_PENDING','');},
          beforePublish:async({signal})=>{const current=await readHost(signal);if(Object.keys(identity).some(key=>current[key]!==identity[key]))throw engineError('ON_AI_PROVISIONING_PENDING','');}};
        const output=await bounded(()=>Reflect.apply(method.value,service,[input,observation,options]));
        if(output===null||typeof output!=='object'||types.isProxy(output))throw engineError('SERVICE_UNAVAILABLE','');
        const descriptors=Object.getOwnPropertyDescriptors(output);
        if(Reflect.ownKeys(descriptors).some(key=>typeof key!=='string'||!Object.hasOwn(descriptors[key],'value')))throw engineError('SERVICE_UNAVAILABLE','');
        if(!Object.hasOwn(descriptors,'ok')||descriptors.ok.value!==true){
          const error=Object.hasOwn(descriptors,'error')?descriptors.error.value:null;
          if(error===null||typeof error!=='object'||types.isProxy(error)||Object.getPrototypeOf(error)!==Object.prototype)throw engineError('SERVICE_UNAVAILABLE','');
          const errorFields=Object.getOwnPropertyDescriptors(error);
          if(Reflect.ownKeys(errorFields).length!==2||['code','message'].some(key=>!Object.hasOwn(errorFields,key)||!Object.hasOwn(errorFields[key],'value')))throw engineError('SERVICE_UNAVAILABLE','');
          const code=Object.hasOwn(aiErrorMessages,errorFields.code.value)?errorFields.code.value:'WB_CLCO_REQUEST_FAILED';
          send(503,{ok:false,error:{code,message:aiErrorMessages[code],retryable:true}});return;
        }
        const keys=['ok','transportChecked','audienceAuthorization','guide','help','authorizationValidUntilMs'];
        if(Reflect.ownKeys(descriptors).length!==keys.length||keys.some(key=>!Object.hasOwn(descriptors,key))
          ||descriptors.transportChecked.value!==true||descriptors.audienceAuthorization.value!=='verified')throw engineError('SERVICE_UNAVAILABLE','');
        const guide=validateLearnerSupportGuide(prepared,descriptors.guide.value,{signal:lifetime.signal});
        const help=descriptors.help.value;
        if(help===null||typeof help!=='object'||types.isProxy(help)||Object.getPrototypeOf(help)!==Object.prototype)throw engineError('SERVICE_UNAVAILABLE','');
        const helpKeys=['component','code','appCredentialsConfigured','provisioning','automaticRetries','workbenchRequiredAtRuntime'],helpFields=Object.getOwnPropertyDescriptors(help);
        if(Reflect.ownKeys(helpFields).length!==helpKeys.length||helpKeys.some(key=>!Object.hasOwn(helpFields,key)||!Object.hasOwn(helpFields[key],'value')))throw engineError('SERVICE_UNAVAILABLE','');
        aiHelp({audienceAuthorization:'verified',help:Object.fromEntries(helpKeys.map(key=>[key,helpFields[key].value]))});
        if(!Number.isSafeInteger(descriptors.authorizationValidUntilMs.value)||descriptors.authorizationValidUntilMs.value<=Date.now())throw engineError('ON_AI_PROVISIONING_PENDING','');
        assertAlive();if(nativeHost)try{assertNativeHostOperation(nativeHost,nativeOperation);}catch{throw engineError('ON_AI_PROVISIONING_PENDING','');}
        if(descriptors.authorizationValidUntilMs.value<=Date.now())throw engineError('ON_AI_PROVISIONING_PENDING','');
        assertAlive();
        send(200,{ok:true,data:guide});return;
        }finally{closeNativeHostOperation(nativeOperation);}
      }
      if(req.method==='GET'&&url.pathname==='/api/diagnostics'){
        // 자동 호출이나 비밀 원문·전체 설정 출력 없이 로컬 연결 상태만 진단한다.
        const info=(mappedAi??defaultAi).connectionInfo();
        send(200,{ok:true,data:{requestId,component:'on-client',version:'0.1.0',engine:{mode,code:mode==='disconnected'?'ENGINE_NOT_CONNECTED':mode==='demo'?'DEMO_ONLY':'ADAPTER_CONFIGURED'},
          ai:{configured:info?.configured===true,authorized:false,authorizationRequired:true},checkedAt:clock().toISOString(),workbenchRequiredAtRuntime:false}});return;
      }
      if(req.method==='GET'&&url.pathname==='/api/vulnerabilities'){
        const data=await bounded(signal=>scanner.scan({signal}));send(200,{ok:true,data});
        return;
      }
      send(404,{ok:false,error:{code:'NOT_FOUND',message:'지원하지 않는 주소입니다.',retryable:false}});
    }catch(error){
      if(actionRequest&&error?.code==='REQUEST_TIMEOUT'){
        const projected=projectAction({ok:false,error:{code:'ACTION_TIMEOUT'}},'result',{});send(projected.status,projected.body);return;
      }
      const code=Object.hasOwn(safeErrors,error?.code)?error.code:'SERVICE_UNAVAILABLE';
      const [status,message]=safeErrors[code];
      send(status,{ok:false,error:{code,message,retryable:nativeAiCheck?AI_RETRYABLE.has(code):status>=500}});
    }finally{clearTimeout(requestTimer);clearTimeout(supportTimer);res.removeListener('close',disconnect);req.removeListener('aborted',disconnect);lifetime.abort();}
  });
  server.requestTimeout=15000;server.headersTimeout=10000;
  server.once('close',()=>{connections.close();nativeHost?.close();for(const controller of connectionReads)controller.abort();});
  return server;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const args=process.argv.slice(2);let demo=false,actions=false,nativePath,sdpPath,actionsPath;
  for(let i=0;i<args.length;i++){
    if(args[i]==='--demo'){demo=true;continue;}
    // C4: 조치는 --alekov-actions 와 --alekov-actions-config <절대경로> 를 함께 줄 때만 켠다. 각각 한 번만 받는다.
    if(args[i]==='--alekov-actions'&&!actions){actions=true;continue;}
    if(args[i]==='--native-host-config'&&nativePath===undefined&&typeof args[i+1]==='string'&&!args[i+1].startsWith('--')){nativePath=args[++i];continue;}
    if(args[i]==='--sdp-host-config'&&sdpPath===undefined&&typeof args[i+1]==='string'&&!args[i+1].startsWith('--')){sdpPath=args[++i];continue;}
    if(args[i]==='--alekov-actions-config'&&actionsPath===undefined&&typeof args[i+1]==='string'&&!args[i+1].startsWith('--')){actionsPath=args[++i];continue;}
    throw Error('UNKNOWN_ARGUMENT');
  }
  if(demo&&sdpPath!==undefined)throw Error('SDP_HOST_DEMO_CONFLICT');
  // 자원(native context·SDP host)을 만들기 전에 조합을 모두 거절한다: 한쪽만 준 경우, demo, native·SDP 설정 누락.
  if(actions!==(actionsPath!==undefined))throw Error('ACTION_STARTUP_INCOMPLETE');
  if(actions&&(demo||nativePath===undefined||sdpPath===undefined))throw Error('ACTION_STARTUP_CONFLICT');
  // 조치 설정은 파일 읽기만 하므로 native helper(registry·ACL 검사)를 부르기 전에 먼저 닫힌 schema 로 확인한다.
  const actionStartup=actions?readActionStartupConfiguration(actionsPath):null;
  const nativeHostConfiguration=nativePath===undefined?undefined:await readNativeHostConfiguration(nativePath);
  const port=Number(process.env.ON_PORT??5189);
  if(!Number.isInteger(port)||port<1024||port>65535)throw Error('INVALID_PORT');
  const sdpHost=sdpPath===undefined?null:createSdpHostEngine(await readSdpHostConfiguration(sdpPath,{projectRoot:resolve(root)}));
  let server;
  try{
    // 학생 모듈에는 본인 범위의 조회·판정 기능만 전달한다. 비밀·설정·종료·조치 기능은 호스트에 둔다(C4 도 이 목록을 늘리지 않는다).
    const hostCapability=sdpHost?Object.freeze({projectId:sdpHost.projectId,
      readIdentity:sdpHost.readIdentity.bind(sdpHost),readApps:sdpHost.readApps.bind(sdpHost),decideAccess:sdpHost.decideAccess.bind(sdpHost),
      readEvents:sdpHost.readEvents.bind(sdpHost),readDevices:sdpHost.readDevices.bind(sdpHost),readSessions:sdpHost.readSessions.bind(sdpHost)}):undefined;
    const engine=demo?demoEngine():await loadEngine(process.env.ON_ENGINE_ADAPTER??(sdpHost?resolve(root,'student/engine-adapter.mjs'):undefined),{hostCapability});
    let approvedPublicPackages=[];
    if(process.env.ON_APPROVED_PUBLIC_PACKAGES){try{approvedPublicPackages=JSON.parse(process.env.ON_APPROVED_PUBLIC_PACKAGES);}catch{throw Error('INVALID_PUBLIC_PACKAGE_LIST');}if(!Array.isArray(approvedPublicPackages))throw Error('INVALID_PUBLIC_PACKAGE_LIST');}
    const scanner=createProjectScanner({projectDirectory:process.env.ON_PROJECT_DIRECTORY,approvedPublicPackages});
    // 같은 createOnServer 안의 nativeHost 와 같은 owned sdpHost 만 조치 설정에 쓰인다(constructor 215–224행).
    server=createOnServer({engine,scanner,...(nativeHostConfiguration?{nativeHostConfiguration}:{}),...(sdpHost?{sdpHostEngine:sdpHost}:{}),
      ...(actionStartup?{sdpActionStartup:actionStartup.sdpActionStartup}:{})});
  }catch(error){sdpHost?.close();throw error;}
  if(sdpHost){server.once('close',()=>sdpHost.close());server.once('error',()=>sdpHost.close());}
  server.listen(port,'127.0.0.1',()=>console.log(`케셰브 ${demo?'예제':'연결 확인'}: http://127.0.0.1:${port}`));
}
