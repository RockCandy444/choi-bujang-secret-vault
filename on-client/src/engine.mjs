import {pathToFileURL} from 'node:url';
import {resolve} from 'node:path';

export const engineError = (code, message, status=503) => Object.assign(new Error(code), {code,safeMessage:message,status});
const disconnected = () => { throw engineError('ENGINE_NOT_CONNECTED','기존 서버·에이전트의 연결을 확인할 수 없습니다. 연결 어댑터를 먼저 확인하세요.'); };
export async function loadEngine(path, {hostCapability} = {}) {
  if (!path) return {evidenceMode:'disconnected'};
  // 이 경로는 서버 실행자의 설정이다. 브라우저 요청에서 모듈을 선택하지 않는다.
  const module = await import(pathToFileURL(resolve(path)).href);
  const engine = hostCapability === undefined ? module.default
    : typeof module.createEngine === 'function' ? await module.createEngine(hostCapability) : null;
  if (!engine || typeof engine !== 'object' || !['connected','disconnected'].includes(engine.evidenceMode)) throw engineError('ENGINE_ADAPTER_INVALID','기존 서버 연결 어댑터의 형식을 확인하세요.');
  return engine;
}
export function engineMethod(engine, name) {
  return typeof engine?.[name] === 'function' ? engine[name].bind(engine) : disconnected;
}
export function demoEngine() {
  const identity={user:{id:'practice-user',label:'연습 사용자'},device:{id:'practice-pc',label:'연습 PC',status:'unknown'},session:{id:'practice-session',status:'active'}};
  const apps=[{id:'library',name:'학습 자료실'},{id:'repository',name:'개발 저장소'},{id:'approval',name:'확인할 업무 앱'}];
  const events=[{id:'event-01',kind:'access',at:'2026-10-12T03:00:00.000Z',appId:'repository',summary:'개발 저장소 접속이 제한됐습니다.',evidence:[{id:'e-01',text:'서버 예제 판정: deny'}],rules:[{id:'rule-01',text:'기기 상태 확인이 필요합니다.'}],state:{access:'denied',session:'active',device:'unknown'},supportedActions:[]}];
  return {
    evidenceMode:'demo',
    projectId:'practice-project',
    readIdentity:async()=>structuredClone(identity), readApps:async()=>structuredClone(apps),
    readEvents:async()=>structuredClone(events),
    readDevices:async()=>[structuredClone(identity.device)],readSessions:async()=>[structuredClone(identity.session)],
    decideAccess:async({appId})=>{
      if(!apps.some(app=>app.id===appId))throw engineError('APP_NOT_FOUND','업무 앱을 찾을 수 없습니다.',404);
      return {appId,decision:appId==='library'?'allow':appId==='repository'?'deny':'challenge',reason:appId==='library'?'예제 정책이 접속을 허용했습니다.':appId==='repository'?'기기 상태를 먼저 확인해야 합니다.':'추가 확인이 필요합니다.',checkedAt:new Date().toISOString()};
    },
  };
}
