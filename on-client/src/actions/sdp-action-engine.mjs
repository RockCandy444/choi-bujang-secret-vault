import {types} from 'node:util';
import {isOwnedSdpHostEngine} from '../engine/sdp-host.mjs';
import {isNativeHostContext} from '../connection/native-context.mjs';

// C2-R2b SOURCE (2026-10-15, 운영 비활성): host 소유 조치 engine 과 context resolver.
// - 학생 모듈 engine·hostCapability 를 쓰지 않는다. 서버를 띄우는 host 코드만 이 함수로 actionConfiguration 을 만든다.
// - service.mjs 의 engine 계약(readEvents·authorizeAction·executeAction·readActionResult)과 소비된 operation 영수증(readActionReceipt)을
//   sdp-host 의 조치 전용 메서드로 잇는다. 공개 readEvents(9필드)는 쓰지 않는다.
// - 조치 context 9필드: relay 검증 부분(subject·project·session·accessPolicyId·engineGeneration·sourcePolicyVersion) +
//   host 가 native 결속에서 읽은 identityVersion. identityVersion 은 조치 권한을 넓히는 데 쓰지 않고 요청 사이 변화만 막는다.
// - c1(#968): 자기 기기 철회 뒤 본인 영수증은 nativeHost(서버 host 가 만든 native host context)를 줄 때만 켠다.
//   sdp-host.readOwnRevokedReceipt 가 영수증 전용 SDP listener + genuine host native ticket 으로 읽는다. 없으면 기존처럼 unknown 이다.
export function createSdpActionConfiguration({sdpHost,readIdentityVersion,databasePath,policy,clock,nativeHost}={}){
  if(!isOwnedSdpHostEngine(sdpHost)||typeof readIdentityVersion!=='function'||types.isProxy(readIdentityVersion)
    ||nativeHost!==undefined&&!isNativeHostContext(nativeHost))throw Error('INVALID_SDP_ACTION_CONFIGURATION');
  const engine=Object.freeze({evidenceMode:'connected',
    readEvents:(scope,call)=>sdpHost.readActionEvents(scope,call),
    authorizeAction:(command,scope,call)=>sdpHost.authorizeAction(command,scope,call),
    executeAction:(command,scope,call)=>sdpHost.executeAction(command,scope,call),
    readActionResult:(input,scope,call)=>sdpHost.readActionReceipt(input,scope,call),
    readActionReceipt:(input,scope,call)=>sdpHost.readActionReceipt(input,scope,call),
    ...(nativeHost?{readOwnRevokedReceipt:(input,scope,call)=>sdpHost.readOwnRevokedReceipt(input,scope,call,nativeHost)}:{})});
  async function resolveContext({signal}={}){
    const relay=await sdpHost.readActionContext({signal});
    const identityVersion=await readIdentityVersion({signal});
    if(!Number.isSafeInteger(identityVersion)||identityVersion<=0)throw Object.assign(Error('ACTION_SCOPE_UNVERIFIED'),{code:'ACTION_SCOPE_UNVERIFIED'});
    return {subjectId:relay.subjectId,projectId:relay.projectId,sessionId:relay.sessionId,identityVersion,appId:'aleph-on',audience:'on-client',
      accessPolicyId:relay.accessPolicyId,engineGeneration:relay.engineGeneration,sourcePolicyVersion:relay.sourcePolicyVersion};
  }
  return Object.freeze({engine,resolveContext,databasePath,policy,...(clock?{clock}:{})});
}
