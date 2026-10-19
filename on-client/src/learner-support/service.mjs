// Local guidance only. No AI transport, credential, engine operation or file access.
import {types} from 'node:util';

const kinds = Object.freeze(['app-start', 'engine-connection', 'ai-access', 'response-delay', 'diagnostic-copy']);
const modes = Object.freeze({disconnected:'ENGINE_NOT_CONNECTED', demo:'DEMO_ONLY', connected:'ADAPTER_CONFIGURED'});
const abortRead = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted').get;
const fail = code => {throw Object.assign(new Error(code), {code});};
function capture(value, keys, code, optional = []) {
  if(value === null || typeof value !== 'object' || types.isProxy(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value)))fail(code);
  const descriptors = Object.getOwnPropertyDescriptors(value), names = Reflect.ownKeys(descriptors);
  if(names.length < keys.length || names.length > keys.length + optional.length
    || names.some(key => typeof key !== 'string' || !keys.includes(key) && !optional.includes(key)
      || !Object.hasOwn(descriptors[key], 'value'))
    || keys.some(key => !Object.hasOwn(descriptors, key)))fail(code);
  return Object.fromEntries(keys.map(key => [key, descriptors[key].value]));
}
function freeze(value) {
  if(value && typeof value === 'object') {for(const child of Object.values(value))freeze(child);Object.freeze(value);}
  return value;
}
function alive(options) {
  const {signal} = capture(options, ['signal'], 'LEARNER_SUPPORT_INPUT_INVALID');
  if(signal === undefined)return;
  if(signal === null || typeof signal !== 'object' || types.isProxy(signal))fail('LEARNER_SUPPORT_INPUT_INVALID');
  let aborted;
  try {aborted = Reflect.apply(abortRead, signal, []);}catch {fail('LEARNER_SUPPORT_INPUT_INVALID');}
  if(aborted)fail('REQUEST_CANCELLED');
}
const actions = freeze({
  'check-app-window':'앱 화면이 열려 있는지 확인하세요. 앱이 실행되지 않으면 시작 안내를 확인하세요.',
  'check-start-guide':'제공된 시작 안내에서 작업 폴더와 실행 순서를 확인하세요. 이 안내는 학생 코드를 수정하지 않습니다.',
  'read-help-info':'도움정보에서 실행 모드와 연결 코드를 확인하세요. 설정됨 표시는 연결 성공을 뜻하지 않습니다.',
  'check-engine-guide':'기존 서버·에이전트 연결 안내와 현재 실행 모드를 확인하세요.',
  'check-example-mode':'예제 모드의 결과는 실제 계정·서버 연결의 증거가 아닙니다.',
  'check-ai-approval':'AI 연결 안내에서 현재 계정과 앱 이용 승인 상태를 확인하세요. 열쇠나 비밀번호를 보내지 마세요.',
  'wait-and-manual-check':'응답 지연 표시를 확인하고 진행 중인 요청이 끝난 뒤 직접 다시 확인하세요. 자동 재시도하지 않습니다.',
  'review-help-before-copy':'도움정보 내용을 직접 확인한 뒤 필요한 항목만 복사하세요. 복사만으로 외부에 전송되지는 않습니다.',
  'contact-instructor':'계속 해결되지 않으면 문제 유형과 화면의 정제된 오류 코드만 담당자에게 알려 주세요. 원문 로그·학생 코드·개인정보·열쇠는 보내지 마세요.',
});
const guides = freeze({
  'app-start':{code:'LOCAL_APP_START_GUIDE', summary:'현재 안내는 실행 중인 앱 서버에서 제공했습니다. 시작 과정이 막힌 부분을 순서대로 확인하세요.', steps:['check-app-window','check-start-guide','contact-instructor']},
  'engine-connection':{code:'LOCAL_ENGINE_GUIDE', summary:'서버 설정과 실제 연결 여부를 구분해 확인하세요.', steps:['read-help-info','check-engine-guide','contact-instructor']},
  'ai-access':{code:'LOCAL_AI_ACCESS_GUIDE', summary:'AI 설정 여부만으로 이용 승인이나 모델 연결 성공을 판단할 수 없습니다.', steps:['read-help-info','check-ai-approval','contact-instructor']},
  'response-delay':{code:'LOCAL_RESPONSE_DELAY_GUIDE', summary:'지연이 발생한 요청의 상태를 확인하세요. 이 안내에서는 서버 응답이나 모델 연결을 시험하지 않습니다.', steps:['read-help-info','wait-and-manual-check','contact-instructor']},
  'diagnostic-copy':{code:'LOCAL_DIAGNOSTIC_COPY_GUIDE', summary:'도움정보는 직접 확인하고 복사할 수 있습니다. 이 요청에서는 클립보드를 읽거나 외부로 전송하지 않습니다.', steps:['read-help-info','review-help-before-copy','contact-instructor']},
});
export function isLearnerSupportProblemKind(value) {
  return typeof value === 'string' && kinds.includes(value);
}
export function readLocalLearnerSupportObservation(mode, aiService) {
  if(typeof mode !== 'string' || !Object.hasOwn(modes, mode))fail('LEARNER_SUPPORT_OBSERVATION_INVALID');
  if(aiService === null || typeof aiService !== 'object' || types.isProxy(aiService))fail('LEARNER_SUPPORT_OBSERVATION_INVALID');
  const method = Object.getOwnPropertyDescriptor(aiService, 'connectionInfo');
  if(!method || !Object.hasOwn(method, 'value') || typeof method.value !== 'function' || types.isProxy(method.value))fail('LEARNER_SUPPORT_OBSERVATION_INVALID');
  let info;
  // Optional help is accepted only as an own data field, then discarded without reading its value.
  try {info = capture(Reflect.apply(method.value, aiService, []), ['configured','authorized','authorizationRequired'], 'LEARNER_SUPPORT_OBSERVATION_INVALID', ['help']);}
  catch {fail('LEARNER_SUPPORT_OBSERVATION_INVALID');}
  if(typeof info.configured !== 'boolean' || info.authorized !== false || info.authorizationRequired !== true)fail('LEARNER_SUPPORT_OBSERVATION_INVALID');
  return freeze({engine:{mode, code:modes[mode]}, ai:{configured:info.configured, authorized:false}});
}
export function buildLocalLearnerSupportGuide(input, observation, options = {signal:undefined}) {
  alive(options);
  const request = capture(input, ['problemKind'], 'LEARNER_SUPPORT_INPUT_INVALID');
  if(!isLearnerSupportProblemKind(request.problemKind))fail('LEARNER_SUPPORT_INPUT_INVALID');
  const observed = capture(observation, ['engine','ai'], 'LEARNER_SUPPORT_OBSERVATION_INVALID');
  const engine = capture(observed.engine, ['mode','code'], 'LEARNER_SUPPORT_OBSERVATION_INVALID');
  const ai = capture(observed.ai, ['configured','authorized'], 'LEARNER_SUPPORT_OBSERVATION_INVALID');
  if(typeof engine.mode !== 'string' || !Object.hasOwn(modes, engine.mode) || engine.code !== modes[engine.mode]
    || typeof ai.configured !== 'boolean' || ai.authorized !== false)fail('LEARNER_SUPPORT_OBSERVATION_INVALID');
  const guide = guides[request.problemKind], stepIds = [...guide.steps];
  if(engine.mode === 'demo' && request.problemKind === 'engine-connection')stepIds.splice(1, 0, 'check-example-mode');
  const result = freeze({source:'local-guide', code:guide.code, problemKind:request.problemKind,
    observations:{engine:{...engine}, ai:{...ai}}, summary:guide.summary,
    steps:stepIds.map((actionId, index) => ({order:index+1, actionId, text:actions[actionId]})),
    contact:{actionId:'contact-instructor', text:actions['contact-instructor']},
    gpt:{status:'disabled', reason:'LEARNER_SUPPORT_AUTHORIZATION_PENDING'},
    limits:{appNotRunning:'use-start-guide', authorization:'not-verified', connection:'not-tested'}});
  alive(options);
  return result;
}
