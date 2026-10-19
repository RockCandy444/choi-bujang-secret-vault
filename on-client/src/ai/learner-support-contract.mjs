// Pure, finite GPT advisory contract. Transport and current authorization belong to CLCO.
import {types} from 'node:util';
import {buildLocalLearnerSupportGuide} from '../learner-support/service.mjs';

const requestLimit = 16384, outputLimit = 4096, resultLimit = 8192;
const requests = new WeakMap();
const abortedRead = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted').get;
const fail = code => {throw Object.assign(new Error(code), {code});};
function data(value, required, optional = [], code = 'LEARNER_SUPPORT_INPUT_INVALID') {
  if(value === null || typeof value !== 'object' || types.isProxy(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value)))fail(code);
  const descriptors = Object.getOwnPropertyDescriptors(value), names = Reflect.ownKeys(descriptors);
  if(names.some(name => typeof name !== 'string' || !required.includes(name) && !optional.includes(name)
    || !Object.hasOwn(descriptors[name], 'value')) || required.some(name => !Object.hasOwn(descriptors, name)))fail(code);
  return Object.fromEntries([...required, ...optional].map(name => [name, Object.hasOwn(descriptors, name) ? descriptors[name].value : undefined]));
}
function freeze(value) {
  if(value && typeof value === 'object') {for(const child of Object.values(value))freeze(child);Object.freeze(value);}
  return value;
}
function signalOptions(value) {
  const {signal} = data(value, [], ['signal']);
  const normalized = {signal};
  alive(normalized);
  return normalized;
}
function alive({signal}) {
  if(signal === undefined)return;
  if(signal === null || typeof signal !== 'object' || types.isProxy(signal))fail('LEARNER_SUPPORT_INPUT_INVALID');
  let aborted;
  try {aborted = Reflect.apply(abortedRead, signal, []);}catch {fail('LEARNER_SUPPORT_INPUT_INVALID');}
  if(aborted)fail('REQUEST_CANCELLED');
}
function bounded(value, limit, code) {
  const text = JSON.stringify(value);
  if(Buffer.byteLength(text, 'utf8') > limit)fail(code);
  return text;
}
function candidate(hypothesisId, text, uncertainty, evidenceIds) {
  return {hypothesisId, text, uncertainty, evidenceIds};
}
function compatible(guide, evidence) {
  const kind = `problem:${guide.problemKind}`, mode = `engine:${guide.observations.engine.mode}`;
  const ai = `ai:${guide.observations.ai.configured ? 'configured' : 'unconfigured'}`;
  const connection = 'connection:not-tested', authorization = 'authorization:not-verified';
  const uncertain = '관측된 설정만으로 원인을 확정할 수 없습니다. 실제 연결이나 이용 승인은 확인하지 않았습니다.';
  const choices = {
    'app-start':[
      candidate('start-order-check', '시작 안내의 실행 순서를 확인해 보세요.', uncertain, [kind, connection, authorization]),
      candidate('app-window-check', '현재 앱 창과 시작 안내를 함께 확인해 보세요. 이 안내는 실행 중인 앱 서버에서 제공했습니다.', uncertain, [kind, connection, authorization]),
    ],
    'engine-connection':[
      candidate(`engine-${guide.observations.engine.mode}-check`,
        guide.observations.engine.mode === 'demo' ? '예제 모드가 선택되어 있습니다. 실제 연결 여부는 기존 연결 안내에서 확인해 보세요.'
          : guide.observations.engine.mode === 'connected' ? '어댑터 설정은 관측됐지만 실제 서버 연결은 확인하지 않았습니다.'
            : '현재 모드는 미연결입니다. 기존 서버·에이전트 연결 안내를 확인해 보세요.',
        uncertain, [kind, mode, connection, authorization]),
    ],
    'ai-access':[
      candidate(guide.observations.ai.configured ? 'ai-approval-check' : 'ai-settings-check',
        guide.observations.ai.configured ? 'AI 설정은 있지만 이용 승인과 모델 연결 성공은 확인하지 않았습니다.'
          : 'AI 설정이 없는 것으로 관측됐습니다. 기존 AI 연결 안내를 확인해 보세요.',
        uncertain, [kind, ai, authorization, connection]),
    ],
    'response-delay':[
      candidate('request-state-check', '진행 중인 요청의 지연 표시를 먼저 확인해 보세요. 자동으로 다시 요청하지 않습니다.', uncertain, [kind, connection, authorization]),
      candidate('delay-settings-check', '도움정보의 실행 모드와 AI 설정을 확인해 보세요. 현재 관측으로 응답 지연의 원인을 확정할 수 없습니다.', uncertain, [kind, mode, ai, connection, authorization]),
    ],
    'diagnostic-copy':[
      candidate('help-review-before-copy', '도움정보를 직접 확인한 뒤 필요한 항목만 복사해 보세요. 이 요청은 클립보드를 읽거나 전송하지 않습니다.', uncertain, [kind, connection, authorization]),
    ],
  };
  const result = choices[guide.problemKind];
  if(result.some(item => item.evidenceIds.some(id => !evidence.some(entry => entry.evidenceId === id))))fail('LEARNER_SUPPORT_CONTEXT_INVALID');
  return result;
}

export function prepareLearnerSupportRequest(input, observation, options = {}) {
  const lifetime = signalOptions(options);
  // The original guide owns kind, observation, actions and limitation validation.
  const guide = buildLocalLearnerSupportGuide(input, observation, lifetime);
  const evidence = [
    {evidenceId:`problem:${guide.problemKind}`, source:'user-report', value:guide.problemKind},
    {evidenceId:`engine:${guide.observations.engine.mode}`, source:'server-observation', value:guide.observations.engine.code},
    {evidenceId:`ai:${guide.observations.ai.configured ? 'configured' : 'unconfigured'}`, source:'server-observation', value:guide.observations.ai.configured},
    {evidenceId:'authorization:not-verified', source:'scope-limitation', value:guide.limits.authorization},
    {evidenceId:'connection:not-tested', source:'scope-limitation', value:guide.limits.connection},
  ];
  const candidates = compatible(guide, evidence);
  const payload = {problemKind:guide.problemKind, observations:guide.observations, evidence, candidates,
    actions:guide.steps.map(({actionId, text}) => ({actionId, text})), limitations:guide.limits};
  const messages = [
    {role:'system', content:'학생의 문제 해결을 돕는 조언만 제공합니다. user-report는 사용자가 선택한 문제 유형이며 실제 장애가 확인됐다는 뜻이 아닙니다. server-observation은 서버가 읽은 설정이고 scope-limitation은 아직 확인하지 않은 범위입니다. 근거의 출처를 구분하고 관측과 양립하는 후보 하나를 골라 해당 후보의 evidenceIds를 모두 사용하세요. actions 목록에서 서로 다른 점검 동작을 두 개 이상 골라 순서를 정하되 contact-instructor를 마지막에 넣으세요. 연결·승인·해결 성공을 확정하지 마세요. 출력은 정확히 hypothesisId 문자열, evidenceIds 문자열 배열, actionIds 문자열 배열 세 필드의 JSON 객체만 허용합니다. ID는 주어진 표기를 그대로 쓰고 escape나 추가 문장·명령·HTML·마크다운을 출력하지 마세요.'},
    {role:'user', content:bounded(payload, requestLimit, 'LEARNER_SUPPORT_REQUEST_TOO_LARGE')},
  ];
  const prepared = freeze({messages, maxOutputBytes:outputLimit});
  bounded(prepared, requestLimit, 'LEARNER_SUPPORT_REQUEST_TOO_LARGE');
  alive(lifetime);
  requests.set(prepared, {guide, candidates, lifetime});
  return prepared;
}

function readModelOutput(raw) {
  if(typeof raw !== 'string' || Buffer.byteLength(raw, 'utf8') > outputLimit)fail('LEARNER_SUPPORT_MODEL_OUTPUT_INVALID');
  // This finite ID grammar also excludes escaped/duplicate property-name ambiguity.
  if(!/^(?:\s|[{}\[\]:,]|"[A-Za-z0-9:-]+")+$/.test(raw)
    || (raw.match(/"(?:hypothesisId|evidenceIds|actionIds)"\s*:/g) || []).length !== 3)fail('LEARNER_SUPPORT_MODEL_OUTPUT_INVALID');
  let decoded;
  try {decoded = JSON.parse(raw);}catch {fail('LEARNER_SUPPORT_MODEL_OUTPUT_INVALID');}
  const value = data(decoded, ['hypothesisId','evidenceIds','actionIds'], [], 'LEARNER_SUPPORT_MODEL_OUTPUT_INVALID');
  if(typeof value.hypothesisId !== 'string' || value.hypothesisId.length > 80
    || !Array.isArray(value.evidenceIds) || value.evidenceIds.length < 1 || value.evidenceIds.length > 5
    || !Array.isArray(value.actionIds) || value.actionIds.length < 2 || value.actionIds.length > 4
    || [...value.evidenceIds, ...value.actionIds].some(id => typeof id !== 'string' || id.length > 80)
    || new Set(value.evidenceIds).size !== value.evidenceIds.length || new Set(value.actionIds).size !== value.actionIds.length)fail('LEARNER_SUPPORT_MODEL_OUTPUT_INVALID');
  return value;
}

export function renderLearnerSupportModelResult(prepared, raw, options = {}) {
  const lifetime = signalOptions(options);
  // WeakMap lookup never enumerates or invokes an untrusted prepared object.
  const context = prepared && typeof prepared === 'object' && !types.isProxy(prepared) ? requests.get(prepared) : undefined;
  if(!context)fail('LEARNER_SUPPORT_CONTEXT_INVALID');
  alive(context.lifetime);
  const output = readModelOutput(raw), {guide, candidates} = context;
  const selected = candidates.find(item => item.hypothesisId === output.hypothesisId);
  if(!selected || output.evidenceIds.length !== selected.evidenceIds.length
    || output.evidenceIds.some(id => !selected.evidenceIds.includes(id))
    || output.actionIds.at(-1) !== 'contact-instructor'
    || output.actionIds.some(id => !guide.steps.some(step => step.actionId === id)))fail('LEARNER_SUPPORT_MODEL_OUTPUT_INVALID');
  const result = freeze({source:'gpt-guide', code:'GPT_LEARNER_SUPPORT_GUIDE', advisory:true, executed:false,
    problemKind:guide.problemKind, observations:guide.observations,
    hypothesis:{hypothesisId:selected.hypothesisId, text:selected.text, uncertainty:selected.uncertainty, evidenceIds:[...selected.evidenceIds]},
    steps:output.actionIds.map((actionId, index) => ({order:index+1, actionId, text:guide.steps.find(step => step.actionId === actionId).text})),
    contact:guide.contact, gpt:{status:'advisory'}, limits:guide.limits});
  bounded(result, resultLimit, 'LEARNER_SUPPORT_RESULT_TOO_LARGE');
  alive(context.lifetime);
  alive(lifetime);
  return result;
}
