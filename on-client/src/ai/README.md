# 케셰브 앱의 서버 AI 연결

앱은 Workbench의 공통 `createClcoClient`를 바탕으로 만든 서버 HTTP 파생 모듈로 알레프게이트에 연결합니다. 완성한 앱은 Workbench를 실행해 두지 않아도 연결 코드를 사용할 수 있습니다. 사건 설명과 조치 제안, 유한한 학습지원 조언을 요청하며, 이 모듈에는 접속 허용·거부·세션 회수의 집행 코드가 없습니다.

## 현재 확인 범위

2026-10-12 로컬 HTTP에서 앱 authorization 확인과 Workbench 공통 transport의 모델 조회·설명 순서를 검증했습니다. 기본 애플리케이션은 실제 canonical 계정 매핑과 서버 verifier가 없으므로 열쇠만 설정해도 `ON_AI_PROVISIONING_PENDING`을 반환합니다. 실제 게이트의 HTTP·자격·공동 예산 통합은 별도 구현 중이며 운영 발급·원격 모델 호출은 미실행입니다. Workbench 열쇠로 `/v1/models`가 응답하더라도 학생 앱 이용 권한으로 인정하지 않습니다.

`app-authorization.mjs`의 실제 HTTP helper가 같은 앱 열쇠·현재 canonical 계정·프로젝트·권한·기간·모델 정책을 검증한 operation은 `audienceAuthorization:'verified'`로 구분합니다. 임의 callback이 만든 `mode:'verified'` object는 거절합니다. 현재 운영 신원 공급자는 연결하지 않았으며 이 성공 경로는 로컬 HTTP fixture로 검증했습니다. 학생 설정과 오류 안내는 `../../docs/AI_SETUP_GUIDE.md`를 읽으세요. 개발용 상세 계약은 소스 저장소의 `docs/AI_AUTHORIZATION_CLIENT.md`에 있습니다.

명시적인 localhost test callback은 기존 합성 시험용으로 유지합니다. 이때 응답은 `transportChecked:true`, `audienceAuthorization:'test'`, `help.code:'ON_AI_TEST_TRANSPORT_ONLY'`이고 `help.provisioning`은 `pending`입니다. 운영 연결 성공이나 실제 학생 수용으로 해석하지 않습니다.

원본 공통 모듈에는 공개 라이선스 명시가 없습니다. 오너 요청에 따른 내부 개발 재사용만 반영했으며 학생 배포 패키지의 라이선스 검토는 남아 있습니다. 자세한 출처는 `../../vendor/NOTICE.md`에 있습니다.

## 서버 설정

- `ON_AI_BASE_URL`: 담당자가 제공한 HTTPS `/api/apps/aleph-on/v1` 주소
- `ON_AI_APP_KEY`: 학생 앱 전용 열쇠. Workbench에 저장한 열쇠나 공급사 원본 키를 복사하지 않습니다.
- `ON_AI_MODEL`: 담당자가 허용하고 `/v1/models`에서 확인한 모델 ID

설정은 앱 서버에서만 읽습니다. 브라우저 번들, 학생 제출물, 소스 관리, 로그에 열쇠를 넣지 않습니다. 권한이 확인된 localhost 시험에서 `ON_AI_MODEL`이 없으면 모델 연결 점검만 가능하고 설명 요청은 `MODEL_NOT_CONFIGURED`로 안내합니다. 임의의 모델 기본값을 넣지 않습니다.

`createOnAiService({env,model,timeoutMs,verifyAppAuthorization:null,appAuthorization:null})`를 서버에서 한 번 생성합니다. 기본 verifier는 null입니다. 실제 연결을 구성하는 담당자는 서버가 검증한 `alephUserId/siteId/identityVersion`을 읽는 `appAuthorization.resolveExpectedContext`를 주입합니다. 학생에게 credential·grant·policy 버전을 수동 입력하게 하지 않습니다. 환경 변수나 브라우저 JSON으로 이 callback을 공급할 수 없습니다. `model`도 서버 설정이며 허용 모델 목록과 대조합니다.

기본 제한 시간은 10초, 모델 응답 크기는 64 KiB, authorization은 16 KiB, 자동 재시도는 0회입니다. 기한은 신원 resolver·권한 확인·transport 준비·모델 HTTP를 합친 전체 operation에 적용됩니다. callback이 signal을 무시하거나 끝나지 않아도 호출자는 timeout 또는 취소 응답을 받고 늦은 proof로 전송하지 않습니다. 전달받은 신원 문맥은 첫 비동기 작업 전에 복사해 고정합니다. 종료 시 timer와 외부 abort listener를 정리하고 내부 signal을 취소합니다. HTTP는 기본 차단하며 `allowLoopbackHttp:true`는 독립 localhost 검증에만 사용합니다. 원격 HTTP나 리다이렉트는 허용하지 않습니다.

localhost 시험의 서버 전용 `verifyAppAuthorization({ signal, purpose, requiredCapability, expectedScope })`은 매 요청마다 최신 proof를 반환해야 합니다. signal은 전체 operation의 제한 시간과 외부 취소를 반영합니다. purpose/capability는 모델 점검에서 `models`/`ai.models`, 설명에서 `explain`/`ai.explain`입니다. proof는 다음 항목을 포함합니다.

```js
{
  subjectId: 'test-student', projectId: 'test-project', appId: 'test-app',
  audience: 'on-client', capabilities: ['ai.models', 'ai.explain'],
  validUntil: '미래의 ISO 시각', revoked: false,
  credentialFingerprint: '현재 ON_AI_APP_KEY의 SHA-256 소문자 hex',
  mode: 'test',
  appKeyScope: {
    subjectId: 'test-student', projectId: 'test-project', appId: 'test-app',
    audience: 'on-client',
  },
}
```

각 ID와 audience는 appKeyScope 안팎 및 서버가 operation options로 제공한 expectedScope와 정확히 일치해야 합니다. 현재 열쇠 지문과 결속되지 않았거나 scope/capability가 없거나 만료·회수된 proof는 차단합니다. expectedScope가 없으면 verifier와 HTTP를 호출하지 않고 발급 준비 중으로 안내합니다. 권한은 HTTP client와 함께 캐시하지 않고 매 모델 점검과 설명 요청에서 재검사합니다. `mode: 'test'`는 명시적인 `allowLoopbackHttp: true`와 localhost 주소를 함께 요구하며 원격 게이트로 요청할 수 없습니다. callback 예외도 비밀 없이 발급 준비 중으로 안내합니다. 이 proof는 실제 운영 발급 기능이 아니며 앱 권한 등록·회수 정책 설계 검토를 대신하지 않습니다.

실제 expectedScope는 `{subjectId,projectId,appId:'aleph-on',audience:'on-client'}`입니다. 서버가 현재 canonical 로그인 신원과 등록 프로젝트에서 매 operation마다 구성합니다. 생성자에 사용자 scope를 고정하거나 사건 입력·브라우저 JSON에서 받아 쓰지 않습니다. 자료실 사용자 ID와 ALEPH canonical studentId를 자동으로 같다고 취급하지 않습니다. 실제 매핑 공급자는 아직 연결하지 않았으므로 기본 실행은 차단하며, localhost fixture의 합성 매핑을 실제 학생 연결로 보고하지 않습니다.

현재 adapter는 단일 학생이 자기 PC의 loopback 서버를 실행하는 용도입니다. 다중 사용자가 공유하는 서버의 인증·프로젝트 격리 기능으로 사용하지 않습니다.

## 메서드와 입출력

`connectionInfo()`는 `{ configured, authorized: false, authorizationRequired: true, help }`를 반환합니다. `configured`는 주소와 열쇠의 값이 있는지만 확인하며 성공 또는 이용 권한을 뜻하지 않습니다. 실제 localhost 시험 연결을 확인하려면 `await checkConnection({ signal, expectedScope })`을 호출합니다. 시험 성공 응답은 `{ ok: true, transportChecked: true, audienceAuthorization: 'test', modelCount, help }`입니다. 모델 ID나 원격 서버의 자유 형식 메타데이터는 도움 정보에 포함하지 않습니다.

`await explainIncident(input, { signal, expectedScope })`은 서버가 기존 기록에서 구성한 아래 정보만 받습니다. 서버는 사건과 근거의 접근 권한을 먼저 확인하고, 현재 로그인 사용자와 프로젝트에 맞는 expectedScope를 별도 options로 제공합니다. 전체 로그·개인정보·열쇠를 넣지 않은 짧은 근거만 사용합니다. 브라우저가 보낸 `supportedActions`, expectedScope 또는 원시 사건을 그대로 신뢰하지 않습니다.

```js
{
  incidentId: 'incident-1',
  evidence: [{ id: 'e1', summary: '세션 만료 뒤 접속 요청' }],
  rules: [{ id: 'r1', description: '만료된 세션의 접속을 거부한다.' }],
  currentState: { access: 'denied', session: 'expired', device: 'unknown' },
  supportedActions: ['request_reauthentication', 'request_device_check']
}
```

사건·근거·규칙·조치 ID는 최대 80자의 영문·숫자·점·밑줄·콜론·하이픈입니다. 근거와 규칙은 각각 1~20개, 근거 요약은 500자, 규칙 설명은 300자입니다. 현재 상태는 `access: allowed|denied|unknown`, `session: active|revoked|expired|unknown`, `device: compliant|noncompliant|unknown`입니다. 지원 조치가 없으면 빈 배열을 전달합니다. 추가 입력 필드, 알려진 앱 열쇠, Bearer/API key/password 등의 명백한 비밀 표기는 거절합니다. 이 검사는 모든 가능한 개인정보나 비밀을 찾아내는 도구가 아니므로 서버의 원본 기록 최소화가 필요합니다.

localhost 시험 성공 응답은 `{ ok: true, transportChecked: true, audienceAuthorization: 'test', explanation, help }`이고 `explanation`은 다음 형식입니다.

```js
{
  summary: '세션이 만료돼 접속이 거부됐습니다.',
  evidenceIds: ['e1'],
  proposals: [{ action: 'request_reauthentication', evidenceIds: ['e1'], reason: '만료된 세션은 다시 인증해야 합니다.' }],
  requiresHumanConfirmation: true,
  executed: false
}
```

설명은 입력의 모든 근거 ID를 빠짐없이 포함해야 합니다. 각 제안은 실제 근거 ID와 서버가 지원한다고 명시한 조치 ID만 참조할 수 있습니다. 누락·중복·없는 근거, 지원하지 않는 조치, 추가 필드, 도구 실행 응답, 잘린 응답, 명백한 비밀을 포함한 응답은 실패로 처리합니다. ID와 형식 검증은 설명의 모든 문장을 의미적으로 입증하지는 않으므로 기존 사건 기록과 함께 사람이 확인합니다. UI는 문자열을 HTML로 실행하지 말고 텍스트로 표시합니다.

제안 선택 뒤 실제 처리는 기존 서버의 별도 인증·권한·현재 상태 확인과 사용자 확인을 거쳐 수행해야 합니다. AI 응답을 집행 명령으로 직접 연결하지 않습니다.

## 실패 안내와 도움 정보

실패는 `{ ok: false, error: { code, message }, help }`로 반환하며 일반 서버에 예외를 던지지 않습니다. 원격 서버의 오류 본문·열쇠·자유 형식 예외 메시지는 반환하거나 기록하지 않습니다. 앱은 접속 판정과 기록 조회를 계속 제공하고, AI 실패를 정상이나 안전으로 표시하지 않습니다.

- `WB_CLCO_AUTH_REQUIRED`: 앱 전용 열쇠 확인
- `WB_CLCO_ACCESS_BLOCKED`: 학생 앱 이용 권한 확인
- `WB_CLCO_SESSION_CLOSED`: 이용 시간 확인
- `WB_CLCO_COHORT_BUDGET_EXHAUSTED`: 반의 사용량 확인
- `WB_CLCO_RATE_LIMITED` / `WB_CLCO_LIMIT_REACHED`: 요청 제한 또는 한도 확인
- `WB_CLCO_SERVER_UNAVAILABLE` / `WB_CLCO_TIMEOUT` / `WB_CLCO_NETWORK_ERROR`: 서버 응답과 연결 확인
- `WB_CLCO_INVALID_RESPONSE` / `ON_AI_INVALID_OUTPUT`: 응답 또는 근거·제안 형식 확인
- `ON_AI_PROVISIONING_PENDING`: 앱 권한과 열쇠 발급 준비 중
- `MODEL_NOT_CONFIGURED`: 서버 모델 설정 필요

도움 정보는 component, code, appCredentialsConfigured, provisioning, automaticRetries, workbenchRequiredAtRuntime만 포함합니다. 복사 기능은 이 객체만 사용하고 서버 주소·열쇠·사건 원문·전체 오류 객체는 포함하지 않습니다. `appCredentialsConfigured`는 값이 존재하는지만 확인합니다. 열쇠 유효성은 실제 연결 점검에서 확인합니다.

## 검증

```powershell
node --test education/on-client/test/ai.test.mjs
```

로컬 17개 테스트 PASS: 기존 13개 회귀 검사(모델 점검, 최소 사건 전송, 추가/누락 근거 거절, 서버 지원 조치 검사, 비밀 sentinel 미반환·로그 0, 401/403/session/budget/rate/5xx/리다이렉트/잘못된 응답/큰 응답/timeout/취소, 자동 재시도 0, 입력 상태 보존, 기본 네트워크 호출 0, Workbench 열쇠 오인 방지, scope/지문/capability/만료/회수 재검사, test 원격 차단, JSON/환경 변수 우회 차단, callback 예외 비밀 미노출)를 보존했습니다. 추가 4개는 현재 engine 사용자/프로젝트/app과 proof의 결속, expectedScope 누락 차단, 무한 verifier의 전체 제한 시간, 외부 abort 및 늦은 proof의 HTTP 요청 0, verifier+transport를 합친 제한 시간, abort listener 정리를 확인합니다. 실제 앱 서버의 기본 동작과 AI 동시 실패 격리는 서버 통합 검수에서 확인해야 합니다.

운영 게이트 호출, 앱 전용 열쇠 발급/등록, Workbench 열쇠와의 충돌 검증, 실제 학생 계정, PC 브라우저 수용 검사, 운영 배포는 **NOT_RUN**입니다. 이 모듈의 로컬 검증은 해당 결과를 대신하지 않습니다.

원 복사본의 출처는 Workbench 커밋 `b6fabbd452533abd6ceca76145620cea19c39d0b`이며 아래 SHA-256을 보존합니다. 현재 vendored 파일은 학습지원 메서드가 추가된 파생본으로 바이트가 같지 않습니다. 현재 파일 해시는 이번 SOURCE 제출에 기록하며 공개 라이선스가 확인됐다고 주장하지 않습니다. 원 복사본 SHA-256:

`D2D156FD9CE80F7CA53F061257470BC67F1E4459675EFBCC78F13285652D5141`

## GPT 학습지원 연결 소스

`explainLearningSupport(input, observation, options)`는 원 순수 계약에서 준비한 객체를 유지하고, 실제 HTTP verifier의 현재 `explain`/`ai.explain` proof와 서버 설정 모델의 허용 여부를 확인합니다. 명시적 합성 test proof는 이 메서드에서 허용하지 않습니다. 기존 models/incident 메서드의 test 경로는 보존합니다. vendor.learnerSupport는 정확히 `{model,problemKind,observations}`를 `/api/apps/aleph-on/v1/learner-support`에 보내며 자유 prompt/messages, 사건 DTO, browser 신원, grant 또는 proof를 body에 넣지 않습니다.

게이트 성공 응답은 정확히 `{ok:true,data:maintainedGuide}`입니다. 서비스는 응답의 유한 ID로 원 prepared를 재렌더하고 모든 필드·한국어 문장·관측·근거·실행 여부를 대조합니다. extra 필드, getter, Proxy와 변조 문장을 거절합니다. 이어 같은 scope/context와 원 operation signal로 실제 authorization을 다시 조회합니다. 신원·credential/grant/version·policy/accessPolicy·목적·capability·지문·모델 정책과 capability/allowedModels를 대조하고 선택 모델의 현재 허용을 확인합니다. validUntil 문자열은 재발행 시각에 따라 달라도 각 proof가 실제 현재 유효해야 합니다. 기존 로컬 guard를 원격 회수 조회라고 표현하지 않습니다.

Vault 서비스는 학습지원 메서드를 명시적으로 분기하고 첫 await 전에 유한 입력·관측·scope/context를 복사합니다. scope/context의 원 값은 clone 전에 문자열·양의 정수와 원 app/audience 계약으로 확인합니다. 서버가 소유한 beforeDispatch와 beforePublish callback도 캡처해 원 signal과 함께 전달합니다. callback은 전송 전과 guide 투영 뒤 host를 대조하는 추가 차단 검사이며 새로운 인증 증거가 아닙니다. 최종 host 대기 이후에 사후 HTTP authorization과 원 proof의 현재성을 확인하고 반환합니다. 서비스 내부의 authorizationValidUntilMs는 proof·operation·Vault credential 기한의 최소로, 서버의 마지막 만료 차단에만 사용하며 권한 증거로 쓰거나 브라우저 guide에 넣지 않습니다. host와 원격 권한 원천의 전후 조회는 원자적 트랜잭션이 아닙니다. callback은 브라우저/body에서 받지 않고 기존 models/incident 메서드에 적용하지 않습니다. vault 대기와 AI operation은 원 총 deadline을 공유하며 남은 시간만 하위 서비스에 전달합니다. 실패나 취소 뒤 재시도하지 않습니다. 공개 라이선스 확인, 실제 운영 호출·키 발급·학생 PC 수용은 여전히 미완료입니다. 새 소스와 검사 계획은 `../../docs/LEARNER_SUPPORT_GPT_CONTRACT.md`에 기록합니다.
