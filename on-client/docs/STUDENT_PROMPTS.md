# 보안 Agent 13~22단계 학생 단계 프롬프트 (v0.6, R4 필수 기준 판정 판, starter 0.2.11)

근거: docs/IMPLEMENTATION_CONTRACT.md, docs/CURRICULUM_R4_V06_OFFICIAL.json. 이 문서는 학생이 단계마다 그대로 따라 하는 진행 안내와, 자기 AI 도우미(CLCO 수업용 AI)에 붙여 넣는 프롬프트입니다. 운영 점수표·검사 기준·공식 개방을 확정하지 않습니다.

이 판(v0.6)은 공식 필수 판정 정책과 함께 명시해 받는 새 13~20단계 접수에만 씁니다. claimRevision 4(R4)의 검사 이름·질문·학생 구현 기준은 v0.5와 같습니다. 기존 v0.5의 비동기 피드백 접수, 이미 받은 결과와 1~3차 기록에 소급 적용하지 않습니다. 21·22단계의 본문과 native v0.5 계약은 그대로이며, 이 판의 필수 판정 적용 대상이 아닙니다. 이 문서만으로 운영 개방이나 점수·순위 정책이 확정되지는 않습니다.

연결이나 실행이 막히면 [CONNECTION_TROUBLESHOOT.md](CONNECTION_TROUBLESHOOT.md)에서 오류 코드별로 찾습니다.

---

## 먼저 읽을 공통 규칙

### 프로젝트 하나로 끝까지 갑니다

- 1~12단계에서 쓰던 프로젝트가 있으면 그대로 이어 씁니다. 3차를 끝내지 못했어도 4차 시작 틀을 새 폴더에 받아 시작할 수 있습니다.
- 13단계에서 시작한 프로젝트 하나로 22단계까지 갑니다. 단계마다 새 프로젝트를 만들지 않습니다.
- 이전 학생 파일과 1~3차 기록은 지우거나 덮어쓰지 않습니다.
- 단계를 시작하기 전에 항상 지금 상태를 커밋합니다. 문제가 생기면 그 커밋의 학생 파일로만 되돌립니다.
- 제출 커밋에는 학생 파일뿐 아니라 실행에 필요한 제공 UI·서버·설정 파일도 함께 넣습니다. 상황실의 PowerShell 커밋 안내는 시작 틀 목록으로 이 파일들을 준비합니다. `student/extension.mjs`만 커밋하면 메뉴·새로고침 연결 원문이 빠져 확인할 수 없습니다. 실제 `.env`와 인증값은 넣지 않습니다.

### 어디를 고치는가

- 13~15단계는 `student/extension.mjs` 하나에서 시작합니다. 16단계부터는 필요하면 학생 화면·설명 파일로 넓힙니다.
- 제공 파일(public/app.js, src/ 아래 서버, 제공 화면)은 고치지 않습니다. 제공 화면이 잘 보이는 것만으로는 단계를 통과하지 못합니다. 13~20단계는 학생 코드가 실제로 바뀌었는지(student-source-changed)와 실제 표시 동작을 확인합니다. 21·22단계는 문서 변경과 최종 소스·재현 계약을 따로 확인합니다.
- 학생 표시 함수는 DOM 요소나 글자를 돌려줍니다. 글자는 HTML 로 해석되지 않고 그대로 보입니다. `innerHTML`·`outerHTML`·`insertAdjacentHTML`·`document.write` 는 쓰지 않고, `document.createElement` 와 `textContent` 를 씁니다.

### 학생 코드가 받을 수 있는 것

- `createStudentView({ api, onChange })` 가 시작점입니다.
- `api.get(path)` 로 읽을 수 있는 주소는 여섯 개뿐입니다: `/api/me`, `/api/apps`, `/api/events`, `/api/devices`, `/api/sessions`, `/api/vulnerabilities`. 다른 주소는 `NOT_ALLOWED` 로 돌아옵니다. 주소 뒤에 `?` 조건을 붙이면 서버가 거절하므로, 걸러 보기는 받은 목록 안에서 합니다.
- AI 점검·설명·조치 요청은 제공 버튼이 보냅니다. 학생 코드에는 POST 를 보내는 함수가 없습니다.
- `onChange()` 를 부르면 앱이 학생 표시 함수를 최신 자료로 다시 부릅니다.
- 표시 함수가 받는 자료는 대부분 `{ status, mode, data?, error? }` 입니다.
  - status: `loading`·`ok`·`error`(접속 판정·AI 연결 점검·사건 설명·조치처럼 아직 실행하지 않은 상태가 있는 자료는 `idle` 도 있음). 응답 형식이 맞지 않으면 `error` 이고 code 가 `CONTRACT_MISMATCH`·`ENGINE_RESULT_UNVERIFIED` 입니다. 이것은 확인 불가이지 정상·빈 목록·차단이 아닙니다.
  - mode: `connected`·`demo`·`disconnected`·`unknown`. demo 는 예제 자료라 실제 연결 성취가 아닙니다.
  - error: `{ code, message }`. 화면에는 message 를 글자로만 보여 줍니다.

### 화면 문장은 뜻으로 확인합니다

- 화면 문장은 정해진 낱말을 맞추는 것이 아니라, 지금 상태를 읽는 사람이 틀리지 않게 전하는 것이 기준입니다.
- 프롬프트 안의 따옴표 문장은 예시입니다. 같은 뜻을 분명히 전하면 다른 표현도 됩니다. "허용되지 않음", "완료 아님"처럼 부정하는 문장도 오해 없이 읽히면 괜찮습니다.
- 아직 확인되지 않은 것을 끝났거나 성공한 것처럼 읽히게 쓰지 않습니다. 확인할 수 없는 것을 정상·안전으로 바꾸지 않습니다.
- 다음은 기계가 정확히 확인하므로 그대로 지킵니다: 원래 값(allow·unknown·executing 같은 코드)을 함께 보여 주는 것, ID·시각·버전 같은 값, 정해진 속성 이름(data-student-…), 정해진 접근 가능한 이름(선택 상자 「기록 종류」·「업무 앱」·「접속 상태」, 「<event.id> 상세」·「도움정보 복사」·「<action> 미지원」 버튼), 비밀값을 화면·복사 내용에 쓰지 않는 것, 요청 횟수·자동 재시도 금지 같은 동작 조건.
- 현재 13~20단계는 서버의 수업용 AI가 이 과제 원문과 제출 커밋의 코드 원문을 읽어 필수 항목을 판정합니다. 서버는 학생 코드를 실행하지 않습니다. 직접 실행해 보는 아래 항목은 학생의 자체 확인이며, 원문 검토를 실제 실행 인증으로 표시하지 않습니다. 제공 UI의 원문은 학생 함수와의 연결을 확인하는 자료이고 제공 코드 자체를 학생의 성취로 인정하지 않습니다.

### 진도와 점수

- 아래의 다음 단계 규칙은 공식 제출·순서 권한이 열린 뒤에 적용됩니다. 지금 내부 시험 자료(fixture)로 통과한 것은 공식 완료·점수·순위가 아닙니다.
- 새 13~20단계 접수는 커밋·원문 확인을 거쳐 필수 AI 기준 판정을 통과하면 확정됩니다. 불리한 의미 판정은 독립 재검토에서도 같은 미충족 기준이 확인돼야 합니다. 자료 부족·수집 잘림·모델 오류·시간 초과·서로 다른 판단은 학생 실패가 아니라 보류입니다.
- 학생은 근거와 수정 안내를 보고 수정·재제출할 수 있습니다. 같은 제출·정책의 기존 결과와 원문·판정·정정 이력은 보존하며, 서버 장애의 재시도는 결과 확인 뒤 명시적으로 요청합니다. 기존 v0.5 결과는 소급 변경하지 않습니다. 21·22단계는 기존 native v0.5의 자동 확인·비동기 피드백 계약을 유지합니다. 이 판은 숫자 점수·분모·순위 산출 방식을 새로 정하지 않습니다.
- 단계마다 적힌 날짜는 권장 기한입니다. 지나도 제출이 막히거나 감점되지 않습니다.
- 순위 집계의 정확한 마감 시각, 마감 뒤 인정 기간, MCP 연동 가산 여부는 아직 정해지지 않았습니다. 정해지면 ALEPH 화면에 공지됩니다.

### 꼭 지킬 것

- 비밀을 다루지 않습니다. AI 열쇠·서버 인증값을 입력하는 칸을 만들지 않고, 코드·제출물·캡처·도움정보에 넣지 않습니다.
- 자동으로 다시 시도하지 않습니다. 실패는 보여 주고, 다시 시도는 사용자가 직접 누르게 합니다.
- AI 설명과 제안은 참고 정보입니다. 실제 조치는 서버가 사람 확인을 거쳐 처리하고, 그 결과는 서버가 알려 준 값으로만 표시합니다.
- 41종 공격 재현, Windows 드라이버, 자체 터널, 운영체제 센서는 13~22단계의 필수 조건이 아닙니다.

### 공통 동선

ALEPH 단계 안내를 읽습니다 → 내 PC 작업 폴더에서 CLCO 수업용 AI 와 함께 개발합니다 → 앱을 실행해 화면에서 확인합니다(실행 방법은 STUDENT_LAUNCH_GUIDE.md) → ALEPH 에 제출하고 자동 확인을 받습니다 → 통과하면 다음 단계로 갑니다. 앱을 실행하는 동안 워크벤치를 계속 켜 둘 필요는 없습니다.

---

## 13단계 · 세 메뉴와 로그인·기기 상태 (권장 10/19)

**목표**: 지금 로그인한 사용자·기기·세션을 상태에 맞게 보여 주고, 다시 불러오면 새 값으로 바꿉니다.

**고칠 파일**: `student/extension.mjs` 의 `renderIdentity`. 다른 함수의 기본 문구는 그대로 둡니다.

**받는 값**: `renderIdentity({ me, devices, sessions })`. 셋 다 `{ status, mode, data?, error? }` 입니다.
- me.data: `{ user:{id,label}, device:{id,label,status}, session:{id,status} }`
- devices.data: `[{ id, label, status }]`, sessions.data: `[{ id, status }]`
- 기기 status: `compliant`·`noncompliant`·`unknown`. 세션 status: `active`·`expired`·`revoked`·`unknown`.

**상태별 표시**

| 상황 | 보여 줄 것 |
|---|---|
| loading | 불러오는 중 |
| ok | 사용자 이름, 기기 이름과 상태, 세션 상태. noncompliant·expired·revoked 는 정상처럼 보이지 않게 |
| error | 연결 실패 또는 확인 불가와 서버 message. 이전 사용자 값은 지움 |
| mode demo | 예제 자료라고 표시 |
| mode disconnected / unknown | 연결 없음 / 확인 불가 |

**AI 에게 붙여 넣을 프롬프트**

```
student/extension.mjs 의 renderIdentity 만 구현해 줘. 다른 파일과 다른 함수는 건드리지 마.
입력은 { me, devices, sessions } 이고 각각 { status, mode, data?, error? } 야.
- status 가 loading 이면 불러오는 중이라는 것을, error 면 서버에 연결하지 못했다는 것과 error.message 를 글자로 보여 줘(예: "연결 실패: " 뒤에 message).
- ok 면 me.data.user.label, me.data.device.label 과 status, me.data.session.status 를 보여 줘.
- 기기 status 는 compliant=정상, noncompliant=점검 필요, unknown=확인 불가로, 세션 status 는 active=사용 중, expired=만료, revoked=취소, unknown=확인 불가로 바꿔 보여 줘.
- mode 가 demo 면 예제 자료라는 것, disconnected 면 연결이 없다는 것, unknown 이면 확인할 수 없다는 것을 함께 보여 줘(예: "예제 자료", "연결 없음", "확인 불가").
- document.createElement 와 textContent 만 써. innerHTML 은 쓰지 마. DOM 요소 하나를 돌려줘.
- 오류일 때 이전에 보이던 사용자 이름이 남지 않게 해.
```

**스스로 확인**
1. 앱을 켜고 보호 현황의 학생 칸에 사용자·기기·세션이 보이는지 봅니다.
2. 다시 불러오기를 누르고 값이 새로 그려지는지 봅니다.
3. 앱 서버를 끈 상태에서 다시 불러오면 연결 실패가 보이고 옛 사용자 이름이 사라지는지 봅니다.
4. 1280px 이상 브라우저에서 세 메뉴를 마우스와 키보드(Tab, Enter)로 오가 봅니다.

**공개 완료 기준**: student-source-changed, three-menus, student-identity-updates, student-failure-visible, identity-after-reload. AI는 제공 UI와 학생 함수의 원문을 대조해 메뉴 연결, 새 입력에 따른 표시 교체, 실패 안내와 이전 사용자 값 제거를 검토합니다. 실제 실행 결과를 인증하는 것은 아닙니다. 스스로 확인할 때 사용자·기기 값을 바꾸고 실패도 확인합니다. loading·error 상태에서도 전달받은 demo·disconnected·unknown 모드 안내를 함께 표시합니다.

**다음 단계 조건**: 제출 커밋의 원문 확인과 필수 AI 기준 판정을 통과하면 서버에 기록되고 14단계가 열립니다.

---

## 14단계 · 업무 앱과 접속 판정 (권장 10/20)

**목표**: 업무 앱 접속 요청의 결과(허용·거부·추가 확인·확인 불가)와 요청 실패를 서로 다르게 보여 줍니다.

**고칠 파일**: `renderDecision`. 13단계 함수는 그대로 둡니다.

**받는 값**: `renderDecision({ status, mode, data?, error?, appId })`
- status: `idle`(요청 전)·`loading`·`ok`·`error`
- data: `{ appId, decision, reason, checkedAt }`, decision: `allow`·`deny`·`challenge`·`unknown`

**상태별 표시**

| 상황 | 보여 줄 것 |
|---|---|
| idle | 앱을 골라 접속을 요청하라는 안내 |
| allow | 허용과 reason |
| deny | 거부와 reason |
| challenge | 추가 확인이 필요하다는 안내. 앱이 확인 절차를 대신하지 않음 |
| unknown 또는 목록에 없는 값 | 확인 불가. 허용으로 보이지 않게 |
| error | 요청 실패. 차단 판정이 아님 |

**AI 에게 붙여 넣을 프롬프트**

```
student/extension.mjs 의 renderDecision 만 구현해 줘. renderIdentity 는 그대로 둬.
입력은 { status, mode, data?, error?, appId } 야. data 는 { appId, decision, reason, checkedAt }.
- idle 이면 앱을 골라 접속을 요청하라는 안내, loading 이면 판정을 확인하는 중이라는 것을 보여 줘(예: "앱을 골라 접속을 요청하세요", "판정 확인 중").
- 판정은 한국어 뜻과 원래 값을 함께 보여 줘: 허용(allow), 거부(deny), 추가 확인 필요(challenge), 확인 불가(unknown). reason 과 checkedAt 도 함께 적어.
- unknown 이거나 이 네 값이 아니면 확인할 수 없다는 뜻과 원래 값 unknown 을 함께 보여 줘(예: "확인 불가(unknown)"). unknown 과 요청 실패 화면은 허용되었거나 정상인 것처럼 읽히면 안 돼. "허용되지 않음"처럼 부정하는 문장은 써도 돼.
- status 가 error 면 요청이 실패했다는 것과 error.message 를 보여 주고, 이것이 거부 판정이 아니라는 것도 알려 줘(예: "요청 실패: " 뒤에 message).
- 색만으로 구분하지 말고 글자로도 구분해. textContent 만 써.
```

**스스로 확인**
1. 업무 앱마다 접속 요청을 눌러 네 판정이 글자로 구분되는지 봅니다.
2. 서버를 끄고 요청해 요청 실패가 거부와 다르게 보이는지 봅니다.
3. 다시 불러오기를 누르면 이전 판정이 지워지는지 봅니다.
4. 키보드로 앱 버튼을 눌러도 결과가 바뀌는지 봅니다.

**공개 완료 기준**: student-source-changed, server-decisions-distinct, decision-reason-visible, unknown-not-allow, failure-not-allow.

**다음 단계 조건**: 기계 확인과 이 판의 필수 AI 기준 판정을 모두 통과해야 확정되고 15단계가 열립니다.

---

## 15단계 · 내 접속 기록과 XDR 경보 (권장 10/21)

**목표**: 내 접속 기록(kind: access)과 저장된 XDR 경보(kind: xdr)를 시각·근거·규칙·상태와 함께 보여 주고, 걸러 보기와 상세 보기를 만듭니다.

**고칠 파일**: `renderEvents`. 필요하면 같은 파일 안에 걸러 보기 상태를 둡니다.

**받는 값**: `renderEvents({ status, mode, data?, error? })`, data 는 기록 배열입니다.
- 기록: `{ id, kind, at, appId, summary, evidence:[{id,text}], rules:[{id,text}], state:{access,session,device}, supportedActions:[] }`
- state 의 세 값은 따로 표시합니다. access: allowed·denied·unknown, session·device 는 13단계와 같습니다.

**어디까지 보이는가(관측 범위)**
- 이 목록은 앱 서버가 내 SDP 감사 기록에서 현재 등록 정보와 맞춰 본 내 기록입니다. 전체 로그도, 다른 학생 기록도 아닙니다.
- 최근 40건까지만 옵니다. 더 있으면 제공 화면 위쪽에 전체 건수와 생략된 건수, 확인 시각이 함께 보입니다. 이 확인 범위 문구는 제공 화면이 보여 주며, 학생 함수에는 목록만 전달됩니다.
- XDR 경보는 서버가 이미 저장한 경보만 나옵니다. 화면을 열 때 새로 탐지하지 않습니다.
- 지금 등록 정보와 맞출 수 없는 옛 기록에는 앱 ID 가 비어 있을 수 있습니다(appId 없음). 지난 세션·기기의 상태는 확인 불가(unknown)로 옵니다. 정상으로 바꾸지 않습니다.
- 지금 실제 목록의 supportedActions 는 비어 있습니다. 비어 있으면 조치 버튼을 만들지 않습니다. 15·16단계 자동 확인이 연결되지 않은 조치를 넘겨 주는 경우에만, 16단계에서 요청을 보내지 않는 비활성 안내 버튼을 상세 안에 둡니다.

**상태별 표시**

| 상황 | 보여 줄 것 |
|---|---|
| ok, 기록 있음 | 시각 순 목록, 종류·앱·요약. 기록을 누르면 근거·규칙·세 상태 |
| ok, 빈 배열 | 표시할 기록이 없음 |
| error | 실패. 빈 목록과 다르게 |
| CONTRACT_MISMATCH | 확인 불가. 이전 목록을 지움 |

**AI 에게 붙여 넣을 프롬프트**

```
student/extension.mjs 의 renderEvents 를 구현해 줘. 앞 단계 함수는 그대로 둬.
입력은 { status, mode, data?, error? } 이고 data 는 기록 배열이야.
기록 하나는 { id, kind, at, appId, summary, evidence:[{id,text}], rules:[{id,text}], state:{access,session,device}, supportedActions } 야.
- 목록은 at 기준 최신순으로 보여 줘. 각 행에 data-student-event-id 속성으로 event.id 를 붙이고, 사건 ID·시각·종류·앱·summary 를 글자로 적어. 시각은 at 원래 값이나 한국 시각으로 읽을 수 있게, 종류는 접속 기록인지 XDR 경보인지 알아볼 수 있게(예: access=접속, xdr=XDR 경보), 앱은 appId(없으면 앱을 확인할 수 없다는 것)로 적어.
- 걸러 보는 선택 상자 세 개를 만들어. 접근 가능한 이름(label 또는 aria-label)은 "기록 종류", "업무 앱", "접속 상태" 로 하고, 전체 값은 all, 나머지 값은 원래 kind·appId·state.access 값으로 해. 서버에 다시 묻지 말고 받은 배열 안에서 걸러.
- 행마다 상세 버튼을 두고 접근 가능한 이름을 "<event.id> 상세" 로 해. 상세 영역에는 data-student-event-detail 속성으로 event.id 를 붙여.
- 상세에는 사건 ID 와 appId, evidence 의 id 와 text, rules 의 id 와 text, state 의 access·session·device 세 값의 원래 값과 한국어 설명을 모두 보여 줘. unknown 은 "확인 불가(unknown)".
- 표식만 붙여서는 통과하지 않아. 실제 글자와 동작이 맞아야 해.
- 빈 배열이면 기록이 없다는 것을, error 면 기록을 불러오지 못했다는 것과 message 를 보여 줘. 기록이 없는 화면이 실패처럼, 실패 화면이 빈 목록처럼 읽히면 안 되고 두 화면은 달라야 해(예: "표시할 기록이 없습니다", "기록을 불러오지 못했습니다: ").
- 새 자료가 오면 이전 목록과 상세를 모두 지우고 다시 그려.
- 기록 글에 <b> 같은 글자가 있어도 글자 그대로 보이게 textContent 만 써.
- 실제 조치 버튼은 만들지 마. 연결되지 않은 조치 안내는 16단계에서 다뤄.
```

**스스로 확인**
1. 기록이 여러 개·없음·실패일 때 화면이 각각 다르게 보이는지 봅니다.
2. 걸러 보기를 바꾸면 목록이 맞게 줄어드는지 봅니다.
3. 상세에서 세 상태가 따로 보이는지, unknown 이 확인 불가로 보이는지 봅니다.
4. 다시 불러오기 뒤 옛 상세가 남지 않는지 봅니다.

**공개 완료 기준**: student-source-changed, event_scope, event_time, event_filter, event_detail, events-refresh-replaces, events-empty-error-distinct.

**다음 단계 조건**: 기계 확인과 이 판의 필수 AI 기준 판정을 모두 통과해야 확정되고 16단계가 열립니다.

---

## 16단계 · 알림·기기·세션·오류·빈 화면 (권장 10/22)

**목표**: 실패·빈 화면·다시 시도·도움정보·미지원 조치를 사용자가 이해할 수 있게 안내합니다.

**고칠 파일**: `renderStatus` 와, 미지원 조치 안내를 넣을 15단계 `renderEvents` 상세. 이 단계부터 필요하면 학생 화면·설명 파일을 더해도 됩니다. 그 밖의 앞 단계 함수는 그대로 둡니다.

**받는 값**: `renderStatus({ devices, sessions, notifications, diagnostics, mode })`
- devices·sessions·diagnostics: `{ status, mode, data?, error? }`
- notifications: `[{ resource, code, message }]`. 제공 코드가 실패한 자료, 점검이 필요한 기기, 끝난 세션, XDR 경보와 확인 불가 상태가 있는 기록을 모아 줍니다.
- diagnostics: `GET /api/diagnostics` 의 비밀 없는 점검 결과

**어디까지 보이는가(관측 범위)**
- 등록 기기는 내 이름으로 등록되고 회수되지 않은 기기 100개까지입니다. 지금 쓰는 기기가 맨 앞에 옵니다. 운영체제처럼 서버가 모르는 값은 확인 불가로 옵니다.
- 세션은 지금 검증된 연결 하나만 옵니다. 지난 세션 목록이 아닙니다.
- 전체 건수·생략 여부·확인 시각은 제공 화면이 보여 줍니다. 형식이 맞지 않으면 제공 화면이 목록 전체를 확인 불가로 바꿉니다.

**상태별 표시**

| 상황 | 보여 줄 것 |
|---|---|
| 기기·세션 불러오는 중 | 불러오는 중 |
| 빈 목록 | 등록된 기기가 없음 / 현재 연결 없음 |
| 실패 | 무엇을 불러오지 못했는지와 message, 사용자가 누르는 다시 시도 안내 |
| 알림 있음 | 알림마다 어느 자료(resource)인지와 message |
| 미지원 조치 | 요청을 보내지 않는 "아직 지원하지 않음" 안내 |

**AI 에게 붙여 넣을 프롬프트**

```
student/extension.mjs 의 renderStatus 를 구현해 줘. 앞 단계 함수는 그대로 둬.
입력은 { devices, sessions, notifications, diagnostics, mode } 야.
- devices·sessions 는 { status, mode, data?, error? }. 불러오는 중·빈 목록·실패를 서로 다른 문장으로 보여 줘.
- 기기는 label 과 status 를, 세션은 id 와 status 를 원래 값과 함께 보여 줘.
- 실패하면 무엇을 불러오지 못했는지와, 다시 시도는 사용자가 위쪽 다시 불러오기 버튼을 직접 누르는 것이라고 안내해(예: "다시 시도는 위쪽 다시 불러오기 버튼을 직접 누르세요"). 시간이 초과된 경우는 시간 초과라는 것이 드러나게 하고, 다시 불러와 성공하면 이전 실패 안내를 지워. 자동으로 다시 요청하지 마.
- notifications 배열은 항목마다 어느 자료의 알림인지(resource), 안전한 code, message 를 글자로 보여 줘. 비어 있으면 주의할 알림이 없다는 것(예: "주의할 알림이 없습니다").
- diagnostics 가 ok 면 requestId, component, version, checkedAt, engine.mode, engine.code 를 보여 줘. 열쇠나 토큰 같은 값은 화면에 쓰지 마.
- 학생 상태 칸 안에 이름이 정확히 "도움정보 복사" 인 버튼을 만들고, 이 정보가 도움 요청에 쓰도록 복사하는 것이라고 알려 줘. 사용자가 누를 때만 위의 안전한 값을 복사해.
- 15·16단계 자동 확인이 연결되지 않은 조치를 넘겨 주면, 15단계 상세(data-student-event-detail) 안에 이름이 정확히 "<action> 미지원" 인 비활성 버튼을 만들고, 아직 지원하지 않는 조치라는 것을 알려 줘(예: "조치 실행 연결은 준비 중입니다"). 실행에 성공한 것처럼 읽히는 문장은 쓰지 말고 어떤 요청도 보내지 마. 실제 목록의 supportedActions 가 비어 있으면 버튼을 만들지 마. 필요하면 15단계 상세 함수에 이 안내를 더해도 돼.
- 세션은 지금 연결 하나만 온다는 점을 적어. 지난 세션 목록이라고 쓰지 마.
- textContent 만 써.
```

renderStatus 하나만 고쳐서는 이 단계를 통과할 수 없습니다. 미지원 조치 안내는 15단계 상세 안에 있어야 하고, 도움정보 복사 버튼은 학생 상태 칸 안에 있어야 합니다. 제공 화면의 복사 버튼이나 안내 문장으로 대신할 수 없습니다. 학생에게 조치 요청(POST) 권한이나 실제 조치 버튼을 더하라는 뜻은 아닙니다.

**스스로 확인**
1. 기기·세션이 빈 경우와 실패한 경우가 다르게 보이는지 봅니다.
2. 다시 시도가 버튼을 누를 때만 일어나는지 봅니다(브라우저 개발자 도구 네트워크 탭에서 요청이 저절로 반복되지 않는지).
3. 도움정보를 복사해 열쇠·비밀이 없는지 읽어 봅니다.
4. 미지원 조치 버튼을 눌러도 요청이 나가지 않는지 봅니다.

**공개 완료 기준**: student-source-changed, devices-sessions-refresh, notifications, loading_empty, retry, diagnostics_redaction, unsupported_action.

**다음 단계 조건**: 기계 확인과 이 판의 필수 AI 기준 판정을 모두 통과해야 확정되고 17단계가 열립니다.

---

## 17단계 · 수업용 AI(알레프게이트) 연결 (권장 10/26)

**목표**: 앱 서버를 통해서만 수업용 AI 에 연결하고, 연결 결과와 실패 원인을 사용자에게 구분해 안내합니다.

**고칠 파일**: `renderAiConnection`, 그리고 `renderExplanation` 의 기초(18단계에서 넓힘).

**연결 순서(제공 화면, 주소·열쇠 입력 없음)**
1. 보호 현황의 계정 연결 확인에서 「시작」을 누르고 확인 번호를 봅니다. 승인 화면을 열어 포털에서 같은 계정으로 승인한 뒤 「연결 확인」을 누릅니다.
2. AI 연결 칸에서 「AI 연결 시작」을 누르고 확인 번호를 봅니다. 「승인 페이지 열기」로 승인한 뒤 「승인했으며 연결 확인」을 누릅니다.
3. 연결 완료가 보이면 「현재 API 연결 점검」을 누릅니다.

**운영자가 먼저 준비해야 하는 것(학생 잘못이 아님)**
- 학생 계정과 앱 권한 발급, 수업용 AI 게이트의 새 버전 반영이 끝나야 실제 연결이 됩니다.
- 그 전에는 권한 준비 중이나 확인 불가가 나옵니다. 연결 완료로 보이지 않으면 성공으로 적지 않습니다.
- Workbench 열쇠나 AI 회사 원본 열쇠를 복사해 붙이지 않습니다.

**받는 값**: `renderAiConnection({ status, mode, data?, error?, checkedAt, explanationAccepted:false })`
- data: `{ transportChecked:true, audienceAuthorization:'test'|'verified', modelCount, help }`
- 모델 목록 응답만으로 사건 설명이 된 것은 아닙니다. 사건 설명은 보안 기록에서 따로 요청하고 확인합니다.
- test 는 시험 연결입니다. verified 는 그 시각 기준 앱 권한 확인과 모델 응답입니다.

**오류 구분(화면에 원문 오류·열쇠를 쓰지 않음)**

| 원인 | 안내 방향 |
|---|---|
| 권한 준비 중·확인 불가 | 담당자에게 계정 연결과 앱 권한 확인 요청 |
| 인증 실패·접근 제한 | 계정 연결 다시 확인, 담당자 확인 |
| 반 사용량·이용 한도 | 담당자 확인 |
| 이용 시간 아님 | 이용 시간 확인 |
| 요청 제한·시간 초과·네트워크 | 잠시 뒤 직접 다시 점검 |
| 취소 | 취소됨. 이전 결과는 현재 결과가 아님 |
| 쓸 수 있는 모델 없음 | 담당자에게 모델 허용 설정 확인 요청 |

**AI 에게 붙여 넣을 프롬프트**

```
student/extension.mjs 의 renderAiConnection 을 구현하고, renderExplanation 은 기초만 만들어 줘. 앞 단계 함수는 그대로 둬.
renderAiConnection 입력은 { status, mode, data?, error?, checkedAt, explanationAccepted } 야.
- status 가 idle 이면 아직 점검 전이라는 것, loading 이면 점검 중이라는 것을 보여 줘(예: "AI 연결 점검 전", "AI 연결 점검 중").
- ok 면 audienceAuthorization 이 test 일 때 "시험 연결 점검(test)", verified 일 때 "앱 권한 확인 후 점검(verified)" 이라고 적고 modelCount 와 checkedAt 을 함께 보여 줘.
- ok 화면에는 연결만 점검했고 사건 설명은 아직 실행하지 않았다는 것을 분명히 적어(예: "사건 설명은 아직 실행하지 않았습니다"). 모델 목록 응답을 사건 설명이 된 것처럼 쓰지 마.
- error 면 안전한 error.code 와 error.message 를 함께 글자로 보여 주고, code 로 원인을 나눠 안내해: 권한 준비 중, 인증, 접근 제한, 사용량·한도, 이용 시간, 요청 제한·시간 초과·네트워크, 취소, 모델 없음. 열쇠나 원문 오류는 쓰지 마.
- 다시 점검해 성공하면 이전 오류 안내(권한·인증 등)는 화면에서 지워져야 해. 현재 점검 결과만 보이게 해.
- 다시 idle 이 오면(계정 연결을 다시 하는 경우 등) 이전 점검 결과를 지우고 아직 점검 전인 상태로 되돌려(예: "AI 연결 점검 전").
- 자동으로 다시 점검하지 마. 다시 점검은 사용자가 버튼을 직접 누르는 것이라고 안내해.
renderExplanation 입력은 { event, explanation, checkedAt } 야. 지금은 explanation.status 가 ok 일 때 바깥 요소에 data-student-explanation-event 속성으로 event.id 를 붙이고, 사건 ID 와 explanation.data.summary 를 글자로 보여 줘. 실패면 안전한 code 와 message 를 보여 주고 기록은 그대로라고 적어. 실패 화면에는 data-student-explanation-event 를 붙이지 마.
textContent 만 써.
```

**스스로 확인**
1. 연결 전 점검 결과가 권한 준비 중으로 보이는지, 그것이 내 잘못으로 적히지 않는지 봅니다.
2. 점검 중 「취소」를 누르면 늦게 온 응답이 다시 나타나지 않는지 봅니다.
3. 계정 연결을 다시 하면 옛 점검 결과가 지워지는지 봅니다.
4. 화면·도움정보·커밋에 열쇠가 없는지 봅니다. 실수로 커밋했다면 바로 담당자에게 알리고 열쇠 교체를 요청합니다.

**공개 완료 기준(내부 제안, 공식 개방 전)**: student-source-changed, ai_transport_checked, ai_model_called, ai_auth_error, ai_limits, ai_manual_recovery, ai_generation_reset, secret_absence, ai_timeout_cancel. 모델 목록만 되고 실제 사건 설명 호출이 막히면 ai_model_called 는 통과하지 못합니다.

**다음 단계 조건**: 공식 제출·순서 권한이 열린 뒤에는, 기계 확인과 이 판의 필수 AI 기준 판정을 모두 통과하면 18단계가 열립니다. 실제 계정·권한이 준비되지 않아 생긴 실패는 기다림(UNV)이며 완료로 처리되지 않습니다.

---

## 18단계 · 근거가 있는 AI 사건 설명 (권장 10/27)

**목표**: AI 설명이 그 기록의 근거·규칙·현재 상태와 이어지게 보여 주고, 근거가 없으면 지어내지 않습니다.

**고칠 파일**: `renderExplanation` 을 완성합니다.

**받는 값**: `renderExplanation({ event, explanation, checkedAt })`
- event: 보안 기록에서 고른 기록(15단계와 같은 모양) 또는 null
- explanation: `{ status, mode, data?, error? }`, data 는 `{ summary, evidenceIds, proposals:[{action,evidenceIds,reason}], requiresHumanConfirmation:true, executed:false }`
- 제공 코드가 이미 검사한 것: 모든 근거 ID 를 빠짐없이 인용했는지, 없는 ID·중복·지원하지 않는 조치·비밀 표기·executed:true 가 없는지. 맞지 않으면 학생 함수에는 실패로 전달됩니다.

**지금 알아 둘 것**
- 지금 기록의 supportedActions 는 비어 있어서 AI 제안은 0개가 정상입니다. 이때는 원천이 지원하는 조치가 없어 제안이 없다고 안내합니다.
- AI 설명은 해석입니다. 사실 판단은 근거 글과 원천이 알려 준 상태로 합니다. unknown 은 확인 불가이며 안전이나 정상으로 바꾸지 않습니다.
- AI 연결이 실패해도 업무 앱 판정과 보안 기록은 계속 동작해야 합니다.

**상태별 표시**

| 상황 | 보여 줄 것 |
|---|---|
| event 없음 | 기록을 먼저 고르라는 안내 |
| loading | 설명 요청 중 |
| ok | 사건 ID, AI 요약, 인용한 근거 ID 와 근거 글, 규칙 글, 확인 불가 상태 목록, 제안(없으면 없는 까닭) |
| error | 설명 실패와 message. 기록은 그대로이며 과제 실패가 아님 |

**AI 에게 붙여 넣을 프롬프트**

```
student/extension.mjs 의 renderExplanation 을 완성해 줘. 앞 단계 함수는 그대로 둬.
입력은 { event, explanation, checkedAt } 야.
- event 가 null 이면 보안 기록에서 기록을 먼저 고르라는 안내(예: "보안 기록에서 기록을 먼저 고르세요").
- explanation.status 가 ok 면 바깥 요소에 data-student-explanation-event 속성으로 event.id 를 붙이고 다음을 보여 줘:
  1) 사건 ID(event.id)를 글자로, AI 설명이 참고용이라는 제목(예: "AI 설명(참고용)")과 explanation.data.summary
  2) evidenceIds 마다 event.evidence 에서 같은 id 를 찾아 "근거 ID — 근거 글"
  3) event.rules 마다 "규칙 ID — 규칙 글"(id 와 text 를 함께)
  4) event.state 에서 unknown 인 항목을 접속·세션·기기별로 나눠, 확인할 수 없다는 것과 원래 값(unknown)을 함께 나열(예: "접속: 확인 불가(unknown)", 없으면 "없음"). 확인할 수 없는 상태를 정상·안전으로 적지 마.
  5) proposals 가 비었으면 제안이 없는 까닭을 알려 줘. event.supportedActions 가 비었으면 원천이 지원하는 조치가 없어 제안이 없는 것이 정상이라는 것, 아니면 AI 가 제안한 조치가 없다는 것(예: "원천이 지원하는 조치가 없어 제안이 없습니다(정상)")
  6) proposals 가 있으면 각 action 과 reason, 그리고 사람이 확인해야 실행되며 아직 실행되지 않았다는 것(예: "사람 확인이 필요하며 실행되지 않았습니다")
- 근거 ID 가 event.evidence 에 없으면 그 설명을 쓸 수 없다는 것과 까닭(근거가 맞지 않음)을 보여 주고 내용을 지어내지 마. 안전한 error.code 가 있으면 함께 보여 줘.
- error 면 AI 설명이 실패했다는 것과 안전한 error.code·message, 그리고 기록은 그대로라는 것을 보여 줘(예: "AI 설명 실패: ", "기록은 그대로입니다"). AI 가 이미 실행했다고 답한 설명은 쓸 수 없다고 보여 줘.
- 실패·자료 없음·근거 불일치 화면에는 data-student-explanation-event 를 붙이지 마. 성공 표식은 성공한 설명에만 붙여.
- 다른 기록을 고르거나 다시 불러오면 이전 설명을 지워.
- 실행 버튼은 만들지 마. textContent 만 써.
```

**스스로 확인**
1. 서로 다른 기록 두 개로 설명을 받아, 근거·규칙이 각 기록 것과 맞는지 봅니다.
2. unknown 상태가 있는 기록에서 확인 불가가 보이는지 봅니다.
3. 설명 요청 중 다른 기록을 고르면 늦게 온 설명이 엉뚱한 기록에 붙지 않는지 봅니다.
4. AI 가 실패해도 업무 앱 판정과 기록 목록이 그대로 되는지 봅니다.

**공개 완료 기준(내부 제안, 공식 개방 전)**: student-source-changed, evidence_binding, unknown_evidence, insufficient_evidence, wrong_event_rejected, proposal_not_executed, non_ai_regression, explanation_refresh. data-student-explanation-event 속성만 붙였다고 통과하지 않습니다. 확인 도구가 사건·근거·규칙·상태를 무작위로 바꿔 내용이 따라 바뀌는지 봅니다.

**다음 단계 조건**: 공식 제출·순서 권한이 열린 뒤에는, 기계 확인과 이 판의 필수 AI 기준 판정을 모두 통과하면 19단계가 열립니다. 실제 AI 설명 성공 확인은 17단계 권한이 준비될 때까지 기다림(UNV)입니다.

---

## 19단계 · AI 조치 제안과 서버 처리 결과 (권장 10/28)

**목표**: AI 제안과 실제 처리를 나눕니다. 서버가 지원하는 조치만 사람 확인 → 서버 전달 → 서버 결과 재조회 순서로 처리되며, 학생 화면은 그 상태를 정확히 보여 줍니다.

**고칠 파일**: `renderAction`.

**제공 화면이 하는 일**: AI 제안의 「조치 준비」, 실제 대상과 확인 기한 표시, 「대상과 조치를 확인했으며 집행합니다」, 「원천 결과만 재조회」, 「조치 화면 취소」. 확인 티켓은 제공 화면 메모리에만 있고 학생 함수에는 전달되지 않습니다.

**받는 값**: `renderAction({ status, event, actionId, target, receipt, observation, message, confirmationExpiresAt?, error? })`
- status: idle·loading·executing·prepared·pending·succeeded·denied·failed·unknown·error·expired
- target: `{ id, generation }` 또는 null. receipt: requestId·receiptId·eventId·actionId·status·version·replayed 등
- observation: `{ observedAt, effectApplied }` 또는 null

**지금 알아 둘 것**
- 지금 기록에는 원천이 지원하는 조치가 없어(supportedActions 빈 배열) 실제 처리 경로가 열리지 않습니다. 화면에 조치 준비 버튼이 나오지 않는 것이 정상입니다.
- 이 단계의 현재 내부 자동 확인은 시험용 원천에서 학생 화면이 제안·사람 확인·ACK·효과 관측을 구분하는지 확인하는 학습 계약입니다. 이 결과만으로 실제 학생의 SDP 권한·대상·집행·결과 재조회가 연결되었다고 인정하지 않습니다.
- 전체 구현 목표에는 실제 원천 집행기 연결과, 같은 학생·프로젝트·대상에 대한 실행 결과 확인이 계속 포함됩니다. 그 부분은 지금 미완료입니다. 운영자 담당이라는 이유로 전체 완료 조건에서 빼지 않습니다. 다만 학생 개인에게 운영자 자격 발급이나 집행기 구축을 요구하지는 않습니다.
- 실제 학생 계정의 조치 처리 결과는 기다림(UNV)입니다.

**상태별 표시**

| status | 뜻 | 보여 줄 것 |
|---|---|---|
| idle | 아직 아무것도 안 함 | 아직 미실행 |
| prepared | 준비만 됨 | 준비됨·미실행, 사건·근거 ID·조치·실제 대상·확인 기한 |
| executing | 서버에 전달 중 | 서버에 전달 중(executing). 결과가 아직 없음 |
| pending | 서버가 받음 | 서버 접수·처리 중(pending). 서버가 받았다는 것(ACK)은 효과가 아님 |
| succeeded | 원천이 효과를 확인 | observation.effectApplied 가 true 일 때만 "효과 확인(succeeded)", 관측 시각, effectApplied: true, receiptId |
| denied / failed | 원천 거절 / 실패 | 거절·실패와 message |
| unknown | 결과 불명 | 효과 없음으로도 성공으로도 판단하지 말고 결과만 재조회하라고 안내 |
| expired | 확인 기한 지남 | 다시 준비하라고 안내 |
| error | 요청이 처리되지 않음 | error.message |

**AI 에게 붙여 넣을 프롬프트**

```
student/extension.mjs 의 renderAction 을 구현해 줘. 앞 단계 함수는 그대로 둬.
입력은 { status, event, actionId, target, receipt, observation, message, confirmationExpiresAt, error } 야.
- status 마다 뜻이 다른 문장을 원래 값과 함께 보여 줘. 예: idle=아직 미실행, prepared=준비됨·미실행(확인 기한 confirmationExpiresAt 을 함께), executing=서버에 전달 중(executing), pending=서버 접수·처리 중(pending), succeeded=효과 확인(succeeded), denied=거절(denied), failed=실패(failed), unknown=결과 불명(unknown)·효과 없음으로 판단 금지, expired=확인 기한 지남(expired)·다시 준비, error=요청 처리 안 됨과 안전한 error.code·message.
- executing·pending 화면은 서버에 전달 중이거나 서버가 받아 처리 중이라는 상태만 전해 줘. 결과가 아직 확인되지 않았다는 것이 드러나야 하고, 읽는 사람이 끝났거나 성공했다고 받아들일 문장은 쓰지 마. "완료 아님"처럼 부정하는 문장은 오해 없이 읽히면 괜찮아.
- succeeded 는 observation.effectApplied 가 true 일 때만 "효과 확인(succeeded)" 과 관측 시각 observation.observedAt, "effectApplied: true" 를 함께 보여 줘. 아니면 결과 불명으로.
- 현재 사건의 event.id 와 근거 ID(event.evidence 의 id), actionId, target.id 와 target.generation, receipt.requestId, receipt.receiptId, receipt.version 을 있는 것만 글자로 보여 줘.
- 성공적으로 그린 바깥 요소에 data-student-action-event 로 event.id, data-student-action-request 로 receipt.requestId 를 붙여.
- 확인 번호 같은 값은 입력에 없으니 만들거나 저장하지 마. 버튼을 만들지 말고 제공 화면 버튼을 쓰게 안내해.
- 새 값이 오면 이전 표시를 모두 지우고 다시 그려. textContent 만 써.
```

**스스로 확인**
1. 지금 기록에서 조치 준비 버튼이 나오지 않고, 그것이 정상이라는 안내가 보이는지 봅니다.
2. 학생 칸이 status 마다 다른 문장을 보여 주는지, 원천 효과가 없을 때 성공으로 보이지 않는지 코드로 다시 읽어 봅니다.
3. 다시 불러오기나 다른 기록 선택 뒤 이전 조치 표시가 지워지는지 봅니다.

**공개 완료 기준(내부 제안, 공식 개방 전)**: student-source-changed, proposal_execution_separation, human_confirmation, current_intent_binding, observed_server_result, duplicate_prevention, unknown_not_success, action_refresh. 속성만 붙여서는 통과하지 않습니다.

**다음 단계 조건**: 공식 제출·순서 권한이 열린 뒤에는, 기계 확인과 이 판의 필수 AI 기준 판정을 모두 통과하면 20단계가 열립니다. 이 통과는 화면 학습 계약의 통과이며, 실제 원천 집행 연결이 끝났다는 뜻이 아닙니다.

---

## 20단계 · 사용 라이브러리와 취약점 정보 대조 (권장 10/29)

**목표**: 프로젝트에 실제 설치된 패키지의 정확한 버전을 OSV 취약점 정보와 대조하고, 출처·확인 시각·실패를 구분해 보여 줍니다.

**고칠 파일**: `renderVulnerabilities`. 패키지를 바꾸기 전에 커밋합니다.

**받는 값**: `renderVulnerabilities({ status, mode, data?, error? })`. status 는 idle·loading·error·ok 입니다.
- data.status(전체 조회 상태): `complete`(모두 조회) · `partial`(일부 조회 실패) · `not_checked`(아직 조회 안 함) · `not_configured`(프로젝트 설정 없음) · `unverifiable`(lock 파일 확인 불가)
- data: lockfileVersion, lockfileHash, checkedAt, packages(설정·확인 불가일 때는 빈 배열)
- packages: `[{ name, version, status, vulnerabilities, source, checkedAt }]`, status: `known_vulnerabilities` · `none_found` · `unverifiable`

**지금 알아 둘 것**
- 서버는 프로젝트의 package-lock.json 과 담당자가 허용한 공개 패키지만 조회합니다. 허용 목록이 비어 있으면 not_configured·not_checked 가 나오는 것이 정상입니다.
- 조회 실패와 미조회는 "취약점 없음"이 아닙니다.
- 일부 조회에서 이미 받은 취약점 ID 는 지우지 않고 보여 줍니다.
- `^1.2.0` 같은 범위가 아니라 실제 설치 버전을 씁니다. 회사·비공개 패키지 이름을 밖으로 보내 확인하지 않습니다.

**AI 에게 붙여 넣을 프롬프트**

```
student/extension.mjs 의 renderVulnerabilities 를 구현해 줘. 앞 단계 함수는 그대로 둬.
입력은 { status, mode, data?, error? } 야.
- status 가 idle 이면 아직 조회 전이라는 것, loading 이면 조회 중이라는 것, error 면 조회가 실패했다는 것과 message 를 보여 줘(예: "조회 전", "조회 중", "조회 실패: "). 오류·조회 중일 때 이전 표를 현재 결과처럼 남기지 마.
- ok 면 data.status 를 원래 값과 함께 뜻을 글자로 보여 줘. 예: 모두 조회(complete), 일부 조회 실패(partial), 아직 조회 안 함(not_checked), 조회 준비 미완료(not_configured), lock 파일 확인 불가(unverifiable).
- 전체 결과에 data.lockfileVersion, data.lockfileHash, data.checkedAt 을 함께 보여 줘. 패키지를 바꾼 뒤 다시 조회하면 새 lockfileHash 로 바뀌어야 해.
- data.packages 의 각 행에 name, version(설치된 정확한 버전), status, source, checkedAt 을 보여 주고, 취약점마다 id 와 modified(수정 시각)를 함께 보여 줘.
  known_vulnerabilities=알려진 항목 있음, none_found=알려진 항목 없음, unverifiable=조회 확인 불가. unverifiable 인데 vulnerabilities 가 있으면 일부만 확인됐고 전체 조회는 확인할 수 없다는 것을 보여 주고(예: "일부 확인·전체 조회 확인 불가") 받은 ID 는 지우지 마.
- 각 행 요소에 data-student-package-name 과 data-student-package-version 을 붙여.
- 조회 실패를 "취약점 없음" 으로 보이게 하지 마. textContent 만 써.
```

**스스로 확인**
1. 보호 현황의 설치 패키지 조회를 눌러 결과가 학생 칸에도 같은 값으로 보이는지 봅니다.
2. 조회 중 취소를 누르고 늦은 응답이 다시 나타나지 않는지 봅니다.
3. 오류 뒤 직접 다시 조회하면 새 요청이 나가는지 봅니다(네트워크 탭).
4. package-lock.json 의 버전과 화면의 버전이 같은지 한두 개 대조합니다.

**공개 완료 기준(내부 제안, 공식 개방 전)**: student-source-changed, exact_lock_version, osv_match, lookup_unavailable, no_results_distinction, partial_preservation, refresh_replaces, request_recovery, stale_response_blocked. 속성만 붙여서는 통과하지 않습니다.

**다음 단계 조건**: 공식 제출·순서 권한이 열린 뒤에는, 기계 확인과 이 판의 필수 AI 기준 판정을 모두 통과하면 21단계가 열립니다. 17~19를 통과하지 않았으면 20단계 검사만으로 다음 단계로 가지 않습니다.

---

## 21단계 · 설명서와 구성도 (권장 11/2)

**목표**: 다른 사람이 설명서만 보고 설치·실행·문제 해결을 할 수 있게 하고, 실제로 되는 것과 아직 안 되는 것을 정직하게 적습니다.

**고칠 파일**: 학생 설명서(예: `README.md` 의 학생 부분 또는 `docs/` 아래 학생 문서)와 구성도. 제공 문서는 고치지 않습니다.

**설명서에 들어갈 것**
1. 설치·실행 순서. 새 PowerShell 창에서 그대로 따라 할 수 있게, 실제로 확인한 명령만 씁니다.
2. 구성도. 브라우저 – 앱 서버 – 기존 접속·XDR 서버 – CLCO 수업용 AI 의 관계를 글이나 직접 그린 그림으로 보여 줍니다. 상자마다 실제 파일이나 주소를 하나씩 적습니다.
3. 제공 코드와 내가 만든 부분의 구분. 제공/학생 영역 목록(manifest)을 기준으로, 내가 만든 함수와 화면을 설명합니다.
4. 실패별 해결 안내. 연결 없음, 권한 준비 중, 확인 불가, 조회 실패 등 화면에 실제로 나오는 문구를 적고, 무엇을 확인하면 되는지 씁니다.
5. 지원 범위. 실제로 확인한 기능과 기다림(UNV) 항목을 나눠 적습니다. 확인하지 않은 인증·조치 실행·OSV 결과를 있는 것처럼 쓰지 않습니다.

**AI 에게 붙여 넣을 프롬프트**

```
이 프로젝트의 학생 설명서를 써 줘. 제공 문서는 고치지 말고 학생 문서 파일을 새로 만들어.
- 내가 실제로 실행해 본 명령만 써. 모르는 명령은 "확인 필요" 로 남겨.
- 구성도는 브라우저, 앱 서버, 기존 접속·XDR 서버, CLCO 수업용 AI 네 상자로 그리고 상자마다 실제 파일 경로나 주소를 하나씩 적어.
- student/extension.mjs 에서 내가 구현한 함수(renderIdentity 부터 renderVulnerabilities 까지)가 각각 무엇을 보여 주는지 한두 문장씩 설명해.
- 화면에 나오는 실패 문구마다 원인과 확인할 것을 표로 정리해.
- 아직 실제로 확인하지 못한 기능은 "기다림(UNV)" 목록으로 따로 적어. 열쇠나 비밀 값은 절대 넣지 마.
```

**스스로 확인**: 설명서만 보고 새 PowerShell 창에서 순서대로 실행해 앱이 뜨는지 봅니다. 구성도의 상자마다 적은 파일·주소가 실제로 응답하는지 확인하고, 확인하지 못한 상자는 확인 안 됨으로 남깁니다.

**공개 완료 기준(제안)**: 공개 목표는 run_instructions, architecture, provided_student_boundary, failure_guide 입니다. 자동 확인은 현재 소스 결속, 학생 문서 변경, 알려진 비밀 패턴 검사, 관측 설정 대조, 문서 명령 실제 실행을 봅니다. 접수·공식 완료 연결은 아직 남아 있습니다. 문서의 글 품질은 AI 피드백으로 따로 오며 통과를 되돌리지 않습니다.

**다음 단계 조건**: 공식 제출·순서 권한이 열린 뒤에는, 자동 확인을 통과하면 22단계가 열립니다.

---

## 22단계 · 새 환경 실행과 버전 기록 (권장 11/3)

**목표**: 새 폴더에서 최종 버전을 설치·실행해, 13~21단계에서 만든 것이 실제로 다시 되는지 확인하고 확인한 범위를 버전과 함께 기록합니다. v1.0 표시는 아래 완료 조건을 모두 채웠을 때만 합니다.

**고칠 파일**: 새 환경 실행 기록 문서와 버전 표시. 기존 폴더의 파일과 기록은 그대로 둡니다.

**순서**
1. 기존 폴더는 그대로 두고, 저장소를 새 빈 폴더에 내려받습니다.
2. 설명서대로 Node.js 를 확인하고 앱을 실행합니다.
3. 13~20단계 기능을 하나씩 눌러 결과를 재현됨 · 재현 안 됨 · 연결 없음 · 확인 불가로 적습니다.
4. 끄고 다시 켠 뒤에도 같은 결과인지 봅니다.
5. demo 결과와 연결 없음은 실제 연결 재현으로 적지 않습니다. 기다림(UNV) 항목은 재현 완료로 적지 않습니다.

**AI 에게 붙여 넣을 프롬프트**

```
새 환경 실행 기록 문서를 만들어 줘. 표는 단계(13~21), 확인한 기능, 결과(재현됨/재현 안 됨/연결 없음/확인 불가), 확인 시각, 비고 다섯 칸이야.
내가 직접 확인해서 불러 주는 결과만 적고, 내가 말하지 않은 칸은 "미확인" 으로 둬.
demo 결과는 "예제 자료" 라고 비고에 적고 재현됨으로 쓰지 마.
실제로 확인한 범위를 먼저 적고, 지금 미완료 항목이 있으면 검증 중인 버전으로 기록해 줘. 19단계의 실제 실행 연결과 22단계의 같은 최종 소스 누적 재현·공식 접수 연결까지 완료·수용된 경우에만 v1.0 으로 표시해 줘. 기다림(UNV) 항목은 따로 모아 줘.
```

**공개 완료 기준(제안)**: 공개 목표는 clean_environment, cumulative_behavior, data_preservation, release_reproduction 입니다. 같은 최종 소스로 13~20 전체와 새 환경 실행을 함께 확인하는 자동 확인이 제안돼 있으며, 실제 연결은 아직 남아 있습니다. 서로 다른 시험 소스로 따로 통과한 결과를 합쳐 같은 최종 소스의 완료로 세지 않습니다.

**마친 뒤**: 위 완료 조건을 채우고 공식 완료가 확인되면 기본 과정이 끝납니다. 지금은 19단계 실제 실행 연결과 21·22단계 공식 접수 연결이 남아 있어, 그 전에는 v1.0 을 붙이지 않습니다. MCP 연동은 기본 완성 뒤의 선택 과제이며 가산 여부는 아직 정해지지 않았습니다.

---

## R4 확인 대응표(이 판 전용)

판 이름: 학생 안내 v0.6(이 문서 첫 줄)와 docs/CURRICULUM_R4_V06_OFFICIAL.json(version 0.6.0-r4-official)이 한 쌍입니다. 단계별 판정 판은 13~20 모두 claimRevision 4 의 checker·rubric 판(예: 13단계 on-pc-13-0.4 / on-13-proposal-0.4)입니다.
「기계」는 고정 값·요청 수·화면 구조처럼 결정적으로 확인합니다. 「뜻」은 아래의 원 질문으로 서버 AI가 과제 원문·학생 원문·전체 실행 관측을 함께 읽는 필수 기준 판정입니다. 「기계 + 뜻」인 검사는 결정적 확인이 하나라도 어긋나면 그대로 실패이고, 모두 맞으면 AI 판정까지 기다립니다. 필요한 판정이 보류인 동안은 통과로 확정하지 않습니다.

| 단계 | 검사 | 확인 | 뜻 질문(키: 질문) |
|---|---|---|---|
| 13 | student-source-changed | 기계 | — |
| 13 | three-menus | 기계 | — |
| 13 | student-identity-updates | 기계 | — |
| 13 | student-failure-visible | 기계 + 뜻 | q13.failure_visible: 서버 연결에 실패했을 때 학생 신원 칸이 연결 실패나 신원을 불러올 수 없다는 것을 보여 주는가? |
| 13 | identity-after-reload | 기계 | — |
| 14 | student-source-changed | 기계 | — |
| 14 | server-decisions-distinct | 기계 | — |
| 14 | decision-reason-visible | 기계 | — |
| 14 | unknown-not-allow | 기계 + 뜻 | q14.unknown_not_allowed: 판정이 unknown 으로 온 요청을 허용됐거나 정상인 것처럼 보여 주지 않는가? |
| 14 | failure-not-allow | 기계 + 뜻 | q14.failure_shown: 판정 요청이 실패했을 때 실패했거나 판정을 받을 수 없다는 것을 보여 주는가?<br>q14.failure_not_allowed: 판정 요청이 실패한 화면이 접근이 허용됐거나 정상인 것처럼 보여 주지 않는가? |
| 15 | student-source-changed | 기계 | — |
| 15 | event_scope | 기계 + 뜻 | q15.event_kind: 기록 목록의 각 줄이 접속 기록인지 XDR 기록인지 종류를 알아볼 수 있게 보여 주는가? 기대 종류는 관측 사실 expected.kind 에 있다. |
| 15 | event_time | 기계 + 뜻 | q15.event_time: 기록 목록의 각 줄이 그 기록의 발생 시각을 보여 주는가? 기대 시각은 관측 사실 expected.at 에 있고 한국 시각 표기도 인정한다. |
| 15 | event_filter | 기계 | — |
| 15 | event_detail | 기계 | — |
| 15 | events-refresh-replaces | 기계 | — |
| 15 | events-empty-error-distinct | 기계 + 뜻 | q15.empty_shown: 기록이 하나도 없을 때 기록이 없다는 것을 보여 주는가?<br>q15.empty_not_error: 기록이 없는 화면을 실패·오류처럼 보여 주지 않는가?<br>q15.error_shown: 기록을 불러오지 못했을 때 실패·오류나 연결 문제임을 보여 주는가? |
| 16 | student-source-changed | 기계 | — |
| 16 | devices-sessions-refresh | 기계 + 뜻 | q16.status_attention: 갱신된 기기·세션 상태 가운데 만료된 세션처럼 주의·확인이 필요한 상태를 알아볼 수 있게 보여 주는가? |
| 16 | notifications | 기계 + 뜻 | q16.failure_notice: 기기 정보를 불러오지 못했을 때 기기 쪽 문제라는 알림을 보여 주는가?<br>q16.failure_next_step: 그 알림이 연결 상태를 확인하라는 등 학생이 할 일을 안내하는가? |
| 16 | loading_empty | 기계 + 뜻 | q16.empty_shown: 기기와 세션이 하나도 없을 때 기기·세션이 각각 없다는 것을 보여 주는가?<br>q16.empty_not_error: 기기·세션이 없는 화면을 실패·오류처럼 보여 주지 않는가?<br>q16.error_shown: 기기 정보를 불러오지 못했을 때 실패·오류나 연결 문제임을 보여 주는가?<br>q16.loading_shown: 기기 정보를 불러오는 동안 불러오는 중임을 보여 주는가? |
| 16 | retry | 기계 + 뜻 | q16.timeout_shown: 기기 정보 요청이 시간 안에 끝나지 않았을 때 시간 초과임을 보여 주는가?<br>q16.recovered_no_timeout: 다시 불러와 성공한 뒤 이전 시간 초과 안내가 남아 있지 않은가? |
| 16 | diagnostics_redaction | 기계 + 뜻 | q16.diagnostics_help: 진단 정보 화면이 도움 요청에 쓰도록 복사할 수 있는 정보임을 안내하는가? |
| 16 | unsupported_action | 기계 + 뜻 | q16.unsupported_shown: 지원하지 않는 조치 버튼에 아직 지원하지 않는다(준비 중)는 것을 보여 주는가?<br>q16.unsupported_not_success: 지원하지 않는 조치를 실행에 성공했거나 집행이 끝난 것처럼 보여 주지 않는가? |
| 17 | student-source-changed | 기계 | — |
| 17 | ai_transport_checked | 기계 + 뜻 | q17.model_count_label: 연결 점검 결과 문구가 받은 모델 수를 모델 수로 알아볼 수 있게 보여 주는가?<br>q17.explanation_not_run: 연결 점검 결과 문구가 연결만 점검했고 사건 설명은 아직 실행하지 않았다는 것을 구분해 보여 주는가?<br>q17.no_explanation_success: 다시 점검한 결과 문구가 실제 AI 사건 설명이나 게이트 처리가 성공·완료됐다고 주장하지 않는가? |
| 17 | ai_model_called | 기계 | — |
| 17 | ai_auth_error | 기계 + 뜻 | q17.auth_error_explained: 오류 코드와 함께 준비·권한·인증 가운데 어떤 문제인지 학생이 알 수 있게 안내하는가?<br>q17.auth_error_not_success: 인증·권한 오류 화면이 점검이나 연결이 성공했다고, 또는 이전 성공 결과(모델 수)를 그대로 보여 주지 않는가? |
| 17 | ai_limits | 기계 + 뜻 | q17.limit_explained: 오류 코드와 함께 사용량·한도·제한·시간 문제임을 학생이 알 수 있게 안내하는가? |
| 17 | ai_manual_recovery | 기계 + 뜻 | q17.recovered_no_auth_error: 다시 점검해 성공한 뒤 화면에 이전 인증 오류 안내가 남아 있지 않은가? |
| 17 | ai_generation_reset | 기계 + 뜻 | q17.reset_idle: 새로고침 뒤 연결 점검이 아직 실행 전(대기) 상태임을 보여 주는가?<br>q17.reset_no_stale_success: 새로고침 뒤 화면이 이전 점검 결과(모델 수·권한 확인 완료 등)를 그대로 남겨 성공처럼 보이지 않는가? |
| 17 | secret_absence | 기계 | — |
| 17 | ai_timeout_cancel | 기계 + 뜻 | q17.timeout_explained: 응답이 늦어 끝난 경우 시간 초과임을 학생이 알 수 있게 보여 주는가?<br>q17.cancel_explained: 학생이 점검을 취소한 경우 취소됐음을 보여 주는가?<br>q17.cancel_not_success: 취소한 뒤 화면이 점검·연결 성공이나 이전 모델 수를 보여 주지 않는가? |
| 18 | student-source-changed | 기계 | — |
| 18 | evidence_binding | 기계 | — |
| 18 | unknown_evidence | 기계 + 뜻 | q18.state_labels: 근거가 확인되지 않은 사건 설명이 접속·세션·기기 상태를 각각 구분해 보여 주는가?<br>q18.unknown_not_confirmed: 상태가 unknown 인 사건을 확인할 수 없다고 보여 주는가?<br>q18.unknown_not_safe: 상태가 unknown 인 사건을 정상·안전·기준 충족으로 단정하지 않는가? |
| 18 | insufficient_evidence | 기계 + 뜻 | q18.insufficient_rejected: 근거가 없는 사건의 설명 요청을 설명할 수 없다(근거 부족·입력 오류)고 보여 주는가? |
| 18 | wrong_event_rejected | 기계 + 뜻 | q18.bad_output_rejected: AI 가 틀린 근거·빠진 근거·비밀값을 낸 경우 그 설명을 쓸 수 없다고 보여 주는가? |
| 18 | proposal_not_executed | 기계 + 뜻 | q18.proposal_not_executed: AI 설명의 조치 제안이 아직 실행되지 않았다는 것을 보여 주는가?<br>q18.human_confirmation: 조치 제안은 사람이 확인해야 실행된다는 것을 보여 주는가?<br>q18.executed_output_rejected: AI 가 이미 실행했다고 답한 설명을 쓸 수 없다고 보여 주는가? |
| 18 | non_ai_regression | 기계 | — |
| 18 | explanation_refresh | 기계 | — |
| 19 | student-source-changed | 기계 | — |
| 19 | proposal_execution_separation | 기계 + 뜻 | q19.proposal_not_success: AI 조치 제안만 받은 화면이 아직 실행하지 않았음을 보여 주고, 실행이 성공·완료됐다고 주장하지 않는가? |
| 19 | human_confirmation | 기계 + 뜻 | q19.prepared_shown: 실행 준비 단계에서 준비됐다는 상태를 보여 주는가?<br>q19.prepared_not_run: 실행 준비 단계에서 아직 실행하지 않았음을 보여 주는가? |
| 19 | current_intent_binding | 기계 + 뜻 | q19.intent_expiry: 실행 대상과 함께 확인 기한이나 확인이 필요하다는 것을 보여 주는가? |
| 19 | observed_server_result | 기계 + 뜻 | q19.ack_not_success: 실행 요청 직후(서버가 처리 중일 때) 화면이 결과를 확인하기 전에 성공·완료를 주장하지 않고 처리 중임을 보여 주는가?<br>q19.result_observed: 서버에서 조회한 실행 결과가 실제로 관측한 결과임을 보여 주는가? |
| 19 | duplicate_prevention | 기계 | — |
| 19 | unknown_not_success | 기계 + 뜻 | q19.unknown_not_success: 처리 결과를 알 수 없는 경우 결과 불명으로 보여 주고, 성공·완료나 효과 없음으로 단정하지 않는가? |
| 19 | action_refresh | 기계 + 뜻 | q19.refresh_no_stale: 새로고침하거나 화면을 다시 불러온 뒤 이전 조치 결과를 지우고 아직 미실행임을 보여 주는가? 초기화나 부정을 설명한 상태 낱말 자체를 이전 결과로 판단하지 않는다. |
| 20 | student-source-changed | 기계 | — |
| 20 | exact_lock_version | 기계 + 뜻 | q20.exact_installed_version: 패키지 행이 설치된 정확한 버전을 조회한 결과임을 보여 주는가? 범위 표기와의 차이를 설명한 문구 자체를 범위 버전 사용으로 판단하지 않는다. |
| 20 | osv_match | 기계 + 뜻 | q20.known_vulnerability: 취약점이 있는 패키지에 알려진 취약점이 있다고 보여 주는가? |
| 20 | lookup_unavailable | 기계 + 뜻 | q20.not_configured: 프로젝트가 설정되지 않은 경우 준비·미설정 상태임을 보여 주는가?<br>q20.not_checked: 승인된 패키지가 없어 조회하지 않은 경우 아직 조회하지 않았음을 보여 주는가?<br>q20.unavailable_not_clean: 설정 안 됨·미조회 상태를 취약점 없음으로 보여 주지 않는가? |
| 20 | no_results_distinction | 기계 + 뜻 | q20.none_found: 조회했지만 알려진 취약점이 없는 패키지를 그렇게 보여 주는가?<br>q20.unverifiable_row: 조회하지 못한 패키지를 확인 불가로 보여 주는가?<br>q20.unverifiable_not_clean: 조회하지 못한 패키지를 취약점 없음·정상·안전으로 보여 주지 않는가? |
| 20 | partial_preservation | 기계 + 뜻 | q20.partial_shown: 일부만 조회된 결과를 일부 결과라고 보여 주는가?<br>q20.unverifiable_row: 조회하지 못한 패키지를 확인 불가로 보여 주는가? |
| 20 | refresh_replaces | 기계 | — |
| 20 | request_recovery | 기계 + 뜻 | q20.request_failed: 조회 요청이 실패한 경우 실패·오류임을 보여 주는가? |
| 20 | stale_response_blocked | 기계 + 뜻 | q20.cancelled_not_clean: 취소한 조회를 취약점 없음·정상·안전으로 보여 주지 않는가? |
