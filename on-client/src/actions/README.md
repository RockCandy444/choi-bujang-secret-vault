# 케셰브 조치 모듈 — 로컬 준비

`createActionService`는 기존 애플리케이션 SQLite 경로와 서버 소유 신원·조치 엔진 hook을 명시적으로 받아 prepare/execute/readResult를 제공한다. 로컬 HTTP와 PC의 사람 확인·결과 조회 화면에 연결했고 독립 검수했다. 기본 실행은 조치 미지원이며 실제 원천 권한·공식19단계 완료를 부여하지 않는다. AI service는 이 모듈을 호출하지 않는다.

```js
createActionService({engine, resolveContext, databasePath, policy, clock})
service.prepare({eventId,actionId},{signal})
service.execute({requestId,confirmationId},{signal})
service.readResult({requestId},{signal})
```

databasePath는 이미 존재하는 절대 경로의 단일 일반 SQLite 파일이어야 한다. symlink·hardlink·없는 파일·상대 경로는 거절한다. 새 DB를 생성하지 않고 supplied application DB에 `alekov_action_intents/state/audit`만 추가한다. 초기 정책·resolver·readEvents/authorizeAction/executeAction/readActionResult가 없으면 파일을 열지 않고 `ACTION_UNSUPPORTED`다. 기존 학생 사건·승인·감사 테이블을 읽거나 수정하지 않는다.

policy의 정확한 필드는 `appId:'aleph-on'`, `audience:'on-client'`, `accessPolicyId`, 중복 없는 `allowedActions`, 양의 안전한 정수 `confirmationTtlMs`, 선택적 `timeoutMs`다. timeout 기본은 10,000ms다. 여분 정책 필드는 설정으로 인정하지 않는다. 설정한 기간은 학습 권장 기한·감점 정책이 아니다.

resolveContext({signal})는 현재 서버가 검증한 **정확한 아홉 필드**를 반환한다.

```js
{subjectId,projectId,sessionId,identityVersion,appId:'aleph-on',audience:'on-client',
 accessPolicyId,engineGeneration,sourcePolicyVersion}
```

identityVersion/engineGeneration은 양의 안전한 정수다. 신원·session·권한/엔진 세대를 임의 합성하지 않는다. 각 async await 뒤 resolver를 다시 읽어 최초 사본과 대조한다. permission/grant/access 변경은 sourcePolicyVersion 또는 engineGeneration 등 검증된 context 세대로 반영해야 하며 실제 원천에서 이 결속을 만들지 못하면 연결을 허용하지 않는다.

readEvents(scope,{signal})의 각 event는 기존 `id,kind,at,summary,evidence:[{id,text}],rules:[{id,text}],state,supportedActions`와 `subjectId,projectId,target:{id,generation}`를 정확히 가진다. target ID는 `subject:...` 또는 `device:...`, generation은 양의 안전한 정수다. read 전후 신원과 모든 반환 행의 subject/project를 검증한다. 대상·근거·규칙·상태·조치 목록은 digest에 들어가므로 이전 intent의 snapshot이 바뀌면 재사용할 수 없다. 기록은 immutable historical snapshot이어야 한다. 결과 관측은 readActionResult에서 별도로 읽는다.

authorizeAction(command,scope,{signal})의 응답은 다음 정확한 형태다.

```js
{allowed:boolean,durableOperations:boolean,context:scope,eventId,actionId,target,snapshotDigest}
```

context/event/action/target/digest가 command와 같고 allowed/durableOperations가 모두 true여야 한다. 단순 true, supportedActions 목록, 요청 body의 approved 값은 권한이 아니다. source가 인증한 현재 principal·target·action·정책 세대를 대조하는 hook이어야 한다. 실제 학생을 operator로 승격하거나 관리자 토큰으로 연결하지 않는다.

executeAction에는 깊게 고정한 서버 명령 `{requestId,fingerprint,scope,eventId,actionId,target,snapshotDigest}`를 전달한다. prepare가 생성한 requestId는 logical operation UUID이며 HTTP 추적 ID가 아니다. 사람 확인 티켓은 `ac-on-` + 고엔트로피 43자이며 prepare 응답에 한 번만 반환한다. DB에는 도메인을 분리한 SHA-256만 저장한다. execute는 서버가 UI의 별도 사람 확인 동작을 인증·Origin 보호한 뒤 호출해야 한다. 티켓 소지만으로 HTTP principal이나 사용자 권한이 생기지 않는다. 이 모듈만으로 브라우저 사람 확인 UI·CSRF 보호가 구현됐다고 주장하지 않는다.

BEGIN IMMEDIATE 안에서 티켓 소비와 dispatch 예약을 먼저 기록한다. 같은 intent의 재전송은 같은 receiptId와 현재 상태를 반환하며 새 engine execute를 하지 않는다. 다른 신원·project·session·세대는 결과 공개도 거절한다. native SQLite는 busy 대기를 0으로 설정해 다른 writer가 잠그면 `ACTION_STORE_FAILED`로 실패 폐쇄하며 자동 재시도하지 않는다. 일시 busy에서 동일 영수증 반환을 보장하는 것은 아니며 원천 처리 수 1회 경계와 구분한다.

executeAction의 정확한 `{status:'accepted'}` ACK는 pending, `{status:'denied'}`는 denied, 그 외는 unknown이다. 성공 ACK나 임의 응답 필드는 succeeded를 만들지 못한다. readActionResult만 다음의 정확한 결속과 실제 effect 관측을 검증한다.

```js
{requestId,fingerprint,scope,eventId,actionId,target,snapshotDigest,
 status:'pending'|'succeeded'|'denied'|'failed'|'unknown',observedAt,
 effect:null|{applied:boolean,operationId:requestId,target,snapshotDigest}}
```

succeeded에는 applied=true와 정확한 operation/target/snapshot 결속이 필수다. observedAt은 intent 생성 이후·현재 clock 이전이어야 한다. 누락·여분·불일치·조회 실패·timeout은 unknown이다. 과거 succeeded 뒤 현재 조회가 timeout이면 이전 성공을 현재 확인 결과로 재사용하지 않고 unknown으로 갱신하되 성공 관측은 audit에 보존한다.

조회 시작 시 projection version을 포착하고 결과·오류·timeout 기록 직전에 같은 version인지 트랜잭션 안에서 확인한다. 그동안 다른 조회가 갱신했거나, 관측 시각이 더 오래됐거나, 같은 epoch의 status/effect가 충돌하면 최신 원장과 감사 이력을 덮지 않는다. 이 요청은 `status:'unknown', superseded:true`로 반환하며 과거 성공을 현재 확인으로 내보내지 않는다. 날짜 문자열은 epoch로 비교하고 저장할 관측 시각은 ISO로 정규화한다. 엔진의 ACK도 반환 직후 사본을 만든 뒤 신원을 재조회한다.

intent와 audit UPDATE/DELETE, projection DELETE를 trigger로 거절한다. projection version은 UPDATE마다 1씩 증가하며 준비·예약·ACK·관측을 별도 audit로 남긴다. 안전하게 투영한 effect observation은 immutable audit에도 저장한다. 기존 테이블의 rollback이나 전체 DB 복원은 하지 않는다. read 실패가 신원 변경 때문이면 옛 scope 영수증/결과를 공개하지 않는다.

dispatch 이후 cancel/timeout/응답 손실은 unknown이다. 늦게 실제 효과가 생길 수 있으며 취소했다고 효과 없음으로 단정하지 않는다. 재시작이나 다른 service instance에서 reserved/pending을 재전송하면 unknown으로 reconcile하고 결과 조회만 한다. constructor와 readResult는 자동 집행하지 않는다. 완전한 exactly-once는 원천 엔진의 durable key/result 계약까지 필요하며 localExecutor의 apply 자체는 이를 제공하지 않는다.

시험은 같은 checkout의 실제 `createLocalExecutor`를 격리된 기존 애플리케이션 SQLite의 test-only KV·operation wrapper에 연결해 실제 차단 효과를 관측한다. 이는 실제 제공 집행기의 로컬 효과 증거다. synthetic context/authority/durable wrapper는 production adapter나 실제 학생 권한의 증거가 아니다. memory-only fallback·admin token·공급사·운영 DB를 사용하지 않는다.

대표 오류 코드는 ACTION_UNSUPPORTED/INPUT_INVALID/SCOPE_UNVERIFIED/SCOPE_CHANGED/EVENT_UNAVAILABLE/DENIED/SNAPSHOT_CHANGED/CONFIRMATION_INVALID/CONFIRMATION_EXPIRED/STORE_FAILED/TIMEOUT/CANCELLED/RESULT_UNVERIFIED다. 원문 source 오류·credential·stack·engine의 추가 필드는 응답에 내보내지 않는다.

로컬 source 수정만 되돌릴 수 있다. 실제 적용 전에는 dispatch를 비활성화하고 unknown을 reconcile하는 운영 절차가 별도로 필요하다. DB의 action·학생 기록을 DROP/과거 복원하거나 자동 재집행하지 않는다. root가 별도 HTTP/UI·독립 Sol 검수·실제 원천을 확인한 뒤 다음 배치를 결정한다.

수행 설정: GPT-6.1 Sol / 요청 High, 내부 실제 effort 독립 관측 없음. 검수: root + 별도 Sol. Astra 추가 호출 0.
