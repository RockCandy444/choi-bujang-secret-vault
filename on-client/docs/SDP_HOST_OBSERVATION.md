# SDP 본인 기록·기기·세션 조회 — 로컬 통합 검증 완료

15·16단계의 본인 접속 기록·XDR 사건·등록 기기·현재 연결 조회를 위한 host입니다. 2026-10-14 새 통합 검사 3건을 각각 한 번 실행해 모두 통과했습니다. 합성 시험 신원으로 실제 릴레이·감사 저장소·탐지기·Timo와 새 설치본의 PC Chrome을 연결한 로컬 결과입니다. 실제 학생 계정·운영 원천 검증은 **NOT_RUN**입니다. 완료한 기존 검사는 다시 실행하지 않았습니다.

- 실제 접속 거부 3건 → 저장된 XDR 경보 → 본인 기록 조회, 안정 ID·정상 append: PASS, 2,195.4981ms.
- 타인·귀속 불가 제어 9건 제외, 옛 앱 세대, 원 로그 후퇴·변조, 판정의 403/428 구분, 세대·제한·취소·기한: PASS, 7,003.4015ms.
- 스타터 0.2.5의 실제 52개 bundle 파일 → 원 installer → 새 설치본 CLI → PC Chrome: PASS, 7,949.2021ms. 기록 5개와 조회 범위 3종, 잘못된 coverage에서 이전 목록 제거와 수동 복구를 확인했습니다. 학생 extension 원본과 구현 대기 표시를 보존했습니다.
- 시험 전후 5,050개 파일과 저장소 상태가 일치했습니다. 자료 리소스 접근은 0건입니다. 근거는 `C:/Work/_aleph-bridge/ALEKOV_OBSERVATION_NEW1_20261014.case1.result.json`, `case2.result.json`, `case3.result.json`입니다.
- 원문 TAP SHA-256: `84aa1927afada6e4286b2a4b2d0a468579354c2248d259abe9c0ebd3aed1f6ff`, `2d66913f447f80126a847f2166a715214440892d107b360113a6c01c04cb5e59`, `c21a53dde4c61136d0011debdb7b4d6b004e92f7d561f3149f8e8dfe992de320`.

## 이번 연결

- src/engine/sdp-host-config.mjs: 기존 HTTPS 경계에 POST /alekov/events, /alekov/devices, /alekov/sessions를 추가합니다.
- src/engine/sdp-host.mjs: readEvents(scope,{signal}), readDevices(scope,{signal}), readSessions(scope,{signal})를 추가합니다.
- student/engine-adapter.mjs: 실제 host가 제공한 조회 메서드만 동일 scope/options로 전달합니다. 기존 readIdentity/readApps/decideAccess만 제공하는 host의 계약은 유지하고, 미지원 조회 메서드는 만들지 않습니다.

서버의 명시적 SDP 실행 경로에 조회 메서드 3개를 연결하고 검증된 coverage만 공개 응답과 기존 UI로 전달합니다. 스타터 0.2.5는 이전 프로필을 보존하며 조회 안내서 1개를 더해 runtime 51개와 manifest 1개로 구성합니다. 기본 adapter는 계속 disconnected입니다. 조회 원천 실패는 빈 배열 성공으로 바꾸지 않습니다. 기존 context/apps/decision의 형식, 개인 mTLS·JWT, 고정 TLS 검증, 파일 snapshot 재검증, 취소, operation 전체 5초 제한을 유지합니다. 기존 native와 학생 미커밋 작업은 보존했습니다.

각 조회는 같은 operation의 자격 snapshot으로 먼저 context를 확인합니다. scope는 정확히 subjectId/projectId/appId/audience이며, 현재 subject와 설정에 고정된 project가 일치해야 합니다. 후속 POST 본문은 appId/audience/projectId/sessionId 네 키뿐입니다. 응답 전후 subject/project/class/device/session/policyRevision/registryDigest/catalogDigest가 같아야 하며, 결과 반환 직전에도 파일·취소·기한·context 유효기간을 다시 검사합니다.

## 성공 응답과 조회 범위

원 응답은 schema/kind/engineRequestId/context, 해당 kind 배열, coverage만 허용합니다. body와 x-sdp-request-id의 engineRequestId를 대조하고, 추가 필드·틀린 신원·세대 변경·원천 실패를 거절합니다.

coverage의 정확한 키는 schema, kind, scope, limit, total, returned, truncated, observedAtMs입니다. schema는 alekov.sdp.coverage.v1입니다.

| 조회 | scope | limit | 뜻 |
|---|---|---:|---|
| events | own-recorded-events | 40 | 현재 본인·프로젝트·등록부로 귀속을 확인한 기록 |
| devices | own-registered-devices | 100 | 현재 본인의 미회수 등록 기기 |
| sessions | current-verified-connection | 1 | 현재 검증된 연결 한 건 |

total과 returned는 0 이상의 safe integer이며 total>=returned, returned=배열 길이<=limit이어야 합니다. truncated는 total>returned와 정확히 일치해야 합니다. sessions는 total=returned=1, truncated=false만 허용합니다. 다른 사용자·전체 시스템의 건수나 전역 sequence는 받지 않습니다.

observedAtMs는 현재 operation 시작부터 응답 수신까지 고정 ±5000ms 범위 안이어야 합니다. 응답 context의 observedAtMs와 차이가 10000ms를 초과하거나, context.validUntilMs 이상이면 거절합니다. 기존 context의 현재 유효기간 검사도 그대로 적용합니다. 원 응답 시각이나 유효기간을 호스트가 연장하지 않습니다.

반환값은 frozen 배열입니다. 검증한 coverage는 배열에 nonenumerable, nonwritable, nonconfigurable data property로 붙이며 coverage 자체도 frozen입니다. 행과 중첩 상태·근거·규칙·supportedActions 배열도 고정합니다. 일반 JSON 배열 직렬화에는 coverage가 포함되지 않으므로, root 서버가 이 속성을 별도로 검사하고 허용 필드만 공개 응답으로 투영해야 합니다. 이 속성에는 비밀·전체 원로그·경로·인증서 지문이 없습니다.

## 조회별 DTO 검증

events는 최대 40개이며 각 행은 정확히 id/kind/at/appId/summary/evidence/rules/state/supportedActions/subjectId/projectId입니다. 행 id는 중복될 수 없고 kind는 access 또는 xdr, at은 원 canonical ISO 형식, appId는 null 또는 안전한 ID여야 합니다. summary는 제어문자를 제외한 최대 200코드포인트입니다. evidence와 rules는 각각 최대 8개, 정확한 id/text 필드와 각 목록 내 중복 없는 ID, 최대 500코드포인트의 안전한 text를 요구합니다. state의 access는 allowed/denied/unknown 중 하나이며 session/device는 unknown만 허용합니다. supportedActions는 빈 배열만 허용합니다. 과거 사건 시각을 현재 조회 시각으로 바꾸거나 조회 시점에 새 경보를 계산하지 않습니다.

devices는 최대 100개이며 정확히 id/label/status/subjectId/projectId입니다. id는 중복 없는 16자리 소문자 hex, label은 등록된 기기, status는 unknown이어야 합니다. 현재 context.deviceId가 목록에 반드시 포함되어야 하며 truncated여도 예외를 두지 않습니다. 공급자는 본인 기기가 100개를 초과할 때 현재 인증 기기를 반환 목록에 포함해야 합니다. 이를 만족하지 않으면 host는 조회를 거절합니다. 등록 상태를 OS 준수나 다른 기기의 현재 인증 성공으로 해석하지 않습니다.

sessions는 정확히 한 건이며 id/status/subjectId/projectId만 허용합니다. id는 현재 context.sessionId와 같고 status는 active여야 합니다. 전체 로그인 이력이나 다른 기기의 활성 세션 목록으로 표시하지 않습니다.

모든 행의 subjectId/projectId는 이번 요청의 검증된 본인 scope와 같아야 합니다. 신원·프로젝트·세대 불일치는 SUBJECT_SCOPE_UNVERIFIED, 형식·coverage 오류는 ENGINE_RESULT_UNVERIFIED로 거절합니다. 기존 ENGINE_TIMEOUT/REQUEST_CANCELLED/ENGINE_NOT_CONNECTED 처리도 유지합니다.

## 남은 수용 조건

원 audit의 최종 checkpoint·현재 등록부 귀속·저장된 incident_raised의 근거를 검증하는 일은 원 SDP 공급자의 계약입니다. host가 응답 형식을 검증했다는 사실만으로 공급자의 감사 원천 검증이나 실제 학생 조회가 완료됐다고 판단하지 않습니다. provider의 현재 기기 포함 처리, 원 응답 DTO·coverage와 host의 호환성, 서버 coverage 투영, 공개 UI는 root의 후속 통합·독립 검증 대상입니다.

기존 개인 자격 파일의 Windows ACL 및 특수 reparse 검증 HELP는 이번 조회 확장으로 해결됐다고 주장하지 않습니다. 설정 파일·개인키·토큰·감사키를 학생 adapter에 전달하거나 조회용 권한으로 전체 운영 사건에 접근하지 않습니다.

수행 모델은 부모 설정을 상속했으며 정확한 runtime 모델·내부 추론 설정은 독립 측정하지 않았습니다. 검수 담당은 root Codex입니다. 이 문서와 소스 작성 외 시험·구문·실행·추가 agent·별도 Astra 호출은 0회입니다.
