# 학생 판정기 요청·응답 계약 v1

`src/decider.mjs`의 `decide(request)`는 반 엔진이 신원, 기기, 경로를 확인한 뒤 전달한 요청만 받습니다. 브라우저가 보낸 사용자 번호·역할·기기 상태를 따로 믿거나 요청에 덧붙이지 마세요. 이 문서는 현재 `student-kit/sdp-core/decision-contract.mjs`의 `aleph.decision.v1` 계약을 설명합니다.

## 요청

요청은 아래 **18개 이름만** 포함합니다. 이름을 추가하거나 중첩 객체로 바꾸면 엔진이 거부합니다.

| 항목 | 뜻 |
|---|---|
| `schema` | 항상 `aleph.decision.v1` |
| `requestId` | 이번 요청의 UUID. 응답에 그대로 돌려줍니다. |
| `classId`, `projectId` | 운영 엔진이 확인한 반과 학생 프로젝트 |
| `subjectId` | 발급자·대상·반·프로젝트를 묶어 만든 가명 주체 ID. Supabase 사용자 번호와 직접 비교하지 않습니다. |
| `deviceId` | 확인된 기기의 16자리 소문자 16진수 ID. 개인키가 아닙니다. |
| `service`, `method`, `path`, `route` | 확인된 서비스와 요청 경로. `route`는 `GET /notes/:id`처럼 허용된 경로 모양입니다. |
| `queryLength`, `querySha256` | 쿼리 문자열의 길이와 SHA-256 지문. 원문 쿼리는 전달되지 않습니다. |
| `at` | 엔진이 만든 UTC ISO 시각. 판정 시각과 5초 넘게 차이 나면 거부됩니다. |
| `policyRevision` | 이번 요청에 적용된 정책 버전 |
| `deviceRegistered` | 기기 등록 여부. 실제 릴레이는 미등록 기기를 판정기보다 먼저 막습니다. `false`는 심판의 가상 요청에서만 올 수 있습니다. |
| `stepUp` | `{verified, authAgeSeconds}`. `verified`가 false이면 나이는 `null`입니다. true일 때 나이는 0~900초입니다. 이 값만 보고 재인증 확인 요청을 건너뛰지 않습니다. |
| `recentEvents` | 엔진이 제공한 최근 사건 배열. 최대 12건이며 각 항목은 `{kind, ageSeconds, count}`입니다. |
| `signals` | `{source, region, network, hour}`. 현재 실제 경로에서는 `source: "none"`, `region/network: "unknown"`입니다. `judge_fixture` 신호를 실제 위치 증거로 취급하지 않습니다. |

현재 계약에는 `request.identity`, `request.device`, `request.geo`, `request.role`, `request.device.approval`이 **없습니다**. 이 값을 브라우저 요청이나 코드의 임의 상수로 채우면 안 됩니다. 위치 이력·강사 역할·기기 승인 기능은 운영 엔진이 출처를 확인하고 별도 계약으로 제공한 뒤 사용할 수 있습니다.

## 응답

`decide(request)`는 다음 **5개 이름만** 담은 객체를 반환합니다.

```js
{
  schema: 'aleph.decision.v1',
  requestId: request.requestId,
  decision: 'allow', // 'allow' | 'deny' | 'step_up'
  reasonCode: 'approved',
  ruleIds: ['my_verified_rule'],
}
```

`reasonCode`는 운영 등록부의 `allowedReasonCodes`에 있는 소문자 코드여야 합니다. 거부와 추가 확인에는 적어도 하나의 규칙 이름이 필요합니다. 응답이 늦거나 형식·요청 ID·이유 코드가 맞지 않으면 엔진은 접근을 허용하지 않습니다. 학생 코드가 `allow`를 반환해도 엔진의 앞선 신원·기기·경로 검사를 되돌릴 수 없습니다.

`step_up`은 엔진에 추가 본인 확인을 요청하는 결정입니다. 단순 `deny`는 재인증 화면으로 이어지지 않습니다. 기존 7단계의 로컬 연습은 `npm run fixture:7`로 정상 요청과 복합 이상 요청 두 건을 비교합니다. 이 연습은 심판 판정이나 실제 학생 접속 증거가 아닙니다.

## 구현 전 확인

1. 규칙이 참일 때만 허용하고 나머지는 거부하거나 추가 확인을 요구합니다.
2. 새로운 `reasonCode`를 쓰려면 운영 등록부와 같은 버전에서 허용 코드가 등록돼야 합니다.
3. 실제 학생 계정, 토큰, 기기 개인키, 자료 본문을 판정 요청·로그·제출 묶음에 넣지 않습니다.
4. 시작 틀의 기본 `decide()`는 모든 요청을 거부합니다. 로컬 연습이 처음에 실패하는 것은 구현 전 상태를 보여 줍니다.
