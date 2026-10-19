# 케셰브 연결과 문제 해결 안내

이 문서는 실행 도구(`tools/start-alekov.ps1`), 계정 연결 확인, AI 앱 승인·점검, 기록 조회에서 만나는 메시지와 오류 코드별로 원인과 할 일을 모은 학생용 안내입니다. 설치·실행 순서는 [STUDENT_LAUNCH_GUIDE.md](STUDENT_LAUNCH_GUIDE.md), SDP 연결의 기술 계약은 [SDP_HOST_CONNECTION.md](SDP_HOST_CONNECTION.md)를 봅니다.

Node.js 는 22~24 를 지원하며, 수업·검사 기준 버전은 24.19.0 입니다. 처음 설치한다면 24.19.0 을 설치합니다.

## 1. 전체 흐름

1. **개발**: 내 PC 의 Workbench 작업 폴더(같은 프로젝트 하나)에서 CLCO 수업용 AI 와 함께 `student/extension.mjs` 등을 고칩니다.
2. **독립 실행**: 앱 폴더(`on-client`)에서 실행 도구로 앱을 켭니다. 이때 Workbench 를 켜 둘 필요는 없습니다.
3. **ALEPH 확인**: 내 GitHub 저장소 주소와 40자리 커밋을 ALEPH 해당 단계에 제출합니다. 서버가 그 커밋으로 자동 확인합니다. 내 화면에서 보인 결과가 제출 결과를 대신하지 않습니다.

같은 프로젝트를 끝까지 씁니다. 연결 문제가 생겨도 기존 작업 폴더를 지우거나 새로 만들지 않습니다.

## 2. 누가 무엇을 준비하나

| 준비 항목 | 담당 | 학생이 할 일 |
|---|---|---|
| Node.js 22~24(수업·검사 기준 24.19.0) | 학생 | 설치 후 PowerShell 창을 새로 엽니다 |
| 4차 시작 틀 배포본 | 운영자(ALEPH 13단계 화면에 공지) | 공지된 곳에서만 받습니다 |
| 계정 연결용 native 호스트 설정 파일 | 운영자 | 안내받은 경로를 실행 명령에 넣습니다. 직접 만들거나 남의 파일을 복사하지 않습니다 |
| SDP 연결용 개인 설정 파일·인증서 | 운영자 | 안내받은 경로를 넣습니다. 프로젝트·Git·제출물 밖에 보관합니다 |
| 학생 계정과 AI 앱 권한 발급 | 운영자 | 화면 순서대로 확인·승인만 합니다 |
| 수업용 AI 게이트의 앱 전용 모델 목록 처리(새 게이트 버전 반영) | 운영자 | 반영 전에는 모델 점검이 실패할 수 있으며 학생 잘못이 아닙니다 |
| SDP 사건과 AI 계정의 대응 등록(18단계) | 운영자(서명 승인) | 대응 파일을 직접 만들지 않습니다 |
| 20단계 공개 패키지 조회 허용 목록 | 운영자 | 비어 있으면 미조회가 정상입니다 |

## 3. 실행 명령(앱 폴더의 PowerShell)

기본:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-alekov.ps1
```

옵션(실행 도구에 있는 것만):

| 옵션 | 뜻 |
|---|---|
| `-Port 5190` | 5189 를 다른 프로그램이 쓸 때 다른 포트로 켭니다. 브라우저 주소도 같은 포트로 엽니다 |
| `-Background` | 창 없이 켭니다. 안내된 프로세스 번호의 node 를 작업 관리자에서 끄면 꺼집니다 |
| `-Demo` | 예제 자료로 켭니다. 실제 연결이 아니며 SDP 설정과 함께 쓸 수 없습니다(SDP_HOST_DEMO_CONFLICT) |
| `-NativeHostConfig "<안내받은 절대 경로>"` | 계정 연결·AI 앱 승인에 쓰는 설정 |
| `-SdpHostConfig "<안내받은 절대 경로>"` | 본인·기기·업무 앱 판정·보안 기록에 쓰는 SDP 연결 설정 |
| `-WaitSeconds 30` | 켜짐 확인을 기다리는 시간(1~120초, 기본 20) |

두 설정을 함께 쓸 때:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-alekov.ps1 -NativeHostConfig "C:\AlekovPrivate\native.json" -SdpHostConfig "C:\AlekovPrivate\sdp-host.json"
```

경로는 예시입니다. 두 설정은 용도가 달라 서로 대신 쓸 수 없고, 함께 켰다고 SDP 계정과 ALEPH 계정이 같은 사람으로 인정되지도 않습니다(18단계 대응 등록은 운영자 몫).

## 4. 상태를 구분하는 법

| 화면에 보이는 것 | 뜻 | 성공인가 |
|---|---|---|
| 연결 없음(disconnected), 미연결(NOT_MOUNTED) | 이 실행에 그 연결이 켜지지 않음 | 아니오 |
| 예제(demo) | 예제 자료 | 아니오 |
| 승인 대기(awaiting_approval), 확인 번호 표시 | 포털에서 승인을 기다림 | 아니오 |
| 권한 준비 중(ON_AI_PROVISIONING_PENDING) | 운영자 준비가 끝나지 않았거나 확인할 수 없음 | 아니오 |
| 확인 불가(UNVERIFIED, CONTRACT_MISMATCH, OUTCOME_UNKNOWN) | 결과를 믿을 수 없음 | 아니오. 정상이나 빈 결과로도 보지 않음 |
| 서비스 장애(SERVER_UNAVAILABLE, TIMEOUT, NETWORK) | 서버나 연결 문제 | 아니오. 잠시 뒤 직접 다시 시도 |
| 빈 목록(정상 응답, 0건) | 확인했고 보여 줄 것이 없음 | 확인은 성공 |
| 연결 완료(connected), verified 점검 | 그 시각 기준 확인됨 | 예. 모델 점검은 사건 설명 성공이 아님 |

## 5. 오류 코드별 해결

### 실행 도구(PowerShell 창)

| 메시지 | 원인 | 학생 확인 | 운영자 확인 | 다시 시도 조건 |
|---|---|---|---|---|
| Node.js 가 없습니다 / 지금 Node.js 는 vXX | Node 없음·버전 다름 | 22~24 설치(기준 24.19.0), 새 창 | 없음 | 설치 뒤 |
| 포트 5189 를 다른 프로그램이 쓰고 있습니다 | 포트 충돌 | 그 프로그램은 두고 `-Port 5190` | 없음 | 바로 |
| 앱 폴더가 아닙니다 / 시작 틀 폴더가 아닙니다 / 바로가기(링크)로 연결된 폴더 | 실행 위치 오류 | on-client 실제 폴더에서 실행 | 없음 | 바로 |
| …초 안에 뜨지 않았습니다 | 서버가 제때 응답 안 함 | 창 메시지 전체와 도움정보를 강사에게 | 서버 로그 | 원인 확인 뒤 |

### 계정 연결 확인(native)

| 코드 | 원인 | 학생 확인 | 운영자 확인 | 다시 시도 조건 |
|---|---|---|---|---|
| NATIVE_HOST_DISABLED, NATIVE_LOGIN_NOT_MOUNTED | 이 실행에 계정 연결 설정이 없음 | `-NativeHostConfig` 를 넣었는지 | 설정 파일 발급 | 설정을 받은 뒤 다시 켜기 |
| NATIVE_LOGIN_PENDING, NATIVE_LOGIN_STATUS_ONLY | 포털 번호 확인 전 | 포털에서 같은 번호 확인 후 「로그인 확인 완료」 | 없음 | 포털 확인 뒤 |
| NATIVE_HOST_EXPIRED, NATIVE_LOGIN_EXPIRED_LOCAL | 확인 기한 지남 | 「계정 연결 취소」 뒤 새로 시작 | 없음 | 새로 시작 |
| NATIVE_HOST_CONTEXT_CHANGED | 계정·로그인·파일·프로젝트 연속성이 바뀜 | 취소 뒤 새로 시작. 같은 계정인지 확인 | 반복되면 설정·프로젝트 등록 확인 | 새로 시작 |
| NATIVE_HOST_BUSY, NATIVE_LOGIN_SERVER_STARTING | 이전 요청이 남음 | 「계정 연결 취소」 또는 「현재 로그인 확인」 | 없음 | 정리 뒤 |
| NATIVE_HOST_TIMEOUT, NATIVE_LOGIN_CLIENT_TIMEOUT, NATIVE_LOGIN_NETWORK | 포털·로컬 응답 지연, 앱 꺼짐 | 앱 실행 창이 켜져 있는지, 인터넷 연결 | 포털 상태 | 「현재 로그인 확인」 먼저, 그다음 직접 다시 |
| NATIVE_HOST_UNVERIFIED, NATIVE_HOST_OUTCOME_UNKNOWN, NATIVE_HOST_RESPONSE_INVALID, NATIVE_LOGIN_UNVERIFIED, NATIVE_LOGIN_RESPONSE_INVALID, NATIVE_LOGIN_SERVER_UNKNOWN | 결과를 확인할 수 없음 | 연결로 보지 않음. 「현재 로그인 확인」 한 번, 계속되면 도움정보를 담당자에게 | 포털·설정 확인 | 원인 확인 뒤 |
| NATIVE_LOGIN_LOCAL_RESET, NATIVE_HOST_CANCELLED, NATIVE_LOGIN_CANCELLED | 화면에서 멈춤 | 서버 쪽 연결이 취소된 것은 아님. 「현재 로그인 확인」 | 없음 | 확인 뒤 |

### AI 앱 승인(AI 연결 칸)

| 코드 | 원인 | 학생 확인 | 운영자 확인 | 다시 시도 조건 |
|---|---|---|---|---|
| ALEKOV_CONNECT_NOT_MOUNTED, ALEKOV_CONNECT_UNAVAILABLE | 이 버전에 연결 경로 없음 | 기다림. 판정·기록은 그대로 사용 | 배포본·설정 | 새 배포본 뒤 |
| ALEKOV_CONNECT_EXPIRED, ALEKOV_CONNECT_NOT_FOUND | 승인 기한 지남·요청 없음 | 이미 승인했으면 「상태 다시 확인」 먼저, 아니면 취소 뒤 새로 | 없음 | 새로 시작 |
| ALEKOV_CONNECT_REJECTED | 승인 계정이 지금 로그인과 다름 | 같은 계정인지 확인 | 없음 | 확인 뒤 새로 |
| ALEKOV_CONNECT_CONTEXT_CHANGED, ALEKOV_CONNECT_CONTEXT_UNVERIFIED | 계정·프로젝트·세션 변경 | 계정 연결부터 다시 | 프로젝트 등록 | 다시 로그인 뒤 |
| ALEKOV_CONNECT_BUSY | 진행 중 요청 | 취소 뒤 | 없음 | 정리 뒤 |
| ALEKOV_CONNECT_NETWORK, ALEKOV_CONNECT_CLIENT_TIMEOUT, ALEKOV_CONNECT_DEADLINE | 연결·시간 문제 | 앱 켜짐 확인, 「상태 다시 확인」 한 번 | 포털 상태 | 확인 뒤 |
| ALEKOV_CONNECT_STORAGE_UNVERIFIED, ALEKOV_CONNECT_OUTCOME_UNKNOWN, ALEKOV_CONNECT_RESPONSE_INVALID | 연결 완료가 아님 | 「연결 도움정보 보기」 내용을 읽고 담당자에게 | 저장소·포털 확인 | 원인 확인 뒤 |

### AI 연결 점검(현재 API 연결 점검)

| 코드 | 원인 | 학생 확인 | 운영자 확인 | 다시 시도 조건 |
|---|---|---|---|---|
| ON_AI_PROVISIONING_PENDING | 앱 권한·계정 연결이 준비 안 됐거나 확인 불가 | 계정 연결·앱 승인을 마쳤는지 | 앱 권한 발급, 게이트 반영 | 운영자 준비 뒤 |
| ON_AI_MODEL_LIST_EMPTY(새 버전에서 표시될 수 있음) | 앱 권한으로 쓸 모델이 없음 | 담당자에게 알림 | 앱 모델 허용 설정 | 설정 뒤 |
| ON_AI_AUTHORIZATION_CHANGED(새 버전에서 표시될 수 있음) | 점검 도중 권한 내용이 바뀜 | 담당자에게 현재 권한 확인 | 권한 변경 이력 | 확인 뒤 |
| WB_CLCO_AUTH_REQUIRED | 앱 인증 실패 | 계정 연결·앱 승인 다시 확인. 열쇠를 복사하지 않음 | 앱 자격 상태 | 확인 뒤 |
| WB_CLCO_ACCESS_BLOCKED | 이용 권한 막힘(권한 새 판 포함) | 담당자에게 | 권한·차단 상태 | 확인 뒤 |
| WB_CLCO_SESSION_CLOSED | 이용 시간 아님 | 이용 시간 확인 | 개방 시간 | 시간 안에 |
| WB_CLCO_COHORT_BUDGET_EXHAUSTED, WB_CLCO_LIMIT_REACHED | 반 사용량·한도 | 담당자에게 | 한도 | 조정 뒤 |
| WB_CLCO_RATE_LIMITED | 요청 제한 | 잠시 기다림 | 없음 | 잠시 뒤 직접 |
| WB_CLCO_TIMEOUT, WB_CLCO_NETWORK_ERROR, WB_CLCO_SERVER_UNAVAILABLE | 게이트 연결 문제 | 인터넷 확인 | 게이트 상태 | 잠시 뒤 직접 |
| WB_CLCO_INVALID_RESPONSE | 게이트 응답이 계약과 다름(허용 밖 모델 포함) | 담당자에게 | 게이트 버전(앱 전용 목록 처리 반영 여부) | 원인 확인 뒤 |
| MODEL_NOT_CONFIGURED | 설정 모델이 허용 목록에 없음 | 담당자에게 | 앱 서버 모델 설정 | 설정 뒤 |

### 기록·기기·세션 조회

| 코드 | 원인 | 학생 확인 | 운영자 확인 | 다시 시도 조건 |
|---|---|---|---|---|
| CONTRACT_MISMATCH(화면 확인 불가) | 응답이나 확인 범위(coverage) 형식이 맞지 않음, 오래된 확인 시각 | 다시 불러오기 한 번 | SDP relay 버전·시계 | 직접 다시 |
| ENGINE_RESULT_UNVERIFIED | 서버 응답 확인 불가 | 도움정보를 담당자에게 | relay·설정 | 원인 확인 뒤 |
| SUBJECT_SCOPE_UNVERIFIED | 현재 로그인과 사건·프로젝트 연결 확인 불가 | SDP 설정을 넣었는지 | SDP 등록부·세션 | 확인 뒤 |
| ENGINE_NOT_CONNECTED | 기존 서버 연결 없음 | `-SdpHostConfig` 여부 | SDP 설정 발급 | 설정 뒤 |
| 정상 응답 0건 | 보여 줄 기록이 없음 | 실패가 아님 | 없음 | 해당 없음 |

## 6. 하지 말 것

- 열쇠·토큰·JWT·인증서·설정 파일 내용을 채팅·도움정보·Git·제출물·안내서에 붙여 넣지 않습니다.
- Workbench 열쇠나 AI 회사 원본 열쇠를 복사해 쓰지 않습니다.
- 연결이 안 된다고 작업 폴더를 지우거나 새로 만들지 않습니다.
- 같은 요청을 여러 번 연달아 누르지 않습니다. 자동 재시도는 없습니다.
- 예제(demo)·연결 없음·확인 불가를 성공으로 적지 않습니다.

## 7. 담당자에게 보낼 것

「도움정보 불러오기」(또는 「연결 도움정보 보기」)로 내용을 읽어 본 뒤 복사해 보냅니다. 도움정보에는 요청 식별자·구성요소·버전·확인 시각·엔진 상태와 안전한 오류 코드 등 점검용 값이 포함됩니다. 표시된 내용을 직접 확인한 뒤 필요한 범위만 복사해 전달합니다. 비밀값이나 설정 파일 원문은 보내지 않습니다. 자동으로 어디에도 보내지지 않습니다.
