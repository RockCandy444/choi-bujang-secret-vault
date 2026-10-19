# SDP host 연결 — 로컬 통합 검증 완료

이 문서는 학생 PC의 앱 엔진이 기존 SDP relay의 개인 mTLS·JWT admission 경로를 이용하는 계약을 설명합니다. 2026-10-14 새 통합 검사 2건을 각각 한 번 실행해 통과했습니다. 합성 시험 신원으로 소유한 로컬 환경에서 실제 host/adapter·mTLS/JWT·서명 정책·Timo 및 PC Chrome을 연결했습니다. 실제 학생 로그인·개인 인증서 발급·운영 릴레이 수용은 **NOT_RUN**입니다.

- host/adapter의 본인 범위·세션·토큰 갱신·타인 거절·취소·종료: PASS, 3,405.3006ms.
- 실제 CLI와 화면이 보이는 PC Chrome의 업무 앱 접근 요청 → 원 Timo 판정 → 화면 표시: PASS, 6,509.1682ms. 판정은 allow, Timo 호출 1건, 원천 리소스 접근 0건입니다. 미구현 기록·기기·세션 조회는 오류로 표시했습니다.
- 시험 전후 5,048개 파일과 저장소 상태가 일치했습니다. 학생 extension은 원본의 구현 대기 상태를 보존했습니다. 완료한 기존 검사 재실행은 0회입니다.
- 근거: `C:/Work/_aleph-bridge/ALEKOV_SDP_HOST_NEW1_20261014.case1.result.json`, `case2.result.json`; 원문 TAP SHA-256 `d6dc19219b9566c5ee3f13257686c4c13a94f751bad4a5b1fa375ce37d627f38`, `161e4dc507d013ab84411dde97e2b8a1e774e5e0cbedbc8f7281974baadaabae`.

## 이번 파일과 통합 경계

- src/engine/sdp-host-config.mjs: 명시적 설정 읽기, 개인 자격 파일 확인, 비밀을 보관하는 WeakMap, 고정 HTTPS 요청.
- src/engine/sdp-host.mjs: 현재 identity, 본인 프로젝트 앱 목록, 실제 접근 판정의 응답 검증과 기존 서버 DTO 투영.
- docs/SDP_HOST_CONNECTION.md: 설정·보존·검증 범위와 미검증 항목.

engine.mjs, server.mjs, student/engine-adapter.mjs와 launcher에 명시적인 `--sdp-host-config` / `-SdpHostConfig` 연결을 추가했습니다. 이 설정을 지정한 실행에서만 host를 만들며, 학생 adapter에는 프로젝트 ID와 조회·판정 메서드 3개만 전달합니다. 기본 실행은 기존 동작을 따릅니다. 이 모듈은 default 엔진 객체를 자동 생성하지 않으며, import만으로 파일·환경 변수·네트워크에 접근하지 않습니다.

## 개인 설정

호출자는 readSdpHostConfiguration(file, {projectRoot})에 운영자가 명시한 절대 설정 경로와 실제 학생 프로젝트 경계를 전달합니다. 반환값은 공개 속성이 없는 frozen opaque 객체입니다. 이 객체만 createSdpHostEngine(configuration)에 전달할 수 있으며 같은 모양의 임의 객체는 거절됩니다.

아래는 형식 설명용 값입니다. 파일을 만들거나 서버를 실행하는 명령이 아니며, 개인 자격이나 실제 서버 주소를 포함하지 않습니다.

~~~json
{
  "schema": "alekov.sdp.host.v1",
  "projectId": "sample-project",
  "host": "relay.example.invalid",
  "port": 7443,
  "servername": "relay.example.invalid",
  "caFile": "C:\\AlekovPrivate\\ca.pem",
  "certFile": "C:\\AlekovPrivate\\student-cert.pem",
  "keyFile": "C:\\AlekovPrivate\\student-key.pem",
  "tokenFile": "C:\\AlekovPrivate\\access-token.txt"
}
~~~

설정은 위 9개 키만 허용합니다. 중복 키, prototype 관련 키, 임의 URL/path/header/fetch/clock/identity 옵션은 거절합니다. projectId는 소문자로 시작하는 영문 소문자·숫자·밑줄·하이픈 1~64자입니다. host는 DNS 이름 또는 IP, servername은 TLS 서버 인증서를 검증할 DNS 이름, port는 1~65535 정수입니다. HTTP나 인증서 검증 해제 설정은 없습니다.

개인 CA·인증서·키·JWT는 기존 3차의 승인된 발급 경로에서 준비해야 합니다. 이 구현은 발급·갱신·공유 인증서 선택·자격 경로 검색을 하지 않습니다. JWT는 tokenFile에서만 읽으며 명령행 인자로 받지 않습니다. 파일은 JWT 하나와 선택적인 끝 개행 하나만 허용하고, 기존 SDP_ACCESS_TOKEN_FILE 출력과 같은 형태를 사용합니다. JWT의 서명·만료·issuer·audience와 개인 인증서는 원 relay가 매 호출 검증합니다.

설정과 네 개 자격 파일은 실제 프로젝트 밖의 정규 절대 경로여야 합니다. Windows에서는 드라이브 절대 경로만 허용하고 ADS, 비정규 경로, 이름 끝의 점·공백을 거절합니다. 일반 파일 여부·단일 hard link·상위 경로와 파일의 symlink/junction·realpath를 검사합니다. 파일을 열기 전후의 fd/path stat, 파일 identity·크기·mtime·ctime, 상위 디렉터리 identity, SHA-256을 확인합니다. 설정/JWT는 각각 8 KiB, CA/cert/key는 각각 64 KiB까지 읽으며 UTF-8 오류를 거절하고 fd를 닫습니다.

프로젝트 경계와 설정·CA·cert·key 증거는 생성 때 고정합니다. 각 operation과 전송 전후, 결과 반환 직전에 다시 확인하며 변경되면 설정을 새로 읽어 엔진을 다시 만들어야 합니다. JWT 파일은 operation마다 새로 읽습니다. operation 사이의 JWT 교체는 허용하고, 진행 중 교체는 기존 결과를 거절합니다. 파일·권한·원본 데이터는 자동 수정하거나 삭제하지 않습니다.

## 실제 연결 계약

HTTPS POST 경로는 /alekov/context, /alekov/apps, /alekov/decision 세 개뿐입니다. appId/audience는 aleph-on/on-client로 고정합니다. 요청은 개인 mTLS와 JWT Bearer 인증을 함께 사용하고, rejectUnauthorized=true와 agent=false를 사용합니다. redirect를 따라가지 않습니다. 요청 본문은 최대 4096바이트, 성공 응답은 최대 64 KiB입니다. 200 성공 상태·application/json·중복 중요 헤더·엄격 JSON·x-sdp-request-id를 확인합니다. 오류 응답의 원문·경로·인증서·토큰은 공개 오류로 전달하지 않습니다.

각 operation은 context와 후속 호출을 합쳐 최대 5초입니다. wall/monotonic 기한을 모두 검사하고, 전달받은 실제 AbortSignal과 close()가 진행 중 HTTPS request/response를 종료합니다. 타이머와 외부 abort listener는 정리합니다. 인증 또는 원천 검증 실패를 접근 deny나 빈 성공으로 바꾸지 않습니다.

- readIdentity({signal}): 현재 context를 확인하고 프로젝트 subject를 user.id로 반환합니다. subjectId는 소문자 64자리 hex이며 raw JWT sub나 issuer를 반환하지 않습니다. device.status는 unknown입니다. session.status=active는 현재 개인 mTLS·JWT·등록부·정책이 유효하다는 의미이며, 앱 접근 허용이나 OS 준수를 뜻하지 않습니다.
- readApps(scope, {signal}): scope는 정확히 subjectId/projectId/appId/audience입니다. 현재 context로 subject와 고정 project를 확인한 뒤 같은 자격 snapshot의 sessionId로 apps를 조회합니다. 전후 subject/project/class/device/session/policy revision/registry digest/catalog digest가 같아야 합니다. 최대 100개 앱의 정확한 id/name/subjectId/projectId와 id 중복 여부를 검증합니다. 앱 목록 자체는 접근 allow 판정이 아닙니다.
- decideAccess({appId, requestId}, scope, {signal}): 현재 context를 조회한 뒤 선택 앱과 원 requestId를 relay에 전달합니다. header·outer·decision의 engineRequestId와 원 clientRequestId, 앱·subject·project·session을 결속합니다. 실제 allow/deny/challenge만 허용합니다. reason과 ruleIds는 안전한 짧은 코드로 검증하고, reason은 “접근 판정: 원코드”로 표시합니다. 원문 정책 설명을 추측하지 않습니다.

readEvents/readDevices/readSessions/AI/action 메서드는 제공하지 않습니다. 미구현 메서드를 가짜 빈 목록이나 성공 결과로 대신하지 않습니다.

context는 고정 schema/kind, 프로젝트 subject 64hex, deviceId 16hex, 0 이상의 safe-integer policyRevision, registry/catalog digest 64hex를 요구합니다. classId·sessionId·앱·reason/rule 식별자는 영숫자로 시작하는 ASCII 영숫자·점·밑줄·콜론·하이픈 1~80자로 제한합니다. sessionId의 특정 접두사를 가정하지 않습니다. UUID는 소문자 RFC 형태로 검증합니다. 실제 공급자와 이 제한의 일치는 root가 후속 확인해야 합니다.

relay와 PC의 관측 시계차는 고정 최대 ±5000ms까지만 허용합니다. observedAtMs와 decision.checkedAt은 해당 operation의 시작부터 응답 수신까지 이 오차 범위 안에 있어야 합니다. validUntilMs는 observedAtMs 이후 최대 10000ms이고, 결과 반환 시점의 PC 시각보다 미래여야 합니다. 원격 validUntilMs를 PC 기준으로 연장하지 않습니다. 시계차가 범위를 벗어나거나 유효기간이 지나면 검증 불가로 거절합니다.

native CLCO 로그인과 SDP 개인 자격은 별개입니다. native registry의 project UUID를 SDP projectId로 자동 변환하거나 같은 프로젝트라고 추정하지 않습니다. 이 엔진은 CLCO의 canonical student identity를 합성하지 않습니다.

## HELP 및 검증 상태

**HELP — Windows 권한과 reparse의 운영 검증:** Node의 lstat/isSymbolicLink/realpath로 보이는 링크·junction과 경로 대체는 검사하지만, 실행 SID owner·보호 DACL·단일 FullControl ACE를 확인하는 Win32 ACL 검증과 일반 symlink로 드러나지 않는 모든 reparse tag의 검사는 이 3개 파일만으로 구현하지 않았습니다. 원 native helper의 권한 검증을 임의로 확장하거나 호출하지 않습니다. 개인키 보관에 대한 이 검증은 별도 승인된 Windows 경계에서 완료해야 하며, 완료 전 운영 수용을 선언하지 않습니다. 지속적인 noShareDelete Windows handle 잠금도 제공하지 않으므로 같은 SID가 수행하는 파일 교체 경합의 완전한 차단을 주장하지 않습니다.

소스 작성과 원바이트 읽기만 수행했습니다. 구문 검사, 단위/통합 시험, 실제 개인 mTLS·JWT 발급, 실제 relay 연결, OS ACL·reparse 검사, 토큰 교체·취소·기한의 실제 경합 시험, 학생 PC 수용은 모두 NOT_RUN입니다. 기존 PASS 시험은 재실행하지 않았습니다. shell·서버·네트워크·commit·배포 작업도 하지 않았습니다.
