# npm 설치 버전과 OSV 정보 대조

이 모듈은 학생이 실제로 설치한 공개 npm 패키지의 정확한 버전을 OSV 데이터와 대조합니다. 설치·업데이트·삭제·원격 코드 실행은 수행하지 않습니다. 조회 결과는 알려진 취약점 정보이며 실제 침해나 제품 전체의 안전성을 판정하지 않습니다.

2026-10-12 현재 구현과 검증은 fixture와 독립 localhost HTTP 서버에 한정됩니다. 실제 OSV 외부 호출, 실제 학생 프로젝트 검사, 서버·UI 통합, 운영 배포는 **NOT_RUN**입니다. 테스트에 등장하는 패키지명·버전·취약점 ID는 가상 자료이며 특정 라이브러리의 실제 취약 여부나 권장 사항이 아닙니다.

## 공식 조회 계약

고정 기본 주소는 `https://api.osv.dev/v1/querybatch`입니다. 공식 계약은 [OSV POST /v1/querybatch](https://google.github.io/osv.dev/post-v1-querybatch/)와 [OSV POST /v1/query](https://google.github.io/osv.dev/post-v1-query/)를 기준으로 합니다. 문서의 파라미터와 페이지 처리 방식은 root가 2026-10-12에 확인했으며, 이 구현 작업에서는 외부 요청을 실행하지 않았습니다.

`queries`의 각 항목에는 `package: { name, ecosystem: 'npm' }`와 정확한 `version`을 넣습니다. 반환 `results`는 조회 입력 순서와 같고, 각 결과의 `vulns`는 `{ id, modified }` 요약 목록입니다. `next_page_token`이 있으면 해당 패키지만 다음 조회에 `page_token`을 넣습니다. 이미 마지막 페이지까지 확인한 패키지는 다시 보내지 않습니다. 원격 리다이렉트를 따르지 않습니다.

## 공개 패키지 선별

```js
import { buildPackageQueries } from './vulnerabilities/osv.mjs';

const { queries, excluded, lockfileVersion } = buildPackageQueries(lock, {
  approvedPublicPackages: ['담당자가 공개 조회를 승인한 canonical npm 이름'],
});
```

`package-lock.json` v2/v3의 `packages`에서 실제 `node_modules` 항목만 확인합니다. 공개 승인 allowlist의 기본값은 빈 배열입니다. 회사·비공개 패키지인지 확인하려고 이름을 registry에 보내지 않으며, 승인되지 않은 패키지는 로컬에서 제외합니다. 승인 여부는 서버 또는 담당자가 제공해야 하고 브라우저 입력으로 임의 확대하지 않습니다.

루트 앱, 로컬 패키지·링크·workspace 항목, `private: true`, file/git 의존성은 제외합니다. `^`, `~`, `>`, `latest` 같은 범위와 태그를 사용하지 않습니다. 정확한 semver 버전과 HTTPS `registry.npmjs.org` tarball의 canonical 이름·버전이 서로 일치해야 합니다. 사용자 정보·query·fragment가 있는 URL이나 다른 registry 주소는 제외합니다. npm alias는 lock에 실제 이름인 `row.name`이 있고, 그 canonical 이름·tarball·버전·공개 승인이 모두 맞을 때만 실제 패키지명으로 조회합니다.

동일 canonical 이름·버전은 중복을 제거합니다. 같은 패키지가 다른 버전으로 여러 번 설치돼 있으면 각각 조회합니다. 결과에는 다음 정보만 남습니다.

```js
{
  queries: [{ package: { name: 'example-public', ecosystem: 'npm' }, version: '1.2.3' }],
  excluded: { unapproved: 0, unsupported: 0, invalid: 0 },
  lockfileVersion: 3,
}
```

제외 요약은 개수만 포함하며 회사 패키지명·로컬 경로·URL을 포함하지 않습니다. 전체 lock, integrity, 로컬 경로, registry URL, 기타 메타데이터를 외부 조회 본문으로 전달하지 않습니다.

## 조회 API와 결과

```js
import { createOsvClient, lookupPackages } from './vulnerabilities/osv.mjs';

const client = createOsvClient();
const results = await client.lookupPackages(queries, {
  signal,
  timeoutMs: 10000,
  maxPages: 10,
  maxResponseBytes: 1048576,
});
// 같은 계약의 함수형 API도 제공합니다.
const sameResults = await lookupPackages(queries, { signal });
```

조회 API에는 `buildPackageQueries`로 선별한 입력만 제공합니다. 각 query는 정확히 `package`와 `version`만 포함해야 하며 `package`는 `name`과 `ecosystem`만 포함해야 합니다. 추가 필드나 범위 버전은 보내지 않습니다. lookup 자체는 공개 승인의 출처를 인증하는 기능이 아니므로, 호출 서버가 승인 목록과 선별 경로를 보장해야 합니다.

반환 배열은 입력 순서를 보존하고 패키지마다 다음 형식입니다.

```js
{
  name: 'example-public',
  version: '1.2.3',
  status: 'known_vulnerabilities', // 또는 none_found / unverifiable
  vulnerabilities: [{ id: 'OSV-FIXTURE-1', modified: '2026-10-01T00:00:00Z' }],
  source: 'https://api.osv.dev/v1/querybatch',
  checkedAt: '조회 시작 ISO 시각',
}
```

- `known_vulnerabilities`: 마지막 페이지까지 확인했고 알려진 취약점 항목이 있음
- `none_found`: 마지막 페이지까지 확인했고 알려진 취약점 항목이 없음
- `unverifiable`: 조회를 끝까지 확인하지 못함. 이미 받은 취약점 요약은 보존됨

취약점이 발견된 페이지 이후 5xx나 timeout이 발생하면 `unverifiable`과 이전 요약을 함께 반환합니다. 결과 길이 불일치, 잘못된 JSON·필드·ID·시각, 반복 cursor, 응답 크기 초과, 페이지 한도 초과도 안전이나 정상으로 표시하지 않습니다. 먼저 완료한 다른 패키지 결과는 이후 오류로 바꾸지 않습니다. 같은 취약점 ID의 반복은 중복을 제거하고 더 최신 `modified`를 보존합니다.

제한 시간은 모든 페이지를 합친 전체 조회에 적용됩니다. `fetchImpl`이 signal을 무시해도 호출자는 제한 시간 또는 취소 시점에 반환받습니다. 늦은 응답으로 다음 페이지를 요청하지 않으며 종료 시 timer와 외부 abort listener를 정리합니다. 기본 자동 재시도는 0회입니다. `page_token`에 따른 연속 조회는 필요한 페이지 처리이며 일반 실패 재시도가 아닙니다. `maxPages`는 모듈의 기술적 한도이며 학생 점수나 진도 제한이 아닙니다.

원문 HTTP 오류, 자유 형식 예외 메시지, cursor, 원격 부가 메타데이터는 반환하거나 로그로 남기지 않습니다. API 열쇠나 인증 header를 요구하지 않습니다.

## 로컬 검증

`createOsvClient({ endpoint, allowLoopbackHttp: true, fetchImpl })` 또는 함수형 options로 시험용 주입이 가능합니다. endpoint 변경은 localhost와 정확한 `/v1/querybatch` 경로에만 허용합니다. 다른 원격 주소는 차단합니다. 이 옵션은 읽기 전용 fixture 검증에만 사용합니다.

```powershell
node --test education/on-client/test/osv.test.mjs
node --check education/on-client/src/vulnerabilities/osv.mjs
```

fixture 11개 검사에서 exact lock, scoped 이름, alias, 중복과 여러 버전, 비공개 제외, 2페이지 순서, 부분 실패와 이전 발견 보존, none_found와 실패의 구분, 전체 timeout·취소·늦은 응답, 큰 응답, 반복 cursor, 페이지 제한, 리다이렉트 차단, 비밀 없는 조회 본문과 로그 0을 확인합니다. 모든 HTTP 실행은 localhost 또는 주입한 fake `fetchImpl`이며 공식 OSV endpoint로 네트워크 요청하지 않습니다.
