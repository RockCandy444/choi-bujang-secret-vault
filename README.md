# BYTE BACK 방어전 시작 틀 R5

현재 단계: **2단계 「자료를 코드 밖으로 옮깁니다」 · 제작 2** (2026-10-06).
이 저장소는 1단계 R5 시작 틀에서 이어졌습니다. 정적 파일의 메모 본문을 제거하고 서버 조회 함수를 연결했으며, Supabase로 옮기는 SQL을 로컬에 준비했습니다. 실제 학생 자료, 토큰, 비밀키를 넣지 마세요.

## 현재 기능과 실행

- `data.json`과 `public/data.json`은 빈 메모 목록입니다. 빌드는 메모 원본을 읽거나 복사하지 않습니다.
- 자료실 화면은 `/api/notes`를 통해 Supabase `public.notes`에서 가상 메모 네 건을 읽어 카드로 표시합니다. 정적 JSON은 읽지 않습니다.
- 배포 빌드는 현재 단계와 저장소·커밋·배포 URL을 `public/aleph.json`에 기록합니다.
- 로컬 빌드: `node scripts/build-public.mjs --local`.
- 로컬 검사: `node --test test/*.test.mjs`. 로컬 검사는 실제 심판 판정이 아닙니다.

## Supabase 가져오기 — SQL Editor에서 실행 필요

`local-only/step2-import.sql`을 학습용 Supabase 프로젝트의 **SQL Editor → New query**에 붙여 넣고 **Run**을 누릅니다. 실제 키를 입력할 필요는 없습니다. 기존 `public.notes` 테이블이 있으면 SQL은 오류로 중단해 기존 자료를 보존합니다. 새 테이블에 한 번만 실행하세요.

현재 SQL은 가상 메모 네 건을 `public.notes`에 넣고, `owner_id uuid`를 비워 둡니다. 이전 제작 1의 세 건에서 네 건으로 갱신했습니다. `auth.users` 외래키와 읽기 정책은 만들지 않으며 RLS를 켜고 `PUBLIC`·`anon`·`authenticated`의 테이블 권한을 회수합니다.

서버 전용 키가 사용하는 `service_role`에는 이 테이블의 SELECT만 명시적으로 부여합니다. 브라우저 역할에는 자료 읽기 권한을 주지 않습니다.

실행 결과는 `note_count = 4`, `owner_id_type = uuid`, `rls_enabled = true`, `anon_can_read = false`, `authenticated_can_read = false`, `foreign_key_count = 0`, `policy_count = 0`이어야 합니다. **Table Editor → notes**에서도 `owner_id` 칸과 RLS 표시를 확인합니다. SQL Editor의 관리자 조회는 허용되고, `anon`·`authenticated`의 읽기는 거부되어야 합니다.

본문이 들어 있는 가져오기 SQL과 네 건의 원본 백업(`local-only/data-before-step2.json`)은 `.gitignore`의 `local-only/`로 Git에서 제외됩니다. 이 폴더는 배포하는 `public/` 밖에 있으며 제출 묶음에도 넣지 않습니다. GitHub 체크아웃에는 가져오기 SQL이 없으므로 이 로컬 작업 폴더에서 실행하세요.

새 정적 파일과 GitHub 최신 파일에는 메모 본문이 없어야 합니다. 이전 Git 커밋에는 1단계에서 공개했던 가상 자료가 남아 있습니다. 원격 Supabase에서의 SQL 실행과 실제 심판 판정은 아직 확인하지 않았습니다.

제작 1 검증: Node 검사 12건과 임시 PostgreSQL 17의 세 건 가져오기 검사를 통과했습니다. 제작 2의 검증은 아래 절차와 테스트로 구분합니다.

## Vercel 서버 함수 설정과 확인

`api/notes.js`는 서버에서만 `SUPABASE_URL`과 `SUPABASE_SECRET_KEY`를 읽습니다. Supabase REST API에는 서버 키를 `apikey` 헤더로만 보내고, 브라우저에는 `title`·`content`만 반환합니다. Supabase 오류 원문·헤더·환경변수는 응답이나 로그로 내보내지 않습니다. 응답 캐시도 끕니다.

Supabase 프로젝트 설정에서 프로젝트 URL과 서버 전용 Secret key를 확인한 뒤, **Vercel → choi-bujang-secret-vault → Settings → Environment Variables**에 두 이름으로 직접 입력합니다. `SUPABASE_SECRET_KEY`는 Sensitive로 등록하고 Production에 적용하세요. 키를 채팅·Git·브라우저 소스에 넣지 않습니다. 저장한 뒤 최신 배포를 **Redeploy**해야 새 환경변수가 반영됩니다. 현재 사용자는 SQL 실행과 환경변수 등록을 아직 하지 않았습니다.

정상 확인: 배포 첫 화면에서 네 카드가 보이고 `/api/notes`는 메모 목록을 반환합니다. `/data.json`은 `notes: []`를 유지합니다. 설정이 없으면 함수는 `503 NOTES_NOT_CONFIGURED`, 조회 실패는 민감한 원문 없이 `502 NOTES_UNAVAILABLE`, GET 이외의 요청은 `405 METHOD_NOT_ALLOWED`를 반환해야 합니다. 공개 키로 Supabase를 직접 읽는 요청은 심판이 확인하며, 이 구현에서는 그 검사를 실행했다고 보고하지 않습니다.

**남은 약점:** `/api/notes`는 아직 로그인·소유자 검사 없는 공개 주소입니다. 주소를 아는 누구나 서버 함수를 통해 가상 메모를 읽을 수 있습니다. 서버 전용 키는 RLS를 우회하므로, RLS가 켜졌다는 사실만으로 이 공개 서버 함수의 접근이 보호되지는 않습니다. 인증·소유자 검사는 다음 제작 단계에서 구현합니다.

참고: [Supabase API 키](https://supabase.com/docs/guides/getting-started/api-keys), [Vercel Node.js 함수](https://vercel.com/docs/functions/runtimes/node-js).

제작 2 로컬 검증: 검사 17건 통과. 모의 DB 응답으로 서버 함수→화면의 네 카드 렌더링, 실패 응답과 로그의 키 비노출, GET 이외 요청 거부, 빈 정적 JSON 유지를 확인했습니다. 임시 PostgreSQL 17에서도 네 건의 원본 일치, service_role의 읽기 허용, anon·authenticated의 읽기 거부와 RLS를 확인했습니다. 실제 Supabase 연결과 배포 화면의 네 카드 확인은 설정 이후에 진행합니다.

## 최신 파일의 가상 메모 문장 검색 절차

아래 두 블록을 작업 폴더의 같은 PowerShell 창에서 순서대로 실행합니다. 검색 기준은 처음 공개했던 커밋의 `data.json`에 있는 네 메모의 `content` 전체 문장입니다. 본문은 메모리에서만 비교하고 출력하지 않습니다. 검색 문장 자체를 README나 새 공개 파일에 복사하지 않습니다. 이 검사는 API 키·로그인·인증 헤더를 사용하지 않습니다.

### 1. GitHub 최신 파일 검색

GitHub 코드 검색 화면의 색인에 의존하지 않고 `origin/main`을 가져와 그 커밋의 모든 추적 파일을 검사합니다. 로컬 작업 파일이나 오래된 원격 추적 정보만 검사한 결과를 GitHub 최신 파일 검사로 기록하지 않습니다.

```powershell
$ErrorActionPreference = 'Stop'
git fetch origin main
if ($LASTEXITCODE -ne 0) { throw 'GitHub 최신 커밋을 가져오지 못했습니다.' }
$scanCommit = (git rev-parse origin/main).Trim()
$scanOldCommit = '82d80ba2582b77f2459d084c361c183f7c68ed8c'
$scanOriginal = ((git show "$($scanOldCommit):data.json") -join "`n") | ConvertFrom-Json
$scanPatterns = @($scanOriginal.notes | ForEach-Object { $_.content })
$scanFiles = @(git ls-tree -r --name-only $scanCommit)
$scanMatches = @()
foreach ($scanFile in $scanFiles) {
  $scanText = (git show "$($scanCommit):$scanFile") -join "`n"
  $scanCount = @($scanPatterns | Where-Object { $scanText.Contains($_) }).Count
  if ($scanCount -gt 0) {
    $scanMatches += [pscustomobject]@{ File = $scanFile; MatchingSentences = $scanCount }
  }
}
[pscustomobject]@{
  Commit = $scanCommit
  FilesChecked = $scanFiles.Count
  MatchingFiles = $scanMatches.Count
}
$scanMatches
```

정상 결과는 `MatchingFiles = 0`입니다. 일치가 있으면 파일 경로와 일치한 문장 종류의 개수만 기록합니다. 다운로드·Git 읽기·JSON 파싱이 실패하면 미확인으로 기록하며, 0건으로 처리하지 않습니다.

### 2. 현재 배포 정적 파일 검색

운영 주소의 응답 원문을 검사합니다. 화면에 보이는 카드만 보고 정적 파일에 본문이 없다고 판단하지 않습니다. 현재 정적 결과물은 `public/index.html`, `public/data.json`, 빌드가 생성하는 `public/aleph.json`이며, `/`도 별도로 확인합니다.

```powershell
$scanApp = 'https://choi-bujang-secret-vault-liard.vercel.app'
foreach ($scanPath in @('/', '/index.html', '/data.json', '/aleph.json')) {
  $scanResponse = Invoke-WebRequest -Uri ($scanApp + $scanPath) -UseBasicParsing `
    -Headers @{ 'Cache-Control' = 'no-cache' } -TimeoutSec 20
  $scanCount = @($scanPatterns | Where-Object { $scanResponse.Content.Contains($_) }).Count
  [pscustomobject]@{
    Path = $scanPath
    Status = [int]$scanResponse.StatusCode
    MatchingSentences = $scanCount
  }
  if ($scanPath -eq '/data.json') {
    [pscustomobject]@{ NoteCount = @(($scanResponse.Content | ConvertFrom-Json).notes).Count }
  }
  if ($scanPath -eq '/aleph.json') {
    $scanIdentity = $scanResponse.Content | ConvertFrom-Json
    [pscustomobject]@{
      DeploymentCommit = $scanIdentity.commit
      SameAsGitHubLatest = $scanIdentity.commit -eq $scanCommit
    }
  }
}
```

정상 결과는 네 경로 모두 `HTTP 200`, `MatchingSentences = 0`, 정적 JSON의 `NoteCount = 0`, `SameAsGitHubLatest = True`입니다. 커밋이 다르면 배포가 최신 GitHub 파일과 다르다고 기록하고, 배포 완료 뒤 다시 검사합니다.

브라우저에서는 **개발자 도구 → Network → Disable cache → 새로고침 → 각 요청의 Response**를 확인합니다. `Sources`에서도 HTML과 연결된 JS·CSS를 검색합니다. 현재 스크립트는 HTML 안에 있지만, 이후 외부 정적 파일이 추가되면 그 파일의 응답까지 같은 기준으로 검사하고 경로를 기록해야 합니다. `/api/notes`는 동적 응답이므로 정적 파일 검색 결과와 분리합니다.

### 검색 결과 기록

확인일: **2026-10-06, 한국시간**. 확인 당시 GitHub `origin/main`과 운영 배포의 커밋은 모두 `743bbb140e5af4f1a22962164e43799d7c1d72f6`이었습니다. 아래는 그 시점의 결과이며, 문서 갱신이나 재배포 뒤에는 위 절차로 최신 커밋을 다시 확인합니다.

| 확인 대상 | 검색 결과 |
|---|---|
| GitHub 최신 커밋의 추적 파일 46개 | 메모 문장 일치 파일 0개, 일치 문장 0건 |
| 운영 배포 `/` | HTTP 200, 일치 문장 0건 |
| 운영 배포 `/index.html` | HTTP 200, 일치 문장 0건 |
| 운영 배포 `/data.json` | HTTP 200, 일치 문장 0건, `notes: []` |
| 운영 배포 `/aleph.json` | HTTP 200, 일치 문장 0건, GitHub 최신 커밋과 일치 |

이 결과는 **검사한 최신 정적 파일과 최신 GitHub 파일에서 원래 메모 문장이 발견되지 않았다**는 뜻입니다. Supabase 권한이나 공개 API의 접근 보호, 옛 파일의 제거, 실제 심판 판정을 증명하지 않습니다.

### 공개 API의 남은 약점과 과거 노출

- 비로그인 `GET /api/notes` 확인 결과: `HTTP 503`, `NOTES_NOT_CONFIGURED`. 현재 미설정으로 조회하지 못한 상태이며, 인증 거부나 방어 성공으로 기록하지 않습니다. 실제 배포의 네 카드 표시는 아직 미확인입니다.
- 구현상 `/api/notes`에는 로그인·소유자 검사가 없습니다. 설정 후에는 비로그인 요청도 서버 전용 키의 권한으로 메모를 읽을 수 있습니다. 정적 파일에서 본문을 지우고 RLS를 켠 것만으로 이 공개 API의 약점이 해결되지는 않습니다. 공개 키를 사용한 Supabase 직접 조회는 심판 확인 항목으로 남깁니다.
- 옛 공개 커밋 `82d80ba2582b77f2459d084c361c183f7c68ed8c`은 현재 `main` 이력의 조상으로 남아 있으며, 그 커밋의 `data.json`에는 네 메모 본문이 있습니다. 최신 파일의 삭제가 과거 공개 커밋의 삭제를 뜻하지 않습니다.
- 옛 Vercel 배포 URL과 파일·캐시의 삭제 또는 접근 차단은 이번 검사에서 확인하지 않았습니다. **옛 공개 커밋과 옛 배포가 남는 한 과거 노출은 해소됐다고 쓰지 않습니다.** 현재도 과거 노출 해소를 주장하지 않습니다.

## 1단계에서 했던 일: 세 걸음

1. GitHub 계정을 만듭니다.
2. 방어전 1단계 카드의 **Deploy** 버튼을 누릅니다. Vercel에 GitHub로 로그인하고, 새 저장소가 **본인 계정의 Public 저장소**인지 확인한 뒤 Deploy를 누릅니다.
3. 배포가 끝나면 화면에 나온 `https://…vercel.app` 주소를 방어전 1단계 카드에 붙여넣고 제출합니다. 저장소 주소나 설정 파일은 적지 않습니다.

1단계에서는 `/`와 `/data.json`에 가상 메모가 공개됐습니다. 현재 2단계 제작 1에서는 공개 목록을 비웠습니다. 1단계 접수와 심판 판정은 포털에서 확인합니다.

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`을 배포합니다. 빌드 명령 `npm run build`는 Vercel이 제공하는 GitHub 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증하고 `public/aleph.json`을 생성합니다. 이 값이 없으면 빌드가 실패하므로, 성공한 것처럼 빈 주소를 내보내지 않습니다. `aleph.json`의 내용만으로 저장소 소유권이나 방어 성공을 인정하지 않습니다. 심판이 공개 저장소의 실제 커밋과 배포된 자료를 따로 대조해야 합니다.

1단계의 `aleph.config.json`에는 주소 자리표시자가 있었습니다. 현재 설정은 실제 저장소·운영 배포 주소와 `step: 2`로 맞췄습니다. `judgeIssuer`는 시작 틀의 값을 보존했습니다. `npm run bundle`과 `bundle-notes.json`은 1단계의 세 걸음에는 포함되지 않습니다.

로컬 화면 확인에는 `node scripts/build-public.mjs --local`을 사용합니다. 로컬 실행은 Vercel 배포나 심판 접수를 증명하지 않습니다. 현재 `src/attack-check.mjs`는 배포된 `/data.json`에 비로그인 요청을 보내 목록이 비었는지 확인하며, 이 결과로 Supabase RLS가 검증됐다고 보고하지 않습니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름도 함께 바꿔야 합니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.
