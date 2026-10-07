# BYTE BACK 방어전 시작 틀 R5

현재 단계: **4단계 「로그인해도 내 자료만 보이게 합니다」 · 저장점** (2026-10-07).
Supabase Auth 로그인·로그아웃과 가상 메모 CRUD를 보존하고, 모든 메모 API에 서버가 검증한 사용자 ID와 DB의 `owner_id` 비교를 적용했습니다. 비밀번호·토큰·서버 키·실제 개인정보·메모 본문을 Git이나 제출 묶음에 넣지 않습니다.

운영 주소: [내 자료실](https://choi-bujang-secret-vault-liard.vercel.app/). 2026-10-07 공개 배포 식별 조회는 3단계 커밋 `8064ff6c5f02`였습니다. 이 저장점에서는 4단계 운영 배포를 실행하지 않았습니다.

## 현재 기능과 실행

- `data.json`과 `public/data.json`은 확인 표시 없는 `{ "notes": [] }`입니다. 빌드는 메모 원본을 읽거나 복사하지 않습니다.
- 로그인 실패 이유를 화면에 표시하며, 로그아웃하면 자료와 편집 화면을 지웁니다. 가입 화면은 없으며 실습 계정은 Supabase Authentication → Users에서 직접 만듭니다.
- API는 기존 인증 도우미가 확인한 사용자 ID만 사용합니다. URL·본문의 소유자 ID는 인증 근거가 아닙니다. 무로그인·잘못된 인증은 자료 없이 401로 거부합니다.
- `GET /api/notes`는 로그인 사용자의 메모 배열을 반환합니다. `POST /api/notes`는 `{id?,title,body}`를 받아 서버가 확인한 ID를 `owner_id`로 저장하고 `{id}`를 반환합니다. UUID가 없으면 서버가 생성합니다.
- `GET·PUT·DELETE /api/notes/:id`는 기존 행의 소유자가 본인일 때만 처리합니다. 한 건 조회·수정 응답은 `{id,title,body}`, 수정 본문은 `{title,body}`, 추가·삭제 응답은 `{id}`를 유지합니다.
- 수정에서는 소유자로 제한한 기존 행의 제목·본문만 바꾸고 반환된 행의 소유자도 확인합니다. `owner_id`가 포함된 수정은 400 `OWNER_CHANGE_NOT_ALLOWED`, 상대·소유자 없는·존재하지 않는 메모 접근은 404 `NOTE_NOT_FOUND`입니다.
- 기존 가상 메모와 학습 DB를 보존합니다. 소유자 없는 메모는 내 목록에 포함하지 않습니다. 정적 파일에는 가상 메모 본문도 넣지 않습니다.
- 배포 빌드는 현재 단계와 저장소·커밋·배포 URL을 `public/aleph.json`에 기록합니다.
- 로컬 빌드: `node scripts/build-public.mjs --local`.
- 로컬 검사: `node --test test/*.test.mjs`. 로컬 검사는 실제 심판 판정이 아닙니다.

## 4단계 저장점과 다시 실행

`aleph.config.json`은 `step: 4`이며 Git origin·운영 주소·Supabase 발급자 `/auth/v1`·audience `authenticated`·공개 JWKS와 실제 다섯 경로가 구현과 일치합니다. 빌드와 배포 식별 파일도 4단계를 지원합니다. `judgeIssuer`는 보존하고, 5단계부터 사용할 원본 API·복구 경로는 아직 `null`입니다. `src/decider.mjs`에는 실제 기본 거부 규칙 `starter.deny`만 남아 있습니다. 메모 API의 보호는 기존 로그인 도우미와 API 소유자 검사가 담당합니다.

기존 로컬 폴더에서 `.\local-only\start-dev.cmd`로 개발 서버를 시작하고 `http://localhost:3000/`을 엽니다. 새 체크아웃에서는 의존성 설치·Vercel 프로젝트 연결·Development 환경변수 등록 뒤 `npx vercel dev --local-config vercel.dev.json`을 실행합니다. `SUPABASE_URL`과 서버 전용 `SUPABASE_SECRET_KEY` 값은 Vercel의 공식 비밀 입력란에 직접 넣습니다. `.env*`, `.vercel/`, 로컬 도구와 검사 도우미는 Git·제출 묶음에 넣지 않습니다.

화면 확인: **로그인 → 가상 메모 추가 → 수정 → 삭제 → 로그아웃**을 A/B 각각 수행합니다. 정상 사용자는 자기 메모만 조회·추가·수정·삭제할 수 있어야 하고, 상대 메모는 목록에서 숨겨지며 상대 메모 UUID의 GET·PUT·DELETE도 404로 거부되어야 합니다. 소유자 변경 PUT은 400, 무로그인·잘못된 인증은 401이어야 합니다.

로컬 전용 실제 검사 안내는 이 작업 폴더의 `local-only/AB_API_CHECK.md`에 있습니다. `node local-only/ab-check-guide.mjs`로 안내 서버를 켜고, 기존 앱에서 A/B를 번갈아 로그인해 검사판의 **이 계정 기준 저장 → 상대 접근 검사 → 내 메모 최종 확인**을 수행합니다. 비밀번호나 토큰을 출력하지 않고 상태 코드와 보존 여부만 복사합니다. GitHub 새 체크아웃에는 이 로컬 도우미가 포함되지 않습니다.

2026-10-07 사용자가 전달한 `local_actual_api_requests` 결과: A/B 기준 조회 200, 양방향 상대 GET·PUT·DELETE 여섯 건 모두 404, 두 계정의 소유자 변경 PUT 모두 400, 마지막 자기 메모 조회 200 및 내용·소유자 보존 모두 성공했습니다. 모든 항목이 `ok: true`, `complete: true`이며 복구는 필요하지 않았습니다. A/B 자기 메모 추가·수정·삭제와 상대 목록 숨김도 사용자가 정상으로 보고했습니다. 이는 사용자 실행 로컬 결과이며 운영 A/B 검사나 심판 판정이 아닙니다.

학습 DB에는 사용자가 `public.notes`만 대상으로 RLS와 최소 권한 SQL을 적용했습니다. 기존 `PUBLIC`·`anon`·`authenticated` 권한을 회수한 뒤 authenticated에 SELECT·INSERT·UPDATE·DELETE만 부여했습니다. 네 소유자 정책은 `auth.uid() = owner_id`를 사용하며 SELECT·DELETE는 USING, INSERT는 WITH CHECK, UPDATE는 USING과 WITH CHECK를 모두 확인합니다. `information_schema.role_table_grants`와 `has_table_privilege` 결과에서 anon은 권한 없음, authenticated는 CRUD만 허용 및 재부여 권한 없음이 확인됐습니다. RLS 활성화 `true`는 사용자 보고입니다. 서버 전용 키는 RLS를 우회하므로 앱 API에서도 소유자 검사를 유지합니다. 이 저장점 작업에서 DB를 변경하지 않았습니다.

자동 검사 35건이 통과했습니다. 인증·소유자 검사·빌드·자기 점검의 모의 검사는 실제 A/B 인증 요청 결과와 구분합니다. 로컬 검사 도우미의 별도 모의 검사 10건도 이전에 통과했습니다.

2026-10-07 현재 운영 주소에 직접 보낸 자기 점검에서는 정적 메모 0건, 다섯 경로의 무로그인·잘못된 인증 요청 열 건 모두 401, 정적 네 경로 HTTP 200과 1단계 확인 표시 부재를 확인했습니다. 배포 식별은 아직 3단계이므로 4단계 식별 점검은 미확인으로 기록됐고, 운영 A/B 인증 요청은 미실행입니다.

제출 묶음은 저장점 커밋과 운영 배포를 확인한 뒤 `npm run bundle`로 생성합니다. `src/attack-check.mjs`는 실제로 요청한 정적 메모 0건, 다섯 경로의 무로그인·잘못된 인증 401, 4단계 배포 식별과 정적 확인 표시 부재만 기록합니다. 운영 A/B 정상 CRUD·상대 접근·소유자 변경·자료 보존은 인증 요청을 보내지 않으므로 미실행으로 남깁니다. 위 로컬 결과를 운영 자동 점검 성공으로 복사하지 않습니다. `bundle-notes.json`과 `artifacts/submission.json`은 커밋하지 않습니다.

아래 3·2단계 설명은 **각 단계 당시의 기록**입니다. 현재 기능과 권한은 위 4단계 설명을 따릅니다. 과거 Git 커밋과 옛 배포의 노출 해소는 여전히 확인하지 않았습니다.

## 3단계 저장점과 다시 실행

`aleph.config.json`의 `step: 3`, 실제 운영 주소, Supabase 발급자 `/auth/v1`, audience `authenticated`, 공개 JWKS 주소와 실제 다섯 API 경로를 구현에 맞췄습니다. `judgeIssuer`는 변경하지 않았고 원본 API와 복구 경로는 아직 `null`입니다. `src/decider.mjs`의 실제 기본 거부 규칙 `starter.deny`를 보존하며, 자료 API 보호는 기존 로그인 검사 도우미가 담당합니다.

서버 설정은 Vercel → Settings → Environment Variables의 `SUPABASE_URL`과 `SUPABASE_SECRET_KEY`입니다. 운영에는 Production, 로컬에는 Development 환경이 필요합니다. 값은 공식 입력란에 직접 넣습니다. 기존 학습 DB가 읽기 권한만 가진 경우 `docs/STEP3_NOTES_CRUD.sql`을 Supabase SQL Editor에서 실행합니다. 이 SQL은 service_role의 CRUD 권한만 보완하고 기존 메모·소유자·RLS·브라우저 권한을 보존합니다.

다시 실행: 기존 로컬 작업 폴더에서는 `.\local-only\start-dev.cmd`로 Vercel 개발 서버를 시작하고 `http://localhost:3000`을 엽니다. 새 체크아웃은 의존성을 설치하고 기존 Vercel 프로젝트를 연결한 뒤 `npx vercel dev --local-config vercel.dev.json`을 사용합니다. 로컬 빌드는 `node scripts/build-public.mjs --local`로 수행합니다. `file://`로 HTML을 열면 서버 API가 실행되지 않습니다. 로컬 도구·`.vercel/`·`.env*`는 Git과 제출 묶음에서 제외합니다.

사용자가 로컬 A 로그인, 메모 추가·수정·삭제, 로그아웃 후 자료 숨김을 정상으로 보고했습니다. 실제 로컬 무로그인·잘못된 인증 요청의 401을 확인했습니다. 자동 검사 29건이 통과했으며, 모의 DB와 메모리 내 가상 서명으로 인증·CRUD 계약을 검사한 결과는 실제 A 계정 시험이나 심판 판정이 아닙니다. 운영 A 계정의 CRUD 확인은 배포 뒤 별도로 진행합니다.

화면 확인: 운영 주소 → 로그인 → 가상 메모 추가 → 수정 → 삭제 → 로그아웃 순서로 누릅니다. 정상 A는 저장·수정·삭제할 수 있어야 하고, 로그아웃 및 시크릿 창의 무로그인 요청에서는 자료가 보이지 않아야 합니다. 계정 비밀번호·토큰은 채팅이나 파일로 전달하지 않습니다.

제출 묶음은 저장점 커밋과 운영 배포 뒤 `npm run bundle`로 생성합니다. `src/attack-check.mjs`는 정적 메모 0건, 실제로 보낸 다섯 경로의 무로그인·잘못된 인증 거부, 3단계 배포 식별, 정적 확인 표시 부재를 기록합니다. 운영 A의 정상 CRUD는 자동 점검에서 미실행으로 남깁니다. B의 타인 메모 접근도 아직 시험하지 않았습니다. `bundle-notes.json`과 `artifacts/submission.json`은 커밋하지 않습니다.

아래 내용은 **2단계 당시의 기록**입니다. 당시 공개 GET·POST 405·로그인 발급자 null·허용 경로 없음은 과거 상태이며, 현재 3단계 동작은 위 설명을 따릅니다. 과거 Git 커밋과 배포의 노출 해소는 여전히 확인하지 않았습니다.

## 2단계 저장점

2026-10-06 저장점: 정적 JSON의 메모 제거, 본문을 복사하지 않는 빌드, 환경변수를 읽는 Vercel 서버 함수, 서버 API를 호출하는 화면, 최신 파일 검색 절차를 보존했습니다. `step: 2`와 Git 원격·운영 배포 주소가 일치하며 로그인 발급자는 `null`, 허용 경로는 빈 배열입니다. 2단계에는 로그인·소유자 검사를 구현하지 않았습니다. `judgeIssuer`는 원래 값을 보존했고 원본 API·복구 경로는 아직 `null`입니다. 판정기는 실제 구현된 기본 거부 규칙 `starter.deny`만 유지하며, 이 판정기가 공개 메모 API를 보호한다고 주장하지 않습니다.

운영 연결 확인 당시 정적 `/data.json`은 빈 목록, 공개 `GET /api/notes`는 HTTP 200으로 가상 메모 네 건을 반환하고 화면에도 네 카드가 보였습니다. `POST /api/notes`는 405입니다. Supabase 관리자 SELECT로 네 건, `owner_id uuid`, RLS 활성화, anon·authenticated 읽기 권한 없음, service_role 읽기 허용, 외래키·정책 0개를 확인했습니다. 심판의 `S02_MARKER_IN_STATIC` 지적을 수정한 뒤, 사용자가 심판 통과·90점을 보고했습니다. 이번 보안 헤더 추가 뒤 점수는 재제출 결과로 확인해야 합니다. 공개 API의 로그인·소유자 검사와 과거 노출 해소는 완료하지 않았습니다.

심판 지적 수정: 빈 정적 JSON과 배포 식별 JSON에 남은 1단계 확인 표시를 제거했습니다. 2단계 빌드는 이를 생성하지 않고, 로컬 빌드는 예전 배포 식별 파일을 정리합니다. 단계 설정에서도 확인 표시를 제거했습니다. 자기 점검에는 `/`, `/index.html`, `/data.json`, `/aleph.json`의 HTTP 200과 표시 부재를 실제 요청으로 확인하는 항목을 추가했습니다. 1단계 기능은 별도 검사로 보존합니다.

보너스 조건 확인: `/data.json`의 HTTP 200·메모 0건과 `/aleph.json`의 HTTP 200은 운영 요청으로 확인했습니다. 첫 화면에는 보안 헤더가 없어서 `vercel.json`의 모든 경로에 `X-Content-Type-Options: nosniff`를 추가했습니다. 배포 빌드는 `/aleph.json`을 자동 생성하며, 로컬 전용 빌드에서만 예전 배포 식별 파일을 지웁니다. [Vercel의 headers 설정](https://vercel.com/docs/project-configuration/vercel-json#headers)을 따릅니다.

재배포 뒤 보너스 확인 명령: `curl.exe -I https://choi-bujang-secret-vault-liard.vercel.app/`. 정상 결과는 HTTP 200과 `X-Content-Type-Options: nosniff`입니다. 브라우저 개발자 도구 **Network → 첫 화면 요청 → Headers → Response Headers**에서도 확인합니다. `/data.json`은 메모 0건, `/aleph.json`은 HTTP 200이어야 하고 POST 메모 요청은 기존대로 405로 거부돼야 합니다. 세 보너스 조건의 충족 확인과 실제 100점 판정은 구분합니다.

다시 실행: `node scripts/build-public.mjs --local`로 빈 정적 파일을 만들고 `node --test test/*.test.mjs`로 로컬 검사를 실행합니다. 배포 첫 화면과 `/data.json`을 열어 비교하며, 설정 후에는 첫 화면의 네 카드가 정상 결과입니다. POST는 거부되어야 하지만 공개 GET의 성공은 아직 인증 보호를 뜻하지 않습니다.

제출 묶음은 저장점 커밋 후 `npm run bundle`로 만듭니다. 자기 점검 네 항목은 정적 목록, 공개 API 조회, 쓰기 거부, 정적 확인 표시 부재를 실제 요청으로 기록하며 심판 판정과 구분합니다. `bundle-notes.json`과 `artifacts/submission.json`은 Git에 넣지 않습니다. 조회 설정이 완료되어 `blockedAt`은 `null`로 갱신하며, 공개 API와 과거 노출의 한계는 설명에 남깁니다.

## Supabase 가져오기와 운영 확인

새 학습용 프로젝트에서는 `local-only/step2-import.sql`을 **SQL Editor → New query → Database**에 붙여 넣고 **Run**을 누릅니다. 이 파일은 처음 선택한 세 건을 가져옵니다. 이어서 `local-only/step2-complete.sql`을 실행하면 네 번째 메모와 서버 읽기 권한을 보완합니다. 실제 키를 SQL에 입력할 필요는 없습니다. 기존 `public.notes` 테이블이 있으면 첫 파일은 오류로 중단해 기존 자료를 보존하므로, 이미 가져온 운영 프로젝트에 다시 실행하지 않습니다.

현재 운영 `public.notes`에는 가상 메모 네 건이 있습니다. SQL은 `owner_id uuid`를 비워 두고 `auth.users` 외래키와 읽기 정책은 만들지 않으며, RLS를 켜고 `PUBLIC`·`anon`·`authenticated`의 테이블 권한을 회수합니다. 보완 SQL은 기존 세 건을 삭제하지 않고, 같은 네 번째 메모가 있으면 중복 삽입하지 않습니다.

서버 전용 키가 사용하는 `service_role`에는 이 테이블의 SELECT만 명시적으로 부여합니다. 브라우저 역할에는 자료 읽기 권한을 주지 않습니다.

실행 결과는 `note_count = 4`, `owner_id_type = uuid`, `rls_enabled = true`, `anon_can_read = false`, `authenticated_can_read = false`, `foreign_key_count = 0`, `policy_count = 0`이어야 합니다. **Table Editor → notes**에서도 `owner_id` 칸과 RLS 표시를 확인합니다. SQL Editor의 관리자 조회는 허용되고, `anon`·`authenticated`의 읽기는 거부되어야 합니다.

본문이 들어 있는 가져오기·보완 SQL과 네 건의 원본 백업(`local-only/data-before-step2.json`)은 `.gitignore`의 `local-only/`로 Git에서 제외됩니다. 이 폴더는 배포하는 `public/` 밖에 있으며 제출 묶음에도 넣지 않습니다. GitHub 체크아웃에는 가져오기 SQL이 없으므로 이 로컬 작업 폴더에서 실행하세요.

새 정적 파일과 GitHub 최신 파일에는 메모 본문이 없어야 합니다. 이전 Git 커밋에는 1단계에서 공개했던 가상 자료가 남아 있습니다. 2026-10-06 원격 Supabase에서 메모 본문 없는 관리자 SELECT로 위 메타데이터를 확인했습니다. 공개 키를 사용하는 직접 조회는 미실행입니다. 정적 표시 수정 후 통과·90점은 사용자의 보고이며, 보안 헤더 추가 뒤 점수는 아직 확인하지 않았습니다.

제작 1 검증: Node 검사 12건과 임시 PostgreSQL 17의 세 건 가져오기 검사를 통과했습니다. 제작 2의 검증은 아래 절차와 테스트로 구분합니다.

## Vercel 서버 함수 설정과 확인

`api/notes.js`는 서버에서만 `SUPABASE_URL`과 `SUPABASE_SECRET_KEY`를 읽습니다. Supabase REST API에는 서버 키를 `apikey` 헤더로만 보내고, 브라우저에는 `title`·`content`만 반환합니다. Supabase 오류 원문·헤더·환경변수는 응답이나 로그로 내보내지 않습니다. 응답 캐시도 끕니다.

Supabase 프로젝트 설정에서 프로젝트 URL과 서버 전용 Secret key를 확인한 뒤, **Vercel → choi-bujang-secret-vault → Settings → Environment Variables**에 두 이름으로 직접 입력합니다. **Key**에는 `SUPABASE_URL` 또는 `SUPABASE_SECRET_KEY`라는 변수 이름을, **Value**에는 해당 값을 넣습니다. 서버 키는 **Type: Secret**, 환경은 **Production**으로 등록하세요. 키를 채팅·Git·브라우저 소스에 넣지 않습니다. 저장한 뒤 최신 배포를 **Redeploy**해야 새 환경변수가 반영됩니다. 운영 프로젝트는 두 변수의 Production 등록과 재배포 Ready 상태를 확인했습니다. 이번 재확인에서는 비밀 Value를 열지 않고 변수 이름과 적용 환경만 검사했습니다.

정상 확인: 배포 첫 화면에서 네 카드가 보이고 `/api/notes`는 메모 목록을 반환합니다. `/data.json`은 `notes: []`를 유지합니다. 설정이 없으면 함수는 `503 NOTES_NOT_CONFIGURED`, 조회 실패는 민감한 원문 없이 `502 NOTES_UNAVAILABLE`, GET 이외의 요청은 `405 METHOD_NOT_ALLOWED`를 반환해야 합니다. 공개 키로 Supabase를 직접 읽는 요청은 심판이 확인하며, 이 구현에서는 그 검사를 실행했다고 보고하지 않습니다.

**남은 약점:** `/api/notes`는 아직 로그인·소유자 검사 없는 공개 주소입니다. 주소를 아는 누구나 서버 함수를 통해 가상 메모를 읽을 수 있습니다. 서버 전용 키는 RLS를 우회하므로, RLS가 켜졌다는 사실만으로 이 공개 서버 함수의 접근이 보호되지는 않습니다. 인증·소유자 검사는 다음 제작 단계에서 구현합니다.

참고: [Supabase API 키](https://supabase.com/docs/guides/getting-started/api-keys), [Vercel Node.js 함수](https://vercel.com/docs/functions/runtimes/node-js).

이번 저장점의 로컬 검사 19건을 통과했습니다. 모의 DB 응답으로 서버 함수→화면의 네 카드 렌더링, 실패 응답과 로그의 키 비노출, GET 이외 요청 거부, 빈 정적 JSON 유지를 확인했습니다. 복원된 메모·1단계 표시·옛 배포 메타데이터가 빌드로 다시 공개되지 않는지 검사하고, 자기 점검이 네 정적 응답의 표시 잔존과 HTTP 실패를 잡는지 확인했습니다. 임시 PostgreSQL 17에서도 네 건의 원본 일치, service_role의 읽기 허용, anon·authenticated의 읽기 거부와 RLS를 확인했습니다. 운영 연결 확인에서는 첫 화면의 네 카드, 비로그인 GET의 HTTP 200·네 건 반환, POST의 HTTP 405, 정적 JSON의 빈 목록을 확인했습니다. 키를 사용하는 Supabase 직접 요청은 보내지 않았습니다.

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
    Stage1MarkerPresent = $scanResponse.Content.Contains('SAMPLE_NOTE_1')
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

정상 결과는 네 경로 모두 `HTTP 200`, `MatchingSentences = 0`, `Stage1MarkerPresent = False`, 정적 JSON의 `NoteCount = 0`, `SameAsGitHubLatest = True`입니다. 커밋이 다르면 배포가 최신 GitHub 파일과 다르다고 기록하고, 배포 완료 뒤 다시 검사합니다.

브라우저에서는 **개발자 도구 → Network → Disable cache → 새로고침 → 각 요청의 Response**를 확인합니다. `Sources`에서도 HTML과 연결된 JS·CSS를 검색합니다. 현재 스크립트는 HTML 안에 있지만, 이후 외부 정적 파일이 추가되면 그 파일의 응답까지 같은 기준으로 검사하고 경로를 기록해야 합니다. `/api/notes`는 동적 응답이므로 정적 파일 검색 결과와 분리합니다.

### 검색 결과 기록

확인일: **2026-10-06, 한국시간**. 운영 연결 확인 당시 GitHub `origin/main`과 운영 배포의 커밋은 모두 `b3a8f6eba34a3438340b7d7c68410cdec83cbb6c`이었습니다. 아래는 그 시점의 검색 결과입니다. 이 문서 갱신 커밋이 추가되면 위 절차로 최신 파일과 배포 커밋을 다시 확인합니다.

| 확인 대상 | 검색 결과 |
|---|---|
| GitHub 최신 커밋의 추적 파일 46개 | 메모 문장 일치 파일 0개, 일치 문장 0건 |
| 운영 배포 `/` | HTTP 200, 일치 문장 0건 |
| 운영 배포 `/index.html` | HTTP 200, 일치 문장 0건 |
| 운영 배포 `/data.json` | HTTP 200, 일치 문장 0건, `notes: []` |
| 운영 배포 `/aleph.json` | HTTP 200, 일치 문장 0건, GitHub 최신 커밋과 일치 |

이 결과는 **검사한 최신 정적 파일과 최신 GitHub 파일에서 원래 메모 문장이 발견되지 않았다**는 뜻입니다. Supabase 권한이나 공개 API의 접근 보호, 옛 파일의 제거, 실제 심판 판정을 증명하지 않습니다.

당시 문장 검색에는 1단계 확인 표시 검사가 빠져 있었습니다. 심판의 `S02_MARKER_IN_STATIC` 지적에 따라 표시를 제거하고 위 `Stage1MarkerPresent` 검사와 제출 묶음의 정적 표시 점검을 추가했습니다. 사용자가 이 수정 후 재제출에서 통과·90점을 보고했습니다.

### 공개 API의 남은 약점과 과거 노출

- 비로그인 `GET /api/notes` 확인 결과: `HTTP 200`, 메모 네 건 반환. 첫 화면에서도 네 카드 표시를 확인했습니다. 이는 조회 연결의 성공이며 인증 보호 성공이나 실제 심판 판정으로 기록하지 않습니다. `POST /api/notes`는 HTTP 405로 거부됐으며, 이는 메서드 제한입니다.
- 구현상 `/api/notes`에는 로그인·소유자 검사가 없습니다. 비로그인 요청도 서버 전용 키의 권한으로 메모를 읽을 수 있습니다. 정적 파일에서 본문을 지우고 RLS를 켠 것만으로 이 공개 API의 약점이 해결되지는 않습니다. 공개 키를 사용한 Supabase 직접 조회는 심판 확인 항목으로 남깁니다.
- 옛 공개 커밋 `82d80ba2582b77f2459d084c361c183f7c68ed8c`은 현재 `main` 이력의 조상으로 남아 있으며, 그 커밋의 `data.json`에는 네 메모 본문이 있습니다. 최신 파일의 삭제가 과거 공개 커밋의 삭제를 뜻하지 않습니다.
- 옛 Vercel 배포 URL과 파일·캐시의 삭제 또는 접근 차단은 이번 검사에서 확인하지 않았습니다. **옛 공개 커밋과 옛 배포가 남는 한 과거 노출은 해소됐다고 쓰지 않습니다.** 현재도 과거 노출 해소를 주장하지 않습니다.

## 1단계에서 했던 일: 세 걸음

1. GitHub 계정을 만듭니다.
2. 방어전 1단계 카드의 **Deploy** 버튼을 누릅니다. Vercel에 GitHub로 로그인하고, 새 저장소가 **본인 계정의 Public 저장소**인지 확인한 뒤 Deploy를 누릅니다.
3. 배포가 끝나면 화면에 나온 `https://…vercel.app` 주소를 방어전 1단계 카드에 붙여넣고 제출합니다. 저장소 주소나 설정 파일은 적지 않습니다.

1단계에서는 `/`와 `/data.json`에 가상 메모가 공개됐습니다. 현재 2단계 제작 1에서는 공개 목록을 비웠습니다. 1단계 접수와 심판 판정은 포털에서 확인합니다.

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`을 배포합니다. 빌드 명령 `npm run build`는 Vercel이 제공하는 GitHub 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증하고 `public/aleph.json`을 생성합니다. 이 값이 없으면 빌드가 실패하므로, 성공한 것처럼 빈 주소를 내보내지 않습니다. `aleph.json`의 내용만으로 저장소 소유권이나 방어 성공을 인정하지 않습니다. 심판이 공개 저장소의 실제 커밋과 배포된 자료를 따로 대조해야 합니다.

1단계의 `aleph.config.json`에는 주소 자리표시자가 있었습니다. 현재 설정은 실제 저장소·운영 배포 주소와 `step: 4`로 맞췄습니다. `judgeIssuer`는 시작 틀의 값을 보존했습니다. `npm run bundle`과 `bundle-notes.json`은 1단계의 세 걸음에는 포함되지 않습니다.

로컬 화면 확인에는 `node scripts/build-public.mjs --local`을 사용합니다. 로컬 실행은 Vercel 배포나 심판 접수를 증명하지 않습니다. 현재 `src/attack-check.mjs`는 배포된 `/data.json`에 비로그인 요청을 보내 목록이 비었는지 확인하며, 이 결과로 Supabase RLS가 검증됐다고 보고하지 않습니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름도 함께 바꿔야 합니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.
