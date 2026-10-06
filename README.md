# BYTE BACK 방어전 시작 틀 R5

현재 단계: **2단계 「자료를 코드 밖으로 옮깁니다」 · 제작 1** (2026-10-06).
이 저장소는 1단계 R5 시작 틀에서 이어졌습니다. 공개 메모 본문을 제거했으며, Supabase로 옮기는 SQL을 로컬에 준비했습니다. 실제 학생 자료, 토큰, 비밀키를 넣지 마세요.

## 현재 기능과 실행

- `data.json`과 `public/data.json`은 빈 메모 목록입니다. 빌드는 메모 원본을 읽거나 복사하지 않습니다.
- 자료실 화면은 공개 메모가 없음을 표시합니다. Supabase 자료 조회 API는 아직 연결하지 않았습니다.
- 배포 빌드는 현재 단계와 저장소·커밋·배포 URL을 `public/aleph.json`에 기록합니다.
- 로컬 빌드: `node scripts/build-public.mjs --local`.
- 로컬 검사: `node --test test/*.test.mjs`. 로컬 검사는 실제 심판 판정이 아닙니다.

## Supabase 가져오기 — SQL Editor에서 실행 필요

`local-only/step2-import.sql`을 학습용 Supabase 프로젝트의 **SQL Editor → New query**에 붙여 넣고 **Run**을 누릅니다. 실제 키를 입력할 필요는 없습니다. 기존 `public.notes` 테이블이 있으면 SQL은 오류로 중단해 기존 자료를 보존합니다. 새 테이블에 한 번만 실행하세요.

SQL은 가상 메모 세 건을 `public.notes`에 넣고, `owner_id uuid`를 비워 둡니다. `auth.users` 외래키와 읽기 정책은 만들지 않으며 RLS를 켜고 `PUBLIC`·`anon`·`authenticated`의 테이블 권한을 회수합니다.

실행 결과는 `note_count = 3`, `owner_id_type = uuid`, `rls_enabled = true`, `anon_can_read = false`, `authenticated_can_read = false`, `foreign_key_count = 0`, `policy_count = 0`이어야 합니다. **Table Editor → notes**에서도 `owner_id` 칸과 RLS 표시를 확인합니다. SQL Editor의 관리자 조회는 허용되고, `anon`·`authenticated`의 읽기는 거부되어야 합니다.

본문이 들어 있는 가져오기 SQL과 네 건의 원본 백업(`local-only/data-before-step2.json`)은 `.gitignore`의 `local-only/`로 Git에서 제외됩니다. 이 폴더는 배포하는 `public/` 밖에 있으며 제출 묶음에도 넣지 않습니다. GitHub 체크아웃에는 가져오기 SQL이 없으므로 이 로컬 작업 폴더에서 실행하세요.

새 정적 파일과 GitHub 최신 파일에는 메모 본문이 없어야 합니다. 이전 Git 커밋에는 1단계에서 공개했던 가상 자료가 남아 있습니다. 원격 Supabase에서의 SQL 실행과 실제 심판 판정은 아직 확인하지 않았습니다.

로컬 검증: Node 검사 12건 통과. 임시 PostgreSQL 17에서 SQL 실행, 세 건의 원본 일치, `owner_id uuid`, RLS, 외래키 없음, `anon`·`authenticated` 읽기 거부를 확인했습니다. 임시 읽기 권한을 줘도 RLS는 두 역할에 0행을 반환했고, 재실행은 기존 자료를 변경하지 않고 중단했습니다.

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
