# 스타터 설치와 업데이트

`tools/install.mjs`는 학생 프로젝트 아래 `on-client`에 수업 스타터를 처음 놓거나, 이미 설치된 제공 파일만 고친다. 기본 실행은 디스크에 쓰지 않는 dry-run이다. `apply: true` 또는 CLI `--apply`가 있을 때만 `on-client`를 만든다.

Node.js 22에서 24의 기본 모듈만 사용한다. 별도 패키지는 설치하지 않는다.

## 쓰기 전에

1. 학생 프로젝트에서 git 저장점을 만든다. 커밋하지 않은 변경이 있으면 그 변경도 저장점에 남긴다.
2. dry-run을 실행하고 `added`, `updated`, `preserved`, `conflicts`를 읽는다.
3. `preserved`에 들어 있는 학생 파일은 diff로 확인한다. 도구는 그 파일을 새 템플릿으로 덮지 않는다.
4. 제공 파일과 학생 수정이 겹치면 학생이 직접 병합한다.

```bash
node tools/install.mjs --source <스타터 디렉터리> --project <학생 프로젝트>
node tools/install.mjs --source <스타터 디렉터리> --project <학생 프로젝트> --apply
```

`--source`와 `--project`는 값이 필요하다. 알 수 없는 인자는 거절한다. 실패하면 종료 코드 1과 오류 코드만 출력한다. 환경 변수와 키는 출력하지 않는다.

## 무엇을 복사하는가

스타터에서 다음만 후보이다.

- `package.json`
- `README.md`
- `.env.example`
- `docs/STUDENT_PROMPTS.md`
- `docs/IMPLEMENTATION_CONTRACT.md`
- `docs/STARTER_UPDATE.md`
- `docs/CURRICULUM.json`
- `docs/AI_SETUP_GUIDE.md`, `docs/PRODUCT_OVERVIEW.md`
- 학생 런타임 `src/**` (`src/learning/**` 내부 검사·원장 코드는 제외)
- `public/**`
- `student/**`
- `vendor/**`
- `tools/app-credentials.ps1` 한 경로: 앱 자격 보관함의 Windows DPAPI helper

스타터에 아직 없는 일반 경로는 건너뛴다. `.env`와 `.env.*`(루트의 빈 설정 예시만 제외), 키, `receipts`, `tools`의 위 helper 이외 모든 파일, `test`, `.git`, `node_modules`와 그 밖의 임의 파일은 복사하지 않는다. Windows 대소문자 차이로 비밀 이름을 우회할 수 없고 hard link도 거절한다. 개발 원본의 운영 작업 상태·내부 검수 문서는 학생 런타임 문서가 아니다.

앱 helper가 있는 새 제공본은 소스 `.on-starter-manifest.json`에 `tools/app-credentials.ps1`의 실제 SHA-256이 기록돼 있어야 한다. helper의 실제 바이트와 다르거나 manifest가 없거나, manifest에 선언한 helper가 누락되면 `ERR_HELPER_SOURCE_UNVERIFIABLE`로 학생 파일을 쓰기 전에 거절한다. manifest의 해시만으로 제공 주체를 인증하지는 않으며 소스와 제공 manifest는 신뢰된 운영 측에서 공급해야 한다. 일반 `tools/**` 허용으로 범위를 넓히지 않는다.

helper 업데이트도 기존 manifest 기준선과 학생 로컬 변경 보존 규칙을 따른다. 학생이 helper를 수정했으면 덮어쓰지 않고 `preserved`로 안내한다. 제공본 자체의 새 필수 런타임 목록은 [STARTER_PACKAGING.md](STARTER_PACKAGING.md)를 따른다. 이번 계약 수정으로 기존 고정 ZIP이 자동으로 갱신되지는 않는다.

상한은 파일 512개, 한 파일 1MiB, 합계 10MiB이다. 해시는 파일 바이트 원문의 SHA-256이다.

소스와 프로젝트는 실제 디렉터리여야 한다. 둘 중 하나가 심볼릭 링크나 정션이거나, 같은 경로이거나, 한쪽이 다른 쪽 안에 있으면 쓰지 않는다. 쓰려는 파일의 부모 경로가 링크여도 거절한다.

## 처음 설치

`project/on-client`가 없으면 허용 목록 파일을 새로 만들고 `.on-starter-manifest.json`에 소스 해시를 기록한다.

`on-client`가 이미 있는데 매니페스트가 없으면 학생 파일인지 확인하지 않는다. 이 경우는 `ERR_UNVERIFIABLE`이며 파일을 쓰지 않는다. 기존 파일 하나를 덮어쓰지 않기 위해 설치 전체를 멈춘다.

## 업데이트

첫 설치 결과의 `manifestDigest`는 운영 측 설치 영수증처럼 학생이 수정하는 파일과 분리해 보관한다. 업데이트에는 이 신뢰된 이전 digest를 `expectedManifestDigest` 또는 CLI `--baseline-manifest-sha256`으로 공급해야 한다. 대상 파일에서 지금 계산한 digest를 입력하는 방식은 기준선 검증이 아니다. 값이 없거나 실제 매니페스트와 다르면 어떤 파일도 업데이트하지 않는다.

```powershell
node tools/install.mjs --source <스타터 디렉터리> --project <학생 프로젝트> --baseline-manifest-sha256 <기존 영수증 digest>
node tools/install.mjs --source <스타터 디렉터리> --project <학생 프로젝트> --baseline-manifest-sha256 <기존 영수증 digest> --apply
```

검증한 매니페스트의 `sourceHashes`가 이전 제공 버전이다.

- 제공 파일의 현재 내용이 이전 소스 해시와 같고 스타터 해시가 바뀌었으면 그 파일만 업데이트한다.
- 학생이 제공 파일을 고쳤으면 `preserved`로 남긴다. 매니페스트의 이전 소스 해시도 유지한다.
- `student/**`는 처음 추가한 뒤 다시 업데이트하지 않는다. 학생이 지운 학생 파일은 다시 만들지 않는다.
- 스타터에 새로 생긴 파일이 대상에 이미 있으면 보존한다.
- 기존 파일은 삭제하지 않는다. 학생이 따로 만든 파일도 삭제하지 않는다.

매니페스트가 깨졌거나 형식이 다르면 `ERR_MANIFEST_INVALID`이며 쓰지 않는다.

적용 호출은 프로젝트 안의 배타적 잠금을 사용한다. 다른 updater가 실행 중이면 `ERR_INSTALL_BUSY`다. 제공 파일은 원문을 자르지 않고 같은 폴더의 임시 파일에 완성한 뒤, 대상의 hash와 파일 identity를 다시 확인해 교체한다. 사용자가 편집 중인 파일은 적용 전에 저장하고 dry-run 결과를 확인한다. 적용 후 새 `manifestDigest`로 설치 영수증을 갱신한다.

## 실패한 설치

쓰는 도중 실패하면 성공으로 보고하지 않는다. 라이브러리 반환값에는 이번 호출에서 기록한 `written`과 `ERR_WRITE`가 있다. 이미 쓴 파일을 자동으로 되돌리거나 지우거나 다른 원본으로 바꾸지 않는다.

매니페스트는 대상 파일 기록이 끝난 뒤, 같은 `on-client` 루트인지 확인한 임시 파일을 이름 바꾸기하여 교체한다. 학생 프로젝트 디렉터리 자체는 이름 바꾸기하지 않는다.

매니페스트가 있는 업데이트는 다시 실행해도 학생 수정 파일을 덮지 않는다. 이미 새 스타터 내용과 같아진 제공 파일은 그 해시를 매니페스트에 맞춘다. 첫 설치가 매니페스트를 남기기 전에 끊기면 그 디렉터리는 확인 불가가 된다. 부분적으로 생긴 파일을 도구가 지우지 않으므로, 학생이 살릴 파일을 옮긴 다음 디렉터리를 직접 정리하고 다시 설치한다.

## 롤백

롤백은 학생 파일을 도구가 되돌리는 절차가 아니다. 학생 원본과 `preserved` 파일은 그대로 둔다. git 저장점과 diff로 이번 업데이트의 제공 파일만 검토하고, 필요한 제공 파일만 저장점에서 되돌린다.

## 운영 도구로 업데이트하기

`tools/student-update.mjs`는 강사·운영자용 한글 안내 도구입니다. `installStarter`를 그대로 호출하며 설치 규칙을 넓히지 않습니다. 학생 앱 실행 파일이 아니고, 학생에게 실행을 맡기지 않습니다.

```powershell
# 1) 미리보기: 아무것도 쓰지 않습니다
node tools/student-update.mjs --source <시작 틀 폴더> --project <학생 Workbench 작업 폴더> [--baseline-manifest-sha256 <보관한 기록값>]
# 2) 결과를 읽은 뒤 같은 명령에 --apply 를 붙여 적용합니다
node tools/student-update.mjs --source <시작 틀 폴더> --project <학생 Workbench 작업 폴더> [--baseline-manifest-sha256 <보관한 기록값>] --apply
```

- 경로는 항상 직접 적습니다. 현재 폴더를 짐작해 쓰지 않습니다. 공백과 한글이 들어간 경로도 됩니다.
- 처음 설치할 때는 기록값 없이 적용합니다. 출력의 「새 기준 기록값」을 학생 이름과 함께 운영 기록에 보관합니다.
- 이미 설치된 프로젝트는 보관한 기록값이 있어야 적용됩니다.
  - 값이 없으면 `ERR_BASELINE_REQUIRED`, 다르면 `ERR_BASELINE_MISMATCH`이고, 두 경우 모두 아무것도 쓰지 않습니다.
  - 대상 폴더에서 지금 계산한 값을 기준으로 넣지 않습니다.
- 출력은 「새로 넣을 파일 / 바꿀 파일 / 학생 파일로 보존」 개수와 보존 경로입니다. 실패하면 `멈춤: <코드> · <설명>`을 보여 주고 종료 코드 1로 끝납니다. 자동으로 다시 시도하거나 강제로 적용하지 않습니다.
- 적용 결과가 확인되지 않으면(`ERR_WRITE`·`ERR_CONFLICT`·`ERR_INSTALL_BUSY`) 성공으로 기록하지 않습니다. 미리보기부터 다시 실행합니다. 삭제·reset·clean·재설치로 복구하지 않습니다.
- 확인 범위: `test/student-launch.check.mjs`의 업데이트 도구 시험 3건(공백·한글 임시 경로, 합성 시작 틀)입니다. 실제 배포 ZIP과 실제 학생 폴더에서는 확인하지 않았습니다.

학생용 실행 방법은 [STUDENT_LAUNCH_GUIDE.md](STUDENT_LAUNCH_GUIDE.md)를 봅니다.

## 오류 코드

`ERR_ARGS`, `ERR_SOURCE_MISSING`, `ERR_PROJECT_MISSING`, `ERR_NOT_DIRECTORY`, `ERR_SYMLINK`, `ERR_HARDLINK`, `ERR_SAME_PATH`, `ERR_NESTED`, `ERR_LIMIT`, `ERR_MANIFEST_INVALID`, `ERR_UNVERIFIABLE`, `ERR_BASELINE_REQUIRED`, `ERR_BASELINE_MISMATCH`, `ERR_INSTALL_BUSY`, `ERR_CONFLICT`, `ERR_READ`, `ERR_WRITE`, `ERR_IO`, `ERR_INTERNAL`.

최초 코드는 Grok CLI가 작성했습니다. Codex가 범위를 확인해 반영하고, 학생 파일 보존을 위한 수정과 독립 검증을 수행했습니다.
