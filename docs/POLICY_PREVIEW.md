# 10단계 제작 1: 안전 정책 차이 미리보기

실행 명령: `npm run policy:preview`. 터미널에서 `restoreVersion`, `scope`,
`changedFiles`, `changes`를 확인합니다. 이 명령에는 복원·승인·배포 기능이 없습니다.
운영 판정기·다른 서비스 규칙·DB·감사 이력·설정을 변경하지 않습니다.
Git 방식에서는 운영 파일을 시험 정책으로 지정하지 못하도록 파일 식별자만 확인합니다.
`aleph.config.json`의 단계와 `restoreRoute`는 이번 제작에서 변경하지 않습니다.

방어전 **10단계 → 만들기 1: 제작 1**의 확인 항목과 터미널 보고서를 대조하세요.
정상 결과는 복원 후보 버전과 시험 정책에서 안전 사본으로 바뀔 줄 범위입니다.
`trial`은 없어질 시험 정책 줄, `safeCopy`는 돌아올 사본 줄이며 `startLine`은
1부터 시작합니다. `lineCount: 0`은 그 위치의 삽입 또는 삭제 경계를 뜻합니다.
같은 파일이면 변경 파일·범위는 빈 배열, 추가·삭제 줄 수는 0입니다.
원문 코드·메모·개인정보·비밀값은 보고서에 출력하지 않습니다.

## Git 사본과 당시 검증 기록 연결

기본 명령은 사용자가 지정한 Git 커밋
`a446a9a793f7712d0f0bf0d72b44e30a1eec0b26`의 `src/decider.mjs`와
같은 커밋의 README 9단계 검증 기록을 직접 읽습니다. Git checkout·fetch·reset,
정책 코드 실행, 파일 생성·쓰기를 하지 않습니다. Git replacement도 사용하지 않습니다.
짧은 별칭으로 다른 버전을 선택하지 않도록 전체 커밋 ID를 고정했습니다.

이 커밋은 한국시간 2026-10-13 17:24:57에 기록됐고 README에는 당시 전체
로컬 검사 108건·탐지 연습 6건·판정기 연습 10건·로컬 빌드 통과가 기재돼
있습니다. 이는 당시 저장된 로컬 검사 기록이며 독립된 안전 인증이나 심판
판정이 아닙니다. 현재 다시 통과한 검사를 과거 검증 기록으로 사용하지 않습니다.

현재 폴더에서 별도의 시험 정책과 침해 시각 기록은 발견하지 못했습니다.
기본 실행은 Git 사본을 읽은 다음 `INCIDENT_TIME_MISSING`으로 중단합니다.
운영 `src/decider.mjs`를 시험 정책으로 자동 지정하거나 사본을 복사해
가짜 시험 정책·침해 시각을 만들지 않습니다.

| 기본 입력 위치 | 필요한 자료 |
|---|---|
| `local-only/policy-preview/trial-decider.mjs` | 별도로 확인한 현재 시험 정책 파일 |
| `local-only/policy-preview/incident.json` | 운영자가 확인한 침해 시각과 기준 커밋 연결 기록 |

Git 방식의 침해 기록은 `incidentAt`, `source`, `baselineCommit` 세 항목만
포함해야 합니다. `source`는 `operator_confirmed`, `baselineCommit`은 위 전체
커밋 ID, `incidentAt`은 확인된 UTC ISO 시각(밀리초와 `Z` 포함)입니다.
서명 파일은 이 방식에서 요구하지 않습니다. **이 로컬 파일은 운영자가 실제
사건 기록을 확인했다는 신뢰 경계입니다. 프로그램이 사건 시각의 진위를
독립적으로 입증하지는 못합니다.** 실제 근거 없이 값을 만들거나 커밋 뒤의
임의 시각으로 채우지 마세요. 침해 전에 저장된 검증 기록이 확인될 때만 사용합니다.

프로그램은 Git 사본·당시 통과 기록·침해 기록의 형식을 확인하고, 검증 기록의
커밋 시각이 침해보다 엄격히 이른지 검사합니다. 커밋 시각은 검증 결과가 이미
기록돼 있었던 시점으로만 쓰며 실제 검사 시각으로 출력하지 않습니다.
침해 시각이 없거나 형식 오류·미래·검증 기록 이전 또는 같은 시각이면 중단합니다.
시험 정책이 없으면 `TRIAL_POLICY_MISSING`, 운영 파일을 직접 지정하면
`TRIAL_POLICY_IS_OPERATIONAL`로 거부합니다. 실패 시 차이·복원 후보 보고서는 없습니다.

다른 위치의 **기존 시험 파일·확인한 사건 기록**을 읽으려면 다음을 사용합니다.

`npm run policy:preview -- --git-backup a446a9a --trial <시험 정책 파일> --incident-record <확인한 침해 기록>`

정상 결과에는 `restoreVersion`, `verificationRecordedAt`, 검증 기록 종류와
지문, 두 정책 지문 및 변경 범위만 나옵니다. 비교와 시간 확인은 로컬 자료를
대상으로 하며 실제 운영 정책 복구·접속 차단을 증명하지 않습니다.

## 기존 서명 사본 방식

`--inputs` 또는 `--trust-key`를 명시한 명령은 기존 서명 사본 방식을 사용합니다.
이 방식도 검증 자료가 없으면 중단합니다. 아래 서명 규격은 제작 1에서 만든
로컬 선택 방식이며 공식 방어전의 필수 규격이 아닙니다.

다음은 이 기능의 **로컬 전용 계약**입니다. 운영 엔진이나 심판의 복구 계약이
아니며, 정책 대상은 `src/decider.mjs` 한 파일로 제한합니다.

| 위치 | 필요한 자료 |
|---|---|
| `local-only/policy-preview/safe-decider.mjs` | 침해 전에 검증한 정책의 원본 바이트 |
| `local-only/policy-preview/safe-receipt.json` | 신뢰한 검증자가 서명한 아래 검증 기록 |
| `local-only/policy-preview/safe-receipt.sig` | 기록 원본 바이트에 대한 Ed25519 서명, 바이너리 64바이트 |
| `local-only/policy-preview/trial-decider.mjs` | 현재 시험 정책 사본. 코드를 실행하지 않고 비교만 함 |
| `local-only/policy-preview/incident.json` | 확인된 침해 시각을 담은 `{"incidentAt":"UTC ISO 시각"}` |
| `local-only/policy-trust/public-key.pem` | 침해 전부터 별도로 신뢰한 검증자의 Ed25519 공개키 |

공개키의 출처는 백업과 독립된 신뢰 경로에서 확인해야 합니다. 사본과 함께 온
새 공개키를 자동으로 신뢰하지 않습니다. 비밀키는 입력으로 받거나 생성·저장하지
않습니다. 기존 `.gitignore`가 `local-only/`를 제외하므로 이 자료는 Git·제출 묶음에
넣지 않습니다. 공식 사본의 형식이 다르면 서명 근거를 보존하는 별도 연결이 필요합니다.

검증 기록은 다음 여섯 항목만 포함해야 합니다.

| 항목 | 조건 |
|---|---|
| `schema` | `aleph.policy-safe-copy.v1` |
| `version` | 검증한 버전 ID. 소문자 영숫자로 시작하고 영숫자·점·밑줄·하이픈만, 최대 64자 |
| `scope` | `src/decider.mjs` |
| `verifiedAt` | 침해 시각보다 엄격히 이른 UTC ISO 시각, 밀리초와 `Z` 포함 |
| `verification` | `passed` |
| `policySha256` | 사본 원본 바이트의 SHA-256, 소문자 16진수 64자 |

검증자가 실제 안전 정책 검사 후 발급한 서명 기록만 사용합니다. 프로그램은
서명·사본 지문·대상·검증 결과·시각을 확인하며, 정책의 안전성을 새로 판정하지
않습니다. 서명이 없거나 변조되면 `SAFE_COPY_VERIFICATION_FAILED` 또는
`SAFE_COPY_VERIFICATION_MISSING`, 신뢰 공개키가 없으면 `TRUST_ANCHOR_MISSING`,
검증이 침해 이후이거나 침해 시각이 미래·형식 오류이면
`PRE_INCIDENT_VERIFICATION_REQUIRED` 등으로 중단합니다. 실패 시 후보 보고서는 없습니다.

다른 로컬 위치를 읽으려면 `--inputs <사본·시험 파일 폴더> --trust-key <독립된 공개키 파일>`을
명령 뒤에 붙입니다. 원문은 오류에도 출력하지 않습니다. 최대 256 KiB·2,000줄
정책만 비교합니다. 보고서의 두 지문은 미리보기 시점에 읽은 바이트를 식별합니다.
후속 제작에서 실제 적용 기능을 붙일 때는 대상·버전·시험 정책 지문을 다시 검증해야 합니다.

개발 검사: `node --test test/policy-preview.test.mjs`. 검사 사본과 서명은 메모리 및
임시 폴더의 가상 자료만 사용합니다. 로컬 검사 통과는 실제 사본 확보·정책 복원·
운영 연결·심판 통과를 뜻하지 않습니다.
