# 공통 AI 연결 모듈 출처

`clco-http.mjs`는 ALEPH Workbench의 `src/clco-http.mjs`를 바탕으로 만든 내부 개발용 파생본입니다. 원 복사본에 유한한 학습지원 요청의 `/learner-support` 메서드·요청 형식 검사·해당 경로의 JSON 응답 형식 검사를 추가했습니다. 해당 경로가 실패해도 chat/completions로 우회하지 않습니다. 기존 models와 chat 메서드는 그대로 사용합니다.

- 원본 작업 폴더: `C:\Work\aleph-workbench`
- 원본 파일 관련 마지막 커밋: `b6fabbd452533abd6ceca76145620cea19c39d0b`
- 원 복사본 SHA-256: `d2d156fd9ce80f7ca53f061257470bc67f1e4459675efbcc78f13285652d5141`입니다. 현재 파생본의 SHA-256은 이번 SOURCE 제출에 따로 기록합니다.
- 원본 저장소는 private 소스이며, 확인한 소스 트리에 LICENSE/NOTICE와 package.json의 license 명시가 없습니다. MIT/Apache/ISC 등 공개 라이선스로 선언하지 않습니다.
- 이번 내부 개발과 로컬 검증의 재사용은 오너의 Workbench 구조 재사용 요청에 따라 허용됐습니다. 학생 배포 패키지에 포함할 수 있는지에 관한 라이선스 검토는 미완료이며, 배포 전 확인해야 합니다.

이 모듈은 서버에서만 사용합니다. Workbench에 저장된 열쇠나 DPAPI 파일은 포함하지 않았습니다.
