// 이 파일은 학생이 같은 프로젝트에서 이어서 구현합니다.
// 제공 UI를 받은 것만으로 단계 완료를 인정하지 않습니다.
export function createStudentView() {
  return {
    renderIdentity({ me, devices, sessions }) {
      // 새 입력마다 새 DOM을 반환해 이전 계정이나 오류 전 자료를 재사용하지 않습니다.
      const root = document.createElement('div');
      const deviceLabels = {
        compliant: '보안 기준 충족',
        noncompliant: '보안 기준 미충족',
        unknown: '확인 불가',
      };
      const sessionLabels = {
        active: '활성',
        expired: '만료',
        revoked: '철회됨',
        unknown: '확인 불가',
      };
      const modeLabels = {
        demo: '예제 자료',
        disconnected: '연결 없음',
        unknown: '확인 불가',
      };
      const addText = (parent, tag, text) => {
        const element = document.createElement(tag);
        element.textContent = text;
        parent.append(element);
        return element;
      };
      const deviceText = (device) =>
        `${device?.label ?? '확인 불가'} (ID: ${device?.id ?? '확인 불가'}) · ${deviceLabels[device?.status] ?? '확인 불가'}`;
      const sessionText = (session) =>
        `ID: ${session?.id ?? '확인 불가'} · ${sessionLabels[session?.status] ?? '확인 불가'}`;
      const renderResource = (title, resource, renderData) => {
        const section = document.createElement('section');
        addText(section, 'h3', title);
        if (Object.hasOwn(modeLabels, resource?.mode)) {
          addText(section, 'p', modeLabels[resource.mode]);
        }
        if (resource?.status === 'loading') {
          addText(section, 'p', '불러오는 중');
        } else if (resource?.status === 'error') {
          addText(section, 'p', `연결 실패: ${resource.error?.message ?? '확인 불가'}`);
        } else if (resource?.status === 'ok') {
          renderData(section, resource.data);
        } else {
          addText(section, 'p', '확인 불가');
        }
        root.append(section);
      };

      renderResource('현재 로그인', me, (section, data) => {
        addText(section, 'p', `사용자: ${data?.user?.label ?? '확인 불가'} (ID: ${data?.user?.id ?? '확인 불가'})`);
        addText(section, 'p', `현재 기기: ${deviceText(data?.device)}`);
        addText(section, 'p', `현재 세션: ${sessionText(data?.session)}`);
      });
      renderResource('내 기기', devices, (section, data) => {
        if (!Array.isArray(data)) {
          addText(section, 'p', '확인 불가');
        } else if (data.length === 0) {
          addText(section, 'p', '등록된 기기 없음');
        } else {
          const list = document.createElement('ul');
          for (const device of data) addText(list, 'li', deviceText(device));
          section.append(list);
        }
      });
      renderResource('내 세션', sessions, (section, data) => {
        if (!Array.isArray(data)) {
          addText(section, 'p', '확인 불가');
        } else if (data.length === 0) {
          addText(section, 'p', '세션 없음');
        } else {
          const list = document.createElement('ul');
          for (const session of data) addText(list, 'li', sessionText(session));
          section.append(list);
        }
      });
      return root;
    },
    renderDecision() { return '학생 구현 대기: 서버의 판정과 이유를 연결하세요.'; },
    renderEvents() { return '학생 구현 대기: 본인 접속·XDR 기록을 연결하세요.'; },
    renderStatus() { return '학생 구현 대기: 기기·세션·알림과 연결 점검 상태를 구분하세요.'; },
    renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
    renderAiConnection() { return '학생 구현 대기: 모델 응답 점검과 실제 사건 설명을 구분하고 AI 오류·취소·수동 복구를 안내하세요.'; },
    renderExplanation() { return '학생 구현 대기: 선택한 사건의 근거·규칙·현재 상태와 AI 설명을 연결하세요. 제안은 자동 실행하지 않습니다.'; },
    renderAction() { return '학생 구현 대기: 현재 사건·조치·실제 대상·사람 확인·ACK와 원천 효과·unknown을 구분하세요.'; },
  };
}
