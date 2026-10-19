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
        `${device?.label ?? '확인 불가'} (ID: ${device?.id ?? '확인 불가'}) · ${deviceLabels[device?.status] ?? '확인 불가'} (${device?.status ?? 'unknown'})`;
      const sessionText = (session) =>
        `ID: ${session?.id ?? '확인 불가'} · ${sessionLabels[session?.status] ?? '확인 불가'} (${session?.status ?? 'unknown'})`;
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
    renderDecision({ status, mode, data, error, appId }) {
      const root = document.createElement('div');
      const addText = (tag, text) => {
        const element = document.createElement(tag);
        element.textContent = text;
        root.append(element);
      };
      const modeLabels = {
        demo: '예제 자료',
        disconnected: '연결 없음',
        unknown: '연결 상태 확인 불가',
      };
      addText('h3', '업무 앱 접근 판정');
      if (Object.hasOwn(modeLabels, mode)) addText('p', modeLabels[mode]);
      addText('p', `업무 앱 ID: ${appId ?? data?.appId ?? '선택 전'}`);

      if (status === 'idle') {
        addText('p', '업무 앱을 골라 접속을 요청하세요.');
      } else if (status === 'loading') {
        addText('p', '판정 확인 중');
      } else if (status === 'error') {
        const message = typeof error?.message === 'string' && error.message.trim()
          ? error.message : '오류 내용을 확인할 수 없습니다.';
        addText('p', `요청 실패: ${message}`);
        addText('p', '요청 실패는 접근 거부 판정이 아닙니다. 접근 판정을 확인할 수 없습니다.');
      } else if (status === 'ok') {
        const labels = {
          allow: '접근 허용',
          deny: '접근 거부',
          challenge: '추가 인증 또는 확인 필요',
          unknown: '판정 확인 불가',
        };
        const decision = Object.hasOwn(labels, data?.decision) ? data.decision : 'unknown';
        addText('p', `${labels[decision]}(${decision})`);
        if (decision === 'unknown' && typeof data?.decision === 'string' && data.decision !== 'unknown') {
          addText('p', `수신한 판정 값: ${data.decision}`);
        }
        addText('p', `판정 이유: ${data?.reason ?? '확인 불가'}`);
        addText('p', `판정 시각: ${data?.checkedAt ?? '확인 불가'}`);
        if (decision === 'allow') addText('p', '정책상 접근 허용이며, 실제 앱 접속 성공을 보장하지 않습니다.');
        if (decision === 'challenge') addText('p', '이 앱은 추가 인증이나 확인 절차를 대신 수행하지 않습니다.');
        if (decision === 'unknown') addText('p', '접근 판정을 확인할 수 없습니다.');
      } else {
        addText('p', '판정 확인 불가(unknown): 요청 상태를 확인할 수 없습니다.');
      }
      return root;
    },
    renderEvents({ status, mode, data, error }) {
      // 새 입력마다 목록과 상세를 새로 만들어 이전 자료를 남기지 않습니다.
      const root = document.createElement('div');
      const addText = (parent, tag, text) => {
        const element = document.createElement(tag);
        element.textContent = text;
        parent.append(element);
        return element;
      };
      const kindLabels = { access: '접속 기록', xdr: 'XDR 경보' };
      const stateLabels = {
        access: { allowed: '접속 허용', denied: '접속 거부', unknown: '확인 불가' },
        session: { active: '활성', expired: '만료', revoked: '철회됨', unknown: '확인 불가' },
        device: { compliant: '보안 기준 충족', noncompliant: '보안 기준 미충족', unknown: '확인 불가' },
      };
      const stateText = (type, value) => {
        const code = value ?? 'unknown';
        const labels = stateLabels[type];
        return `${Object.hasOwn(labels, code) ? labels[code] : '확인 불가'}(${code})`;
      };
      const kindText = (kind) =>
        `${Object.hasOwn(kindLabels, kind) ? kindLabels[kind] : '종류 확인 불가'}(${kind})`;
      const appText = (appId) => appId || '앱을 확인할 수 없습니다';
      addText(root, 'h3', '내 접속 기록과 XDR 경보');
      addText(root, 'p', '현재 등록 정보와 대조한 본인 기록입니다. XDR 경보는 이미 저장된 경보입니다.');
      const modeLabels = { demo: '예제 자료', disconnected: '연결 없음', unknown: '연결 상태 확인 불가' };
      if (Object.hasOwn(modeLabels, mode)) addText(root, 'p', modeLabels[mode]);

      if (status === 'loading') {
        addText(root, 'p', '기록을 불러오는 중입니다.');
        return root;
      }
      if (status === 'error') {
        const message = typeof error?.message === 'string' && error.message.trim()
          ? error.message : '오류 내용을 확인할 수 없습니다.';
        addText(root, 'p', `기록을 불러오지 못했습니다: ${message}`);
        if (error?.code === 'CONTRACT_MISMATCH') {
          addText(root, 'p', '응답 형식이 맞지 않아 기록을 확인할 수 없습니다.');
        }
        return root;
      }
      if (status !== 'ok' || !Array.isArray(data)) {
        addText(root, 'p', '기록 확인 불가(unknown): 기록 자료를 확인할 수 없습니다.');
        return root;
      }

      // 받은 배열을 복사해 정렬하고, 필터는 서버 요청 없이 이 목록에만 적용합니다.
      const events = [...data].sort((a, b) => Date.parse(b.at) - Date.parse(a.at));
      const filters = document.createElement('div');
      root.append(filters);
      const makeFilter = (name, values, describe) => {
        const label = document.createElement('label');
        addText(label, 'span', `${name} `);
        const select = document.createElement('select');
        select.setAttribute('aria-label', name);
        const all = addText(select, 'option', '전체');
        all.value = 'all';
        for (const value of [...new Set(values)].sort()) {
          const option = addText(select, 'option', describe(value));
          option.value = value;
        }
        select.value = 'all';
        label.append(select);
        filters.append(label);
        return select;
      };
      const kindFilter = makeFilter('기록 종류', events.map(event => event.kind), kindText);
      const appFilter = makeFilter('업무 앱', events.map(event => event.appId).filter(Boolean), appText);
      const accessFilter = makeFilter('접속 상태', events.map(event => event.state.access), value => stateText('access', value));
      const count = addText(root, 'p', '');
      count.setAttribute('aria-live', 'polite');
      const list = document.createElement('ul');
      root.append(list);

      const renderEntries = (parent, title, entries) => {
        addText(parent, 'h4', title);
        if (entries.length === 0) {
          addText(parent, 'p', `${title} 없음`);
          return;
        }
        const items = document.createElement('ul');
        for (const entry of entries) addText(items, 'li', `${entry.id}: ${entry.text}`);
        parent.append(items);
      };
      const renderList = () => {
        list.replaceChildren();
        const filtered = events.filter(event =>
          (kindFilter.value === 'all' || event.kind === kindFilter.value)
          && (appFilter.value === 'all' || event.appId === appFilter.value)
          && (accessFilter.value === 'all' || event.state.access === accessFilter.value));
        count.textContent = events.length === 0 ? '표시할 기록이 없습니다.'
          : filtered.length === 0 ? '선택한 조건에 맞는 기록이 없습니다.'
          : `받은 기록 ${events.length}건 중 ${filtered.length}건 표시`;
        for (const event of filtered) {
          const row = document.createElement('li');
          row.setAttribute('data-student-event-id', event.id);
          addText(row, 'p', `사건 ID: ${event.id} · 시각: ${event.at} · 종류: ${kindText(event.kind)} · 업무 앱: ${appText(event.appId)}`);
          addText(row, 'p', event.summary);
          const button = addText(row, 'button', `${event.id} 상세`);
          button.type = 'button';
          button.setAttribute('aria-expanded', 'false');
          const detailHost = document.createElement('div');
          row.append(detailHost);
          button.addEventListener('click', () => {
            const expanded = button.getAttribute('aria-expanded') === 'true';
            detailHost.replaceChildren();
            button.setAttribute('aria-expanded', String(!expanded));
            if (expanded) return;
            const detail = document.createElement('section');
            detail.setAttribute('data-student-event-detail', event.id);
            addText(detail, 'h4', `사건 ID: ${event.id}`);
            addText(detail, 'p', `업무 앱: ${appText(event.appId)}`);
            renderEntries(detail, '근거', event.evidence);
            renderEntries(detail, '규칙', event.rules);
            addText(detail, 'p', `접속 상태: ${stateText('access', event.state.access)}`);
            addText(detail, 'p', `세션 상태: ${stateText('session', event.state.session)}`);
            addText(detail, 'p', `기기 상태: ${stateText('device', event.state.device)}`);
            detailHost.append(detail);
          });
          list.append(row);
        }
      };
      for (const select of [kindFilter, appFilter, accessFilter]) select.addEventListener('change', renderList);
      renderList();
      return root;
    },
    renderStatus() { return '학생 구현 대기: 기기·세션·알림과 연결 점검 상태를 구분하세요.'; },
    renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
    renderAiConnection() { return '학생 구현 대기: 모델 응답 점검과 실제 사건 설명을 구분하고 AI 오류·취소·수동 복구를 안내하세요.'; },
    renderExplanation() { return '학생 구현 대기: 선택한 사건의 근거·규칙·현재 상태와 AI 설명을 연결하세요. 제안은 자동 실행하지 않습니다.'; },
    renderAction() { return '학생 구현 대기: 현재 사건·조치·실제 대상·사람 확인·ACK와 원천 효과·unknown을 구분하세요.'; },
  };
}
