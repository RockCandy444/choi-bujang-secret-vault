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
            if (Array.isArray(event.supportedActions) && event.supportedActions.length > 0) {
              addText(detail, 'p', '아직 지원하지 않는 조치입니다. 조치 실행 연결은 준비 중입니다.');
              for (const action of event.supportedActions) {
                const unsupported = addText(detail, 'button', `${action} 미지원`);
                unsupported.type = 'button';
                unsupported.disabled = true;
              }
            }
            detailHost.append(detail);
          });
          list.append(row);
        }
      };
      for (const select of [kindFilter, appFilter, accessFilter]) select.addEventListener('change', renderList);
      renderList();
      return root;
    },
    renderStatus({ devices, sessions, notifications, diagnostics, mode }) {
      // 매번 새 DOM을 반환하므로 새 조회 결과에 이전 목록이나 오류가 남지 않습니다.
      const root = document.createElement('div');
      const addText = (parent, tag, text) => {
        const element = document.createElement(tag);
        element.textContent = text;
        parent.append(element);
        return element;
      };
      const valueText = value => typeof value === 'string' && value.trim() ? value : '확인 불가';
      const modeLabels = { demo: '예제 자료', disconnected: '연결 없음', unknown: '연결 상태 확인 불가' };
      const deviceLabels = { compliant: '보안 기준 충족', noncompliant: '보안 기준 미충족', unknown: '확인 불가' };
      const sessionLabels = { active: '활성', expired: '만료', revoked: '철회됨', unknown: '확인 불가' };
      addText(root, 'h3', '기기·현재 연결·알림과 진단 정보');
      if (Object.hasOwn(modeLabels, mode)) addText(root, 'p', modeLabels[mode]);
      const renderResource = (title, resource, renderData, idleText) => {
        const section = document.createElement('section');
        addText(section, 'h4', title);
        if (Object.hasOwn(modeLabels, resource?.mode)) addText(section, 'p', modeLabels[resource.mode]);
        if (resource?.status === 'loading') {
          addText(section, 'p', `${title}: 불러오는 중`);
        } else if (resource?.status === 'error') {
          const code = valueText(resource.error?.code);
          const timeout = /(?:^|_)TIMEOUT$/.test(code) ? ' (시간 초과)' : '';
          addText(section, 'p', `${title} 조회에 실패했습니다${timeout}: ${valueText(resource.error?.message)} (code: ${code})`);
          addText(section, 'p', title === '진단 정보'
            ? '진단 정보는 제공 화면의 도움정보 불러오기 버튼을 직접 눌러 다시 조회하세요.'
            : '다시 시도는 위쪽 다시 불러오기 버튼을 직접 누르세요.');
        } else if (resource?.status === 'ok') {
          renderData(section, resource.data);
        } else if (resource?.status === 'idle') {
          addText(section, 'p', idleText);
        } else {
          addText(section, 'p', `${title}: 조회 상태 확인 불가`);
        }
        root.append(section);
      };
      const renderList = (section, data, emptyText, describe) => {
        if (!Array.isArray(data)) {
          addText(section, 'p', '응답 형식을 확인할 수 없어 목록 확인 불가');
        } else if (data.length === 0) {
          addText(section, 'p', emptyText);
        } else {
          const list = document.createElement('ul');
          for (const item of data) addText(list, 'li', describe(item));
          section.append(list);
        }
      };
      renderResource('등록 기기', devices, (section, data) => {
        renderList(section, data, '등록된 기기가 없음', device => {
          const status = valueText(device?.status);
          return `기기 이름(label): ${valueText(device?.label)} · 상태(status): ${Object.hasOwn(deviceLabels, status) ? deviceLabels[status] : '확인 불가'} (${status})`;
        });
      }, '등록 기기를 아직 조회하지 않았습니다. 위쪽 다시 불러오기 버튼을 직접 누르세요.');
      addText(root, 'p', '세션 조회 범위는 현재 검증된 연결 한 개입니다. 지난 세션 전체 목록은 제공하지 않습니다.');
      renderResource('현재 세션', sessions, (section, data) => {
        renderList(section, data, '현재 연결 없음', session => {
          const status = valueText(session?.status);
          return `세션 ID(id): ${valueText(session?.id)} · 상태(status): ${Object.hasOwn(sessionLabels, status) ? sessionLabels[status] : '확인 불가'} (${status})`;
        });
      }, '현재 세션을 아직 조회하지 않았습니다. 위쪽 다시 불러오기 버튼을 직접 누르세요.');

      const alerts = document.createElement('section');
      addText(alerts, 'h4', '알림');
      if (!Array.isArray(notifications)) {
        addText(alerts, 'p', '알림 확인 불가');
      } else if (notifications.length === 0) {
        addText(alerts, 'p', '알림 없음: 주의할 알림이 없습니다.');
      } else {
        const list = document.createElement('ul');
        for (const notification of notifications) {
          const item = document.createElement('li');
          addText(item, 'p', `자료(resource): ${valueText(notification?.resource)}`);
          addText(item, 'p', `코드(code): ${valueText(notification?.code)}`);
          addText(item, 'p', `내용(message): ${valueText(notification?.message)}`);
          list.append(item);
        }
        alerts.append(list);
      }
      root.append(alerts);

      let helpText = '';
      renderResource('진단 정보', diagnostics, (section, data) => {
        if (data == null || (typeof data === 'object' && !Array.isArray(data) && Object.keys(data).length === 0)) {
          addText(section, 'p', '표시할 진단 정보가 없습니다.');
          return;
        }
        if (typeof data !== 'object' || Array.isArray(data)) {
          addText(section, 'p', '응답 형식이 맞지 않아 진단 정보 확인 불가');
          return;
        }
        // 전체 응답을 복사하지 않고 계약의 여섯 문자열만 새 객체에 담습니다.
        const safe = {
          requestId: valueText(data.requestId),
          component: valueText(data.component),
          version: valueText(data.version),
          checkedAt: valueText(data.checkedAt),
          engine: { mode: valueText(data.engine?.mode), code: valueText(data.engine?.code) },
        };
        for (const key of ['requestId', 'component', 'version', 'checkedAt']) addText(section, 'p', `${key}: ${safe[key]}`);
        addText(section, 'p', `engine.mode: ${safe.engine.mode}`);
        addText(section, 'p', `engine.code: ${safe.engine.code}`);
        helpText = JSON.stringify(safe, null, 2);
      }, '진단 정보를 아직 조회하지 않았습니다. 제공 화면의 도움정보 불러오기 버튼을 직접 누르세요.');
      addText(root, 'p', '도움정보 복사는 도움 요청에 사용할 위의 진단 항목 6개를 복사합니다. 버튼을 누를 때만 클립보드에 복사합니다.');
      const copy = addText(root, 'button', '도움정보 복사');
      copy.type = 'button';
      copy.disabled = !helpText;
      const copyStatus = addText(root, 'p', helpText ? '표시된 진단 정보를 확인한 뒤 복사하세요.' : '복사할 진단 정보가 없습니다.');
      copyStatus.setAttribute('role', 'status');
      copyStatus.setAttribute('aria-live', 'polite');
      copy.addEventListener('click', async () => {
        if (!helpText || copy.disabled) return;
        copy.disabled = true;
        try {
          await navigator.clipboard.writeText(helpText);
          copyStatus.textContent = '도움정보를 클립보드에 복사했습니다.';
        } catch {
          copyStatus.textContent = '도움정보를 복사하지 못했습니다. 클립보드 권한을 확인한 뒤 도움정보 복사 버튼을 직접 다시 누르세요.';
        } finally {
          copy.disabled = false;
        }
      });
      return root;
    },
    renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
    renderAiConnection({ status, mode, data, error, checkedAt }) {
      // 상태를 보관하지 않고 현재 입력만 표시합니다. 재요청은 제공 버튼이 담당합니다.
      const root = document.createElement('section');
      const addText = (tag, text) => {
        const element = document.createElement(tag);
        element.textContent = text;
        root.append(element);
      };
      const valueText = value => typeof value === 'string' && value.trim() ? value : '확인 불가';
      addText('h3', 'AI 연결 점검');
      if (mode === 'demo') addText('p', '예제 자료(demo)입니다. 실제 계정의 AI 연결을 확인한 결과가 아닙니다.');
      if (mode === 'disconnected') addText('p', '현재 연결 없음(disconnected)');
      if (status === 'idle') {
        addText('p', 'AI 연결 점검 전입니다. 아직 점검을 실행하지 않았습니다.');
      } else if (status === 'loading') {
        addText('p', 'AI 연결 점검 중입니다. 아직 결과를 받지 않았습니다.');
      } else if (status === 'ok') {
        const labels = { test: '시험 연결 점검(test)', verified: '앱 권한 확인 후 점검(verified)' };
        if (data?.transportChecked === true && Object.hasOwn(labels, data?.audienceAuthorization)
          && Number.isInteger(data?.modelCount) && data.modelCount >= 0) {
          addText('p', labels[data.audienceAuthorization]);
          addText('p', `응답 모델 수: ${data.modelCount}개`);
          addText('p', `점검 시각: ${valueText(checkedAt)}`);
          addText('p', '연결만 점검했으며 사건 설명은 아직 실행하지 않았습니다. 사건 설명은 보안 기록에서 별도로 요청하고 확인하세요.');
          if (data.modelCount === 0) addText('p', '쓸 수 있는 모델이 없습니다. 담당자에게 모델 허용 설정을 확인하세요.');
        } else {
          addText('p', 'AI 연결 점검 결과 확인 불가: 응답 형식을 확인할 수 없습니다. 담당자에게 확인하세요.');
        }
      } else if (status === 'error') {
        // error는 제공 화면이 정리한 안전한 code·message만 받습니다. 전체 응답은 출력하지 않습니다.
        const code = valueText(error?.code);
        const guidance = {
          ON_AI_PROVISIONING_PENDING: '권한 준비 중입니다. 학생 코드의 문제가 아니므로 담당자에게 계정 연결과 앱 권한 준비를 확인해 달라고 요청하세요.',
          ON_AI_TRANSPORT_PENDING: 'AI 연결 준비 중입니다. 담당자에게 연결 준비 상태를 확인하세요.',
          AI_REQUEST_UNVERIFIED: '연결 또는 응답 확인 불가입니다. 담당자에게 계정 연결과 앱 권한을 확인해 달라고 요청하세요.',
          ON_AI_AUTHORIZATION_CHANGED: '점검 도중 이용 권한이 바뀌었습니다. 담당자에게 현재 계정 연결과 앱 권한을 확인하세요.',
          WB_CLCO_AUTH_REQUIRED: '인증 실패입니다. 계정 연결과 AI 앱 승인 상태를 다시 확인하고 담당자에게 문의하세요.',
          WB_CLCO_ACCESS_BLOCKED: '접근 제한 상태입니다. 담당자에게 앱 이용 권한을 확인하세요.',
          WB_CLCO_COHORT_BUDGET_EXHAUSTED: '반의 AI 사용량이 소진됐습니다. 담당자에게 사용량을 확인하세요.',
          WB_CLCO_LIMIT_REACHED: 'AI 이용 한도에 도달했습니다. 담당자에게 한도를 확인하세요.',
          WB_CLCO_SESSION_CLOSED: '현재 AI 이용 시간이 아닙니다. 허용된 이용 시간을 확인하세요.',
          WB_CLCO_RATE_LIMITED: '요청 제한 상태입니다. 잠시 뒤 AI 연결 점검 버튼을 직접 누르세요.',
          WB_CLCO_TIMEOUT: 'AI 응답 시간 초과입니다. 잠시 뒤 직접 다시 점검하세요.',
          REQUEST_TIMEOUT: '서버 응답 시간 초과입니다. 잠시 뒤 직접 다시 점검하세요.',
          ENGINE_TIMEOUT: '서버 확인 시간 초과입니다. 잠시 뒤 직접 다시 점검하세요.',
          TIMEOUT: 'AI 응답 시간 초과입니다. 잠시 뒤 직접 다시 점검하세요.',
          WB_CLCO_NETWORK_ERROR: '네트워크 연결 오류입니다. 연결 상태를 확인한 뒤 직접 다시 점검하세요.',
          NETWORK_ERROR: '네트워크 연결 오류입니다. 연결 상태를 확인한 뒤 직접 다시 점검하세요.',
          WB_CLCO_SERVER_UNAVAILABLE: 'AI 서버에 연결할 수 없습니다. 잠시 뒤 직접 다시 점검하세요.',
          WB_CLCO_CANCELLED: '점검을 취소했습니다. 이전 응답은 현재 결과가 아닙니다.',
          CANCELLED: '점검을 취소했습니다. 이전 응답은 현재 결과가 아닙니다.',
          REQUEST_CANCELLED: '점검을 취소했습니다. 이전 응답은 현재 결과가 아닙니다.',
          MODEL_NOT_CONFIGURED: '사용할 모델 설정을 확인할 수 없습니다. 담당자에게 모델 허용 설정을 확인하세요.',
          ON_AI_MODEL_LIST_EMPTY: '쓸 수 있는 모델이 없습니다. 담당자에게 모델 허용 설정을 확인하세요.',
        };
        addText('p', `AI 연결 점검 오류 · 코드: ${code}`);
        addText('p', `내용: ${valueText(error?.message)}`);
        addText('p', Object.hasOwn(guidance, code) ? guidance[code] : '원인을 확인할 수 없습니다. 담당자에게 오류 코드와 발생 시각을 알려 주세요.');
      } else {
        addText('p', 'AI 연결 점검 상태 확인 불가');
      }
      addText('p', '자동으로 다시 점검하지 않습니다. 다시 점검하려면 제공 화면의 AI 연결 점검 버튼을 직접 누르세요.');
      return root;
    },
    renderExplanation({ event, explanation, checkedAt }) {
      // 제공 화면은 선택·새로고침 시 이전 요청을 무효화하고 이 함수를 다시 호출합니다.
      // 매번 새 요소를 반환하며, 근거 검사를 마친 성공 화면에만 성공 속성을 붙입니다.
      const root = document.createElement('section');
      const addText = (tag, text) => {
        const element = document.createElement(tag);
        element.textContent = text;
        root.append(element);
      };
      const valueText = value => typeof value === 'string' && value.trim() ? value : '확인 불가';
      const fail = message => {
        addText('p', `AI 사건 설명 실패: ${message}`);
        if (explanation?.error?.code) addText('p', `코드: ${valueText(explanation.error.code)}`);
        addText('p', '기록은 그대로입니다. AI 연결이나 응답 문제는 과제 실패가 아닙니다.');
        return root;
      };
      const addList = (title, entries) => {
        addText('h4', title);
        if (entries.length === 0) return addText('p', '없음');
        const list = document.createElement('ul');
        for (const text of entries) {
          const item = document.createElement('li');
          item.textContent = text;
          list.append(item);
        }
        root.append(list);
      };
      addText('h3', 'AI 설명(참고용)');
      // 입력 오류는 event가 null일 수 있으므로 선택 안내보다 먼저 보여 줍니다.
      if (explanation?.status === 'error') return fail(valueText(explanation.error?.message));
      if (!event) {
        addText('p', '보안 기록에서 기록을 먼저 고르세요.');
        return root;
      }
      if (explanation?.status === 'loading') {
        addText('p', 'AI 사건 설명 요청 중입니다. 아직 설명 결과를 받지 않았습니다.');
        return root;
      }
      if (explanation?.status === 'idle') {
        addText('p', 'AI 사건 설명 요청 전입니다. 보안 기록에서 사건을 선택해 AI 설명 요청 버튼을 직접 누르세요.');
        return root;
      }
      if (explanation?.status !== 'ok') return fail('설명 요청 상태 확인 불가');

      const data = explanation.data;
      if (data?.executed === true) return fail('AI가 이미 실행했다고 답한 설명은 사용할 수 없습니다.');
      if (typeof event.id !== 'string' || !event.id.trim()
        || !Array.isArray(event.evidence) || event.evidence.length === 0
        || !Array.isArray(event.rules) || event.rules.length === 0) {
        return fail('사건 근거·규칙이 부족하여 설명을 사용할 수 없습니다.');
      }
      const evidence = new Map(event.evidence.map(entry => [entry.id, entry.text]));
      const refsMatch = refs => Array.isArray(refs) && refs.length > 0
        && new Set(refs).size === refs.length && refs.every(id => evidence.has(id));
      if (!refsMatch(data?.evidenceIds) || data.evidenceIds.length !== evidence.size) {
        return fail('근거가 현재 기록과 맞지 않아 설명을 사용할 수 없습니다.');
      }
      if (typeof data.summary !== 'string' || !data.summary.trim()
        || data.requiresHumanConfirmation !== true || data.executed !== false
        || !Array.isArray(data.proposals) || !Array.isArray(event.supportedActions)
        || data.proposals.some(proposal => !proposal || !event.supportedActions.includes(proposal.action)
          || !refsMatch(proposal.evidenceIds) || typeof proposal.reason !== 'string' || !proposal.reason.trim())) {
        return fail('설명·조치 제안의 응답 형식을 확인할 수 없습니다.');
      }

      root.setAttribute('data-student-explanation-event', event.id);
      addText('p', `사건 ID: ${event.id}`);
      addText('p', 'AI 설명은 해석입니다. 사실 판단은 인용한 근거 글과 연동 시스템이 알려 준 현재 상태를 기준으로 하세요.');
      addText('p', data.summary);
      addText('p', `확인 시각: ${valueText(checkedAt)}`);
      if (explanation.mode === 'demo') addText('p', '예제 설명(demo)입니다. 실제 AI 사건 설명의 성공을 확인한 결과가 아닙니다.');
      addList('인용한 근거', data.evidenceIds.map(id => `${id} — ${evidence.get(id)}`));
      addList('현재 규칙', event.rules.map(rule => `${rule.id} — ${rule.text}`));
      const stateNames = { access: '접속', session: '세션', device: '기기' };
      addList('확인되지 않은 현재 상태', Object.keys(stateNames)
        .filter(key => event.state?.[key] === 'unknown')
        .map(key => `${stateNames[key]}: 확인 불가(unknown)`));
      addText('h4', '조치 제안');
      if (data.proposals.length === 0) {
        addText('p', event.supportedActions.length === 0
          ? '연동 시스템이 지원하는 조치가 없어 제안이 없습니다(정상).'
          : 'AI가 제안한 조치가 없습니다.');
      } else {
        for (const proposal of data.proposals) {
          addText('p', `${proposal.action} — ${proposal.reason} (근거: ${proposal.evidenceIds.join(', ')})`);
        }
      }
      addText('p', '제안은 사람 확인이 필요하며 실행되지 않았습니다. 설명·제안만으로 보안 조치가 실행되지는 않습니다.');
      return root;
    },
    renderAction({ status, event, actionId, target, receipt, observation, message, confirmationExpiresAt, error }) {
      // 제공 화면이 이전 표시를 교체하므로 호출마다 현재 입력만 담은 새 DOM을 반환합니다.
      // 확인 티켓·집행·중복 방지·조회 순서는 제공 화면이 담당합니다.
      const root = document.createElement('section');
      const addText = (tag, text) => {
        const element = document.createElement(tag);
        element.textContent = text;
        root.append(element);
      };
      const present = value => (typeof value === 'string' && value.trim())
        || (typeof value === 'number' && Number.isFinite(value));
      const addValue = (label, value) => {
        if (present(value)) addText('p', `${label}: ${value}`);
      };
      const labels = {
        idle: '아직 미실행(idle)',
        loading: '조치 준비 또는 결과 조회 중(loading). 결과를 기다리고 있습니다.',
        prepared: '준비됨·미실행(prepared). 실제 대상과 확인 기한을 읽고 사람이 확인해야 합니다.',
        executing: '서버에 전달 중(executing). 처리 결과는 아직 확인되지 않았습니다.',
        pending: '서버 접수·처리 중(pending). 접수 응답(ACK)은 실제 효과가 아닙니다. 처리 결과는 아직 확인되지 않았습니다.',
        succeeded: observation?.effectApplied === true
          ? '효과 확인(succeeded)'
          : '결과 불명(unknown). 받은 상태는 succeeded이나 실제 효과가 확인되지 않았습니다. 성공이나 효과 없음으로 판단하지 마세요.',
        denied: '거절(denied). 연동 시스템이 조치를 거절했습니다.',
        failed: '실패(failed). 연동 시스템의 조치 처리가 실패했습니다.',
        unknown: '결과 불명(unknown). 성공이나 효과 없음으로 판단하지 마세요.',
        expired: '확인 기한 지남(expired). 현재 사건에서 조치를 다시 준비하세요.',
        error: '요청 처리 안 됨(error). 오류 코드와 내용을 확인하세요.',
      };
      addText('h3', '조치 요청 상태와 실제 결과');
      addText('p', Object.hasOwn(labels, status) ? labels[status] : '결과 불명(unknown). 요청 상태를 확인할 수 없습니다.');
      // 이 속성은 현재 입력의 연결 표시이며, 실행 성공을 뜻하지 않습니다.
      if (typeof event?.id === 'string' && event.id.trim()) {
        root.setAttribute('data-student-action-event', event.id);
      }
      if (typeof receipt?.requestId === 'string' && receipt.requestId.trim()) {
        root.setAttribute('data-student-action-request', receipt.requestId);
      }
      addValue('사건 ID(event.id)', event?.id);
      if (Array.isArray(event?.evidence)) {
        for (const evidence of event.evidence) addValue('근거 ID(event.evidence.id)', evidence?.id);
      }
      addValue('조치(actionId)', actionId);
      addValue('실제 대상(target.id)', target?.id);
      addValue('대상 세대(target.generation)', target?.generation);
      addValue('요청 ID(receipt.requestId)', receipt?.requestId);
      addValue('접수 ID(receipt.receiptId)', receipt?.receiptId);
      addValue('결과 버전(receipt.version)', receipt?.version);
      addValue('사람 확인 기한(confirmationExpiresAt)', confirmationExpiresAt);
      if (status === 'succeeded' && observation?.effectApplied === true) {
        addValue('관측 시각(observation.observedAt)', observation.observedAt);
        addText('p', 'effectApplied: true');
      }
      if (receipt?.replayed === true) {
        addText('p', '기존 요청의 응답입니다(replayed: true). 새 실행으로 표시하거나 중복 집행하지 않습니다.');
      }
      addValue('안내', message);
      addValue('오류 코드(error.code)', error?.code);
      addValue('오류 내용(error.message)', error?.message);
      if (status === 'unknown' || (status === 'succeeded' && observation?.effectApplied !== true)
        || !Object.hasOwn(labels, status)) {
        addText('p', '조치를 다시 집행하지 말고 제공 화면의 「연동 시스템 결과만 재조회」(현재 제공 화면 이름: 「원천 결과만 재조회」)로 결과만 확인하세요.');
      }
      if (Array.isArray(event?.supportedActions) && event.supportedActions.length === 0) {
        addText('p', '연동 시스템이 지원하는 조치가 없어 「조치 준비」 버튼이 나오지 않는 것이 정상입니다.');
      }
      addText('p', 'AI 제안은 실행이 아닙니다. 지원 조치가 있으면 제공 화면의 「조치 준비」에서 실제 대상·근거·기한을 확인한 뒤 「대상과 조치를 확인했으며 집행합니다」로 사람이 확인합니다.');
      addText('p', '「조치 화면 취소」는 화면을 초기화하며, 이미 서버에 전달된 조치 효과를 되돌리지 않습니다.');
      return root;
    },
  };
}
