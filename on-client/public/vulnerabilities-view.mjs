const SOURCE = "https://api.osv.dev/v1/querybatch";
const FAIL = "조회 결과를 표시할 수 없습니다";
// C5-R2: 화면에 보일 오류 문구는 이 표에서만 고른다. 서버·호출부가 넘긴 message 는 쓰지 않는다.
const ERROR_TEXT = Object.freeze({
  CANCELLED: "패키지 조회를 취소했습니다. 이전 결과는 현재 확인 결과가 아닙니다.",
  REQUEST_CANCELLED: "패키지 조회를 취소했습니다. 이전 결과는 현재 확인 결과가 아닙니다.",
  TIMEOUT: "패키지 조회 응답이 늦어 중단했습니다. 잠시 뒤 직접 다시 조회하세요.",
  REQUEST_TIMEOUT: "패키지 조회 응답이 늦어 중단했습니다. 잠시 뒤 직접 다시 조회하세요.",
  CONTRACT_MISMATCH: "패키지 조회 응답 형식을 확인할 수 없습니다. 결과를 표시하지 않습니다.",
  SERVICE_UNAVAILABLE: "패키지 조회를 지금 처리할 수 없습니다. 잠시 뒤 직접 다시 조회하세요.",
  HOST_REJECTED: "허용되지 않은 접속 주소라 조회하지 않았습니다.",
  ORIGIN_REJECTED: "허용되지 않은 화면에서 온 요청이라 조회하지 않았습니다.",
  REQUEST_INVALID: "조회 요청을 처리할 수 없습니다.",
});
const ERROR_TEXT_UNKNOWN = "패키지 조회를 확인할 수 없습니다. 결과를 표시하지 않습니다.";
const SCAN_STATUS = new Set(["not_configured", "not_checked", "unverifiable", "complete", "partial"]);
const PACKAGE_STATUS = new Set(["known_vulnerabilities", "none_found", "unverifiable"]);
const HASH = /^[0-9a-f]{64}$/;
const NAME = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const OSV_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/;

function isFindingId(value) {
  if (typeof value !== "string" || !OSV_ID.test(value) || forbiddenText(value)) return false;
  // Reserved ID families cannot fall through to the generic OSV identifier branch.
  if (/^CVE-/i.test(value)) return /^CVE-\d{4}-\d{4,}$/.test(value);
  if (/^GHSA-/i.test(value)) return /^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/.test(value);
  return true;
}

function isPlain(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function sameKeys(value, allowed) {
  const keys = Reflect.ownKeys(value);
  if (keys.length !== allowed.length) return false;
  for (const key of keys) {
    if (typeof key !== "string" || !allowed.includes(key)) return false;
  }
  return true;
}

function forbiddenText(value) {
  return /[\u0000-\u001f\u007f]/.test(value)
    || /bearer\s+\S+/i.test(value)
    || /sk-[A-Za-z0-9_-]{8,}/.test(value)
    || /private\s*key/i.test(value)
    || /password/i.test(value)
    || /-----BEGIN [A-Z ]*KEY-----/.test(value);
}

function isIso(value) {
  if (typeof value !== "string" || !ISO.test(value)) return false;
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return false;
  // Preserve valid offset and nanosecond source timestamps, but reject normalized invalid dates.
  const day = value.slice(0, 10);
  const midnight = Date.parse(day + "T00:00:00Z");
  return Number.isFinite(midnight) && new Date(midnight).toISOString().slice(0, 10) === day;
}

function identOk(part, rejectNumericLeadingZero) {
  if (part == null) return true;
  const bits = part.split(".");
  for (const bit of bits) {
    if (bit.length < 1) return false;
    if (rejectNumericLeadingZero && /^0\d+$/.test(bit)) return false;
  }
  return true;
}

function isSemver(value) {
  if (typeof value !== "string" || value.length > 100 || forbiddenText(value)) return false;
  const match = SEMVER.exec(value);
  if (!match) return false;
  return identOk(match[4], true) && identOk(match[5], false);
}

function isName(value) {
  return typeof value === "string" && value.length <= 214 && NAME.test(value) && !forbiddenText(value);
}

function isExcluded(value) {
  if (!isPlain(value)) return false;
  const names = sameKeys(value, ["count"]) ? ["count"]
    : sameKeys(value, ["unapproved", "unsupported", "invalid"]) ? ["unapproved", "unsupported", "invalid"] : null;
  return names !== null && names.every(name => Number.isSafeInteger(value[name]) && value[name] >= 0)
    && Number.isSafeInteger(names.reduce((total, name) => total + value[name], 0));
}

const excludedCount = value => Object.hasOwn(value, "count") ? value.count : value.unapproved + value.unsupported + value.invalid;

function isLock(value) {
  return value === 2 || value === 3;
}

function normalizeFinding(value) {
  if (!isPlain(value) || !sameKeys(value, ["id", "modified"])) return null;
  if (!isFindingId(value.id)) return null;
  if (!isIso(value.modified)) return null;
  return { id: value.id, modified: value.modified };
}

function normalizePackage(value, seen) {
  if (!isPlain(value) || !sameKeys(value, ["name", "version", "status", "vulnerabilities", "source", "checkedAt"])) return null;
  if (!isName(value.name) || !isSemver(value.version)) return null;
  if (!PACKAGE_STATUS.has(value.status) || value.source !== SOURCE || !isIso(value.checkedAt)) return null;
  if (!Array.isArray(value.vulnerabilities)) return null;
  const vulnerabilities = [];
  const ids = new Set();
  for (const finding of value.vulnerabilities) {
    const normalized = normalizeFinding(finding);
    if (!normalized || ids.has(normalized.id)) return null;
    ids.add(normalized.id);
    vulnerabilities.push(normalized);
  }
  if (value.status === "known_vulnerabilities" && vulnerabilities.length < 1) return null;
  if (value.status === "none_found" && vulnerabilities.length !== 0) return null;
  const pair = value.name + "\0" + value.version;
  if (seen.has(pair)) return null;
  seen.add(pair);
  return {
    name: value.name,
    version: value.version,
    status: value.status,
    vulnerabilities,
    source: SOURCE,
    checkedAt: value.checkedAt,
  };
}

function normalizeScanInner(value) {
  if (!isPlain(value) || typeof value.status !== "string" || !SCAN_STATUS.has(value.status)) return null;
  if (value.status === "not_configured" || value.status === "unverifiable") {
    const code = value.status === "not_configured" ? "PROJECT_NOT_CONFIGURED" : "LOCKFILE_UNVERIFIABLE";
    if (!sameKeys(value, ["status", "code", "checkedAt", "packages"])) return null;
    if (value.code !== code || !isIso(value.checkedAt)) return null;
    if (!Array.isArray(value.packages) || value.packages.length !== 0) return null;
    return { status: value.status, code, checkedAt: value.checkedAt, packages: [] };
  }
  if (value.status === "not_checked") {
    if (!sameKeys(value, ["status", "code", "lockfileVersion", "lockfileHash", "excluded", "checkedAt", "packages"])) return null;
    if (value.code !== "NO_APPROVED_PACKAGES" || !isLock(value.lockfileVersion)) return null;
    if (typeof value.lockfileHash !== "string" || !HASH.test(value.lockfileHash)) return null;
    if (!isExcluded(value.excluded) || !isIso(value.checkedAt)) return null;
    if (!Array.isArray(value.packages) || value.packages.length !== 0) return null;
    return {
      status: "not_checked",
      code: "NO_APPROVED_PACKAGES",
      lockfileVersion: value.lockfileVersion,
      lockfileHash: value.lockfileHash,
      excluded: { count: excludedCount(value.excluded) },
      checkedAt: value.checkedAt,
      packages: [],
    };
  }
  if (!sameKeys(value, ["status", "lockfileVersion", "lockfileHash", "excluded", "checkedAt", "packages"])) return null;
  if (!isLock(value.lockfileVersion) || typeof value.lockfileHash !== "string" || !HASH.test(value.lockfileHash)) return null;
  if (!isExcluded(value.excluded) || !isIso(value.checkedAt)) return null;
  if (!Array.isArray(value.packages) || value.packages.length > 256) return null;
  const seen = new Set();
  const packages = [];
  let unverifiable = 0;
  for (const item of value.packages) {
    const normalized = normalizePackage(item, seen);
    if (!normalized) return null;
    if (normalized.status === "unverifiable") unverifiable += 1;
    packages.push(normalized);
  }
  if (value.status === "complete" && unverifiable !== 0) return null;
  if (value.status === "partial" && unverifiable < 1) return null;
  return {
    status: value.status,
    lockfileVersion: value.lockfileVersion,
    lockfileHash: value.lockfileHash,
    excluded: { count: excludedCount(value.excluded) },
    checkedAt: value.checkedAt,
    packages,
  };
}

export function normalizeScan(value) {
  try {
    return normalizeScanInner(value);
  } catch {
    return null;
  }
}

function el(document, tag, text) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function field(document, label, value) {
  const row = el(document, "p");
  row.appendChild(el(document, "span", label));
  row.appendChild(el(document, "span", value));
  return row;
}

function sourceLine(document) {
  const row = el(document, "p");
  row.appendChild(el(document, "span", "출처"));
  const link = el(document, "a", SOURCE);
  link.setAttribute("href", SOURCE);
  link.setAttribute("rel", "noopener noreferrer");
  link.setAttribute("target", "_blank");
  row.appendChild(link);
  return row;
}

function packageStatusText(pkg) {
  if (pkg.status === "unverifiable" && pkg.vulnerabilities.length > 0) return "일부 확인 · 전체 조회 확인 불가";
  if (pkg.status === "unverifiable") return "조회 확인 불가";
  if (pkg.status === "known_vulnerabilities") return "알려진 항목 있음";
  return "알려진 항목 없음(조회 시점 기준)";
}

function packageTable(document, packages) {
  const table = el(document, "table");
  const headRow = el(document, "tr");
  for (const label of ["패키지", "버전", "조회 상태", "식별자", "수정 시각", "패키지 조회 시각"]) {
    headRow.appendChild(el(document, "th", label));
  }
  const thead = el(document, "thead");
  thead.appendChild(headRow);
  table.appendChild(thead);
  const tbody = el(document, "tbody");
  for (const pkg of packages) {
    const findings = pkg.vulnerabilities.length > 0 ? pkg.vulnerabilities : [null];
    for (const finding of findings) {
      const row = el(document, "tr");
      row.appendChild(el(document, "td", pkg.name));
      row.appendChild(el(document, "td", pkg.version));
      row.appendChild(el(document, "td", packageStatusText(pkg)));
      row.appendChild(el(document, "td", finding ? finding.id : ""));
      row.appendChild(el(document, "td", finding ? finding.modified : ""));
      row.appendChild(el(document, "td", pkg.checkedAt));
      tbody.appendChild(row);
    }
  }
  table.appendChild(tbody);
  return table;
}

function renderScan(document, root, scan) {
  const lead = {
    not_configured: "프로젝트 연결 준비 중",
    not_checked: "승인된 공개 패키지를 아직 조회하지 않았습니다",
    unverifiable: "설치 목록 확인 불가",
    complete: "조회 완료",
    partial: "일부 조회",
  }[scan.status];
  root.setAttribute("data-scan", scan.status);
  root.appendChild(el(document, "p", lead));
  if (scan.code) root.appendChild(field(document, "코드", scan.code));
  if (scan.lockfileVersion != null) root.appendChild(field(document, "설치 목록 원천", "package-lock.json"));
  if (scan.lockfileVersion != null) root.appendChild(field(document, "잠금 파일 버전", String(scan.lockfileVersion)));
  if (scan.lockfileHash) root.appendChild(field(document, "잠금 파일 해시", scan.lockfileHash));
  if (scan.excluded) root.appendChild(field(document, "조회 제외", String(scan.excluded.count) + "건"));
  root.appendChild(field(document, "조회 시각", scan.checkedAt));
  root.appendChild(sourceLine(document));
  if (scan.packages.length > 0) root.appendChild(packageTable(document, scan.packages));
  else if (scan.status === "complete") root.appendChild(el(document, "p", "표시할 패키지 조회 결과가 없습니다."));
}

export function createVulnerabilitiesView({ document }) {
  if (document == null || typeof document.createElement !== "function") {
    throw new TypeError("document required");
  }
  const root = document.createElement("section");
  root.setAttribute("data-view", "vulnerabilities");

  function render(resource) {
    clear(root);
    const state = isPlain(resource) && (resource.status === "idle" || resource.status === "loading" || resource.status === "error" || resource.status === "ok")
      ? resource.status
      : "error";
    root.setAttribute("data-state", state);
    root.setAttribute("data-scan", "");
    if (state === "idle") {
      root.appendChild(el(document, "p", "조회 대기"));
      return root;
    }
    if (state === "loading") {
      root.appendChild(el(document, "p", "조회 중"));
      return root;
    }
    if (state !== "ok") {
      root.appendChild(el(document, "p", FAIL));
      const error = isPlain(resource) && isPlain(resource.error) ? resource.error : null;
      // C5-R2: 오류 원문(message)은 표시하지 않는다. 알려진 code 는 모듈 안의 고정 문구로, 모르는 code 는 공통 안내로만 보인다.
      const code = error && typeof error.code === "string" && /^[A-Z][A-Z0-9_]{0,63}$/.test(error.code) ? error.code : "";
      if (code) root.appendChild(field(document, "코드", code));
      root.appendChild(el(document, "p", Object.hasOwn(ERROR_TEXT, code) ? ERROR_TEXT[code] : ERROR_TEXT_UNKNOWN));
      root.appendChild(el(document, "p", "이전 조회 결과를 현재 결과로 보지 않습니다. 필요하면 직접 다시 조회하세요."));
      return root;
    }
    const scan = normalizeScan(resource.data);
    if (!scan) {
      root.setAttribute("data-state", "error");
      root.appendChild(el(document, "p", FAIL));
      return root;
    }
    renderScan(document, root, scan);
    return root;
  }

  return { render };
}
