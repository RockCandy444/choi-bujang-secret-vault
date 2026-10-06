import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { deploymentIdentity } from './deployment-identity.mjs';

const root = resolve(import.meta.dirname, '..');
const output = resolve(root, 'public', 'data.json');
const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));
if (config.step !== 2) {
  throw new Error('현재 빌드는 2단계의 빈 공개 자료 목록만 생성합니다.');
}
if (typeof config.sampleMarker !== 'string' || !/^[A-Z0-9_]{1,80}$/u.test(config.sampleMarker)) {
  throw new Error('가상 자료 확인 표시 형식을 확인하세요.');
}
await mkdir(resolve(root, 'public'), { recursive: true });
// Never read or copy note bodies from data.json or the local import files.
await writeFile(output, `${JSON.stringify({ sampleMarker: config.sampleMarker, notes: [] }, null, 2)}\n`, 'utf8');
console.log('메모 본문 없는 공개 자료 목록을 생성했습니다.');
if (!process.argv.includes('--local')) {
  const identity = deploymentIdentity(process.env, config);
  await writeFile(resolve(root, 'public', 'aleph.json'),
    `${JSON.stringify(identity, null, 2)}\n`, 'utf8');
  console.log('배포 저장소·커밋·주소를 public/aleph.json에 기록했습니다.');
}
