import { open } from 'node:fs/promises';

const fail = code => { throw new Error(code); };

export async function readInput(path, missingCode, maxBytes, forbiddenIdentity) {
  let handle;
  try {
    handle = await open(path, 'r');
    const stat = await handle.stat({ bigint: true });
    if (!stat.isFile() || stat.size > maxBytes) fail('POLICY_INPUT_INVALID');
    if (forbiddenIdentity) {
      if (stat.ino <= 0n || forbiddenIdentity.ino <= 0n) fail('POLICY_INPUT_UNREADABLE');
      if (stat.dev === forbiddenIdentity.dev && stat.ino === forbiddenIdentity.ino) {
        fail('TRIAL_POLICY_IS_OPERATIONAL');
      }
    }
    // Bound allocation even if an input grows after stat.
    const bytes = Buffer.alloc(maxBytes + 1);
    let total = 0;
    while (total < bytes.length) {
      const { bytesRead } = await handle.read(bytes, total, bytes.length - total, total);
      if (bytesRead === 0) break;
      total += bytesRead;
    }
    if (total > maxBytes) fail('POLICY_INPUT_INVALID');
    return bytes.subarray(0, total);
  } catch (error) {
    if (error.code === 'ENOENT') fail(missingCode);
    if (['POLICY_INPUT_INVALID', 'TRIAL_POLICY_IS_OPERATIONAL'].includes(error.message)) throw error;
    fail('POLICY_INPUT_UNREADABLE');
  } finally { await handle?.close(); }
}
