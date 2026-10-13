import { createClient } from '@supabase/supabase-js';

// A fresh admin read avoids trusting client roles, editable user_metadata,
// or stale permission claims in an otherwise valid access token.
export async function verifyNoticeWritePermission({ login, projectUrl, secret }) {
  if (login.kind !== 'student') return 'denied';
  try {
    const client = createClient(projectUrl, secret, {
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
      global: { fetch: (input, options) => fetch(input, { ...options,
        redirect: 'error', signal: AbortSignal.timeout(10000), cache: 'no-store' }) },
    });
    const { data, error } = await client.auth.admin.getUserById(login.userId);
    if (error) return 'unavailable';
    if (!data?.user || data.user.id !== login.userId) return 'denied';
    const permissions = data.user.app_metadata?.aleph_permissions;
    return Array.isArray(permissions) && permissions.every(value => typeof value === 'string')
      && permissions.includes('instructor_notices.write') ? 'allowed' : 'denied';
  } catch {
    // Upstream user data and exceptions must never be logged or returned.
    return 'unavailable';
  }
}
