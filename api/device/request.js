// An unavailable registration service cannot issue an approval or receipt.
// No key, token, request payload or pretend pending registration is stored.
export default function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('Vercel-CDN-Cache-Control', 'no-store');
  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST');
    return response.status(405).json({ approved: false, error: 'METHOD_NOT_ALLOWED' });
  }
  const headers = request.headers ?? {};
  const host = headers.host;
  const local = typeof host === 'string' && /^(localhost|127\.0\.0\.1)(:\d+)?$/u.test(host);
  let sameOrigin = false;
  try {
    const origin = new URL(headers.origin);
    sameOrigin = origin.host === host && origin.pathname === '/'
      && origin.protocol === (local ? 'http:' : 'https:')
      && !origin.username && !origin.password && !origin.search && !origin.hash;
  } catch { /* Missing or malformed Origin is denied. */ }
  if (!sameOrigin || headers['sec-fetch-site'] === 'cross-site') {
    return response.status(403).json({ approved: false, error: 'DEVICE_ORIGIN_DENIED' });
  }
  return response.status(503).json({ approved: false, error: 'DEVICE_APPROVAL_NOT_CONFIGURED' });
}
