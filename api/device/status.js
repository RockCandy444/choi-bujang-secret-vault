// No engine approval/session contract is provided. Never infer registration
// from a login, installation, client header/body, or a local constant.
export default function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('Vercel-CDN-Cache-Control', 'no-store');
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({ approved: false, error: 'METHOD_NOT_ALLOWED' });
  }
  return response.status(503).json({ approved: false, error: 'DEVICE_APPROVAL_NOT_CONFIGURED' });
}
