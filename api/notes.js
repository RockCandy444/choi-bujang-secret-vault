// Stage 2: deliberately public. Authentication is a later stage.
export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('Vercel-CDN-Cache-Control', 'no-store');
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  const secret = process.env.SUPABASE_SECRET_KEY;
  let endpoint;
  try {
    const project = new URL(process.env.SUPABASE_URL);
    if (project.protocol !== 'https:' || project.username || project.password
        || project.search || project.hash || project.pathname !== '/'
        || !secret || /\s/u.test(secret)) throw new Error('Invalid server configuration');
    endpoint = new URL('/rest/v1/notes', project);
    endpoint.searchParams.set('select', 'title,content');
    endpoint.searchParams.set('order', 'created_at.asc,id.asc');
    endpoint.searchParams.set('limit', '4');
  } catch {
    return response.status(503).json({ error: 'NOTES_NOT_CONFIGURED' });
  }

  try {
    const upstream = await fetch(endpoint, {
      headers: { apikey: secret, Accept: 'application/json' },
      redirect: 'error', signal: AbortSignal.timeout(10000), cache: 'no-store',
    });
    // Never forward upstream errors, headers, configuration, or extra fields.
    if (!upstream.ok) throw new Error('Upstream failure');
    const rows = await upstream.json();
    if (!Array.isArray(rows) || rows.length > 4 || rows.some(row => !row
        || typeof row.title !== 'string' || typeof row.content !== 'string'
        || row.title.includes(secret) || row.content.includes(secret))) {
      throw new Error('Invalid notes response');
    }
    return response.status(200).json({ notes: rows.map(({ title, content }) => ({ title, content })) });
  } catch {
    // Do not log the exception: it may contain an upstream URL or credential.
    return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
  }
}
