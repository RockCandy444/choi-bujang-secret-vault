import config from '../aleph.config.json' with { type: 'json' };
import { operationsSummary } from '../src/operations.mjs';

// Public receipt of credential-free checks; this is NOT an engine telemetry API.
export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('Vercel-CDN-Cache-Control', 'no-store');
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  try {
    const summary = await operationsSummary({ config, commit: process.env.VERCEL_GIT_COMMIT_SHA });
    response.setHeader('X-Aleph-Check-Id', summary.requestId);
    return response.status(200).json(summary);
  } catch {
    return response.status(503).json({ error: 'OPERATIONS_UNAVAILABLE' });
  }
}
