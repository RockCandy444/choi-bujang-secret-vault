import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';
import { RESOURCE_IDS, RESOURCE_ID_HEADER } from '../src/resource-ids.mjs';
import { denyApi } from '../src/api-denial.mjs';
import { verifyNoticeWritePermission } from '../src/verify-notice-permission.mjs';

let verifyLoginAuthorization;

export default async function handler(request, response) {
  const reject = (status, reason) => denyApi(response, RESOURCE_IDS.notices, status, reason);
  response.setHeader(RESOURCE_ID_HEADER, RESOURCE_IDS.notices);
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('Vercel-CDN-Cache-Control', 'no-store');
  response.setHeader('Vary', 'Authorization');
  try {
    const path = new URL(request.url || '/api/notices', 'https://route.invalid').pathname;
    if (path !== '/api/notices' && path !== '/api/notices/') {
      return reject(404, 'NOT_FOUND');
    }
  } catch {
    return reject(404, 'NOT_FOUND');
  }
  if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method)) {
    response.setHeader('Allow', 'GET');
    return reject(405, 'METHOD_NOT_ALLOWED');
  }
  const authorization = request.headers?.authorization;
  if (typeof authorization !== 'string' || !authorization) {
    return reject(401, 'LOGIN_REQUIRED');
  }
  let project;
  const secret = process.env.SUPABASE_SECRET_KEY;
  try {
    project = new URL(process.env.SUPABASE_URL);
    if (project.protocol !== 'https:' || project.username || project.password
        || project.search || project.hash || project.pathname !== '/'
        || project.origin !== new URL(config.identityProvider.issuer).origin
        || typeof secret !== 'string' || !secret || /\s/u.test(secret)) {
      throw new Error('Invalid server configuration');
    }
    verifyLoginAuthorization ??= createLoginVerifier({ config, supabaseSecretKey: secret });
  } catch {
    return reject(503, 'NOTICES_NOT_CONFIGURED');
  }
  let login;
  try {
    login = await verifyLoginAuthorization(authorization);
    if (!login) {
      return reject(401, 'LOGIN_REQUIRED');
    }
  } catch {
    return reject(401, 'LOGIN_REQUIRED');
  }
  if (request.method !== 'GET') {
    const permission = await verifyNoticeWritePermission({ login, projectUrl: project.origin, secret });
    if (permission === 'unavailable') return reject(503, 'NOTICE_PERMISSION_UNAVAILABLE');
    if (permission !== 'allowed') return reject(403, 'NOTICE_WRITE_NOT_ALLOWED');
    // Authorization does not create a notice storage/write implementation.
    response.setHeader('Allow', 'GET');
    return reject(405, 'METHOD_NOT_ALLOWED');
  }
  // No notice data exists yet. Do not read or repurpose the existing notes DB.
  return response.status(200).json([]);
}
