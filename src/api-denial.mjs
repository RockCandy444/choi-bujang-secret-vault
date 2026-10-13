// Call only with server-selected constants. Never pass requests or exceptions.
export function denyApi(response, resourceId, status, reason) {
  console.warn(JSON.stringify({ event: 'api_denied', resourceId, reason }));
  return response.status(status).json({ error: reason });
}
