export async function api(path, options = {}) {
  const headers = options.body instanceof FormData ? { ...options.headers } : { 'Content-Type': 'application/json', ...options.headers };
  const response = await fetch(`/api${path}`, { ...options, signal: options.signal || AbortSignal.timeout(10000), headers });
  if (!response.ok) {
    let detail;
    try { detail = (await response.json()).detail; } catch { /* HTTP errors may have no JSON body. */ }
    throw new Error(typeof detail === 'string' ? detail : `Request failed (${response.status}). Please try again.`);
  }
  return response.json();
}
