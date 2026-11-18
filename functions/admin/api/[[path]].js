
// Cloudflare Pages Function for /admin/api/*
// Verify Cloudflare Access JWT from assertion header or signed session cookie.
const reply = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  }
});

function base64urlBytes(value) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}
function decodeJSON(value) {
  return JSON.parse(new TextDecoder().decode(base64urlBytes(value)));
}
function cookieValue(request, name) {
  const cookies = request.headers.get('Cookie') || '';
  for (const item of cookies.split(';')) {
    const pos = item.indexOf('=');
    if (pos < 0) continue;
    if (item.slice(0, pos).trim() === name) return item.slice(pos + 1).trim();
  }
  return null;
}

async function authenticate(request, env) {
  const team = String(env.CF_ACCESS_TEAM_DOMAIN || '').replace(/^https?:\/\//, '').replace(/\/$/, '');
  const audience = String(env.CF_ACCESS_AUD || '').trim();
  if (!team || !audience) throw new Error('Missing Access verification settings');

  // The assertion header is added by Access when requests pass through the policy.
  // The signed cookie is also issued by Access after browser login.
  const token = request.headers.get('Cf-Access-Jwt-Assertion') ||
    cookieValue(request, 'CF_Authorization');
  if (!token) {
  console.error('CRM AUTH: No Access JWT received');
  return false;
}
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  let header, payload;
  try {
    header = decodeJSON(parts[0]);
    payload = decodeJSON(parts[1]);
  } catch {
    return false;
  }
  if (header.alg !== 'RS256' || typeof header.kid !== 'string') return false;
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isFinite(payload.exp) || payload.exp <= now ||
      !Number.isFinite(payload.iat) || payload.iat > now + 60 ||
      (Number.isFinite(payload.nbf) && payload.nbf > now + 60)) return false;
  if (payload.iss !== `https://${team}`) {
  console.error('CRM AUTH: Issuer mismatch');
  return false;
}

if (!(Array.isArray(payload.aud) ? payload.aud : [payload.aud]).includes(audience)) {
  console.error('CRM AUTH: Audience mismatch');
  return false;
} [payload.aud]).includes(audience)) return false;

  const response = await fetch(`https://${team}/cdn-cgi/access/certs`);
  if (!response.ok) throw new Error('Unable to retrieve Access signing keys');
  const { keys = [] } = await response.json();
  const jwk = keys.find(k => k.kid === header.kid && k.kty === 'RSA');
  if (!jwk) return false;
  const key = await crypto.subtle.importKey('jwk', jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  return crypto.subtle.verify('RSASSA-PKCS1-v1_5', key,
    base64urlBytes(parts[2]), new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
}

const allowed = ['New', 'Contacted', 'Qualified', 'Proposal Sent', 'Won', 'Lost'];

export async function onRequest({ request, env, params }) {
  let valid;
  try {
    valid = await authenticate(request, env);
  } catch (e) {
    console.error('Access verification failed', e);
    return reply({ error: 'Authentication configuration unavailable' }, 503);
  }
  if (!valid) return reply({ error: 'Unauthorized' }, 401);
  if (!env.DB) return reply({ error: 'Database binding DB is missing' }, 503);

  const url = new URL(request.url);
  const method = request.method;
  const route = (Array.isArray(params.path) ? params.path.join('/') : params.path || '').replace(/\/$/, '');
  try {
    if (route === 'leads' && method === 'GET') {
      const status = url.searchParams.get('status') || '';
      if (status && !allowed.includes(status)) return reply({ error: 'Invalid status' }, 400);
      const q = (url.searchParams.get('q') || '').trim().slice(0, 100);
      const page = Math.max(1, Math.min(10000, Number.parseInt(url.searchParams.get('page') || '1', 10) || 1));
      const size = 25;
      const offset = (page - 1) * size;
      let where = ' WHERE 1=1';
      const bindings = [];
      if (status) {
        where += ' AND status = ?';
        bindings.push(status);
      }
      if (q) {
        where += " AND (business_name LIKE ? ESCAPE '\\' OR contact_name LIKE ? ESCAPE '\\' OR phone LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\')";
        const value = `%${q.replace(/[\\%_]/g, '\\$&')}%`;
        bindings.push(value, value, value, value);
      }
      const count = await env.DB.prepare(`SELECT COUNT(*) AS total FROM leads${where}`).bind(...bindings).first();
      const rows = await env.DB.prepare(`SELECT id,business_name,contact_name,phone,email,service,message,status,created_at FROM leads${where} ORDER BY id DESC LIMIT ? OFFSET ?`).bind(...bindings, size, offset).all();
      const stats = await env.DB.prepare('SELECT status, COUNT(*) AS count FROM leads GROUP BY status').all();
      return reply({ leads: rows.results || [], total: count?.total || 0, page, pageSize: size, stats: stats.results || [] });
    }

    const match = /^leads\/(\d+)$/.exec(route);
    if (match && method === 'PATCH') {
      const origin = request.headers.get('Origin');
      if (origin && origin !== url.origin) return reply({ error: 'Invalid origin' }, 403);
      if (!(request.headers.get('content-type') || '').includes('application/json')) return reply({ error: 'Expected JSON' }, 415);
      if (Number(request.headers.get('content-length') || 0) > 2048) return reply({ error: 'Request too large' }, 413);
      let body;
      try { body = await request.json(); } catch { return reply({ error: 'Invalid JSON' }, 400); }
      if (!allowed.includes(body?.status)) return reply({ error: 'Invalid status' }, 400);
      const result = await env.DB.prepare('UPDATE leads SET status=? WHERE id=?').bind(body.status, Number(match[1])).run();
      if (!result.meta?.changes) return reply({ error: 'Lead not found' }, 404);
      return reply({ ok: true });
    }
    return reply({ error: 'Not found' }, 404);
  } catch (e) {
    console.error('CRM query error', e);
    return reply({ error: 'Unable to process request' }, 500);
  }
}
