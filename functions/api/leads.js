const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }
});

export async function onRequestPost({ request, env }) {
  if (!env.DB) return json({ error: 'Database binding is missing.' }, 503);
  const origin = request.headers.get('Origin');
  if (origin && new URL(origin).hostname !== new URL(request.url).hostname) {
    return json({ error: 'Invalid origin.' }, 403);
  }
  if (!(request.headers.get('content-type') || '').includes('application/json')) {
    return json({ error: 'Expected JSON.' }, 415);
  }
  if (Number(request.headers.get('content-length') || 0) > 10000) return json({ error: 'Request too large.' }, 413);
  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON.' }, 400); }
  const str = (key, max) => typeof body?.[key] === 'string' ? body[key].trim().slice(0, max) : '';
  if (body?.website_url) return json({ ok: true }); // Honeypot
  if (body?.consent !== true) return json({ error: 'Consent is required.' }, 400);
  const business = str('business_name', 100), name = str('contact_name', 100);
  const phone = str('phone', 30), email = str('email', 150);
  const service = str('service', 500), message = str('message', 1500);
  if (!business || !name || !service || !/^\+?[0-9 ()-]{7,30}$/.test(phone)) {
    return json({ error: 'Please complete the required fields.' }, 400);
  }
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: 'Invalid email.' }, 400);
  try {
    await env.DB.prepare(`INSERT INTO leads (business_name, contact_name, phone, email, service, message, status)
      VALUES (?, ?, ?, ?, ?, ?, 'New')`).bind(business, name, phone, email, service, message).run();
    return json({ ok: true }, 201);
  } catch (e) {
    console.error('Lead insert failed', e);
    return json({ error: 'Unable to save your enquiry right now.' }, 500);
  }
}
