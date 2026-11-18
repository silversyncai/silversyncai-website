// Cloudflare Pages Function for /admin/api/*
 // Secure SilverSync AI CRM API

const reply = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    }
  });

function base64urlBytes(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(
    Math.ceil(normalized.length / 4) * 4,
    "="
  );

  return Uint8Array.from(
    atob(padded),
    c => c.charCodeAt(0)
  );
}

function decodeJSON(value) {
  return JSON.parse(
    new TextDecoder().decode(base64urlBytes(value))
  );
}

function cookieValue(request, name) {
  const cookies = request.headers.get("Cookie") || "";

  for (const item of cookies.split(";")) {
    const pos = item.indexOf("=");

    if (pos < 0) continue;

    if (item.slice(0, pos).trim() === name) {
      return item.slice(pos + 1).trim();
    }
  }

  return null;
}

async function authenticate(request, env) {
  const team = String(
    env.CF_ACCESS_TEAM_DOMAIN || ""
  )
    .replace(/^https?:\/\//, "")
    .replace(/\/$/, "");

  const audience = String(
    env.CF_ACCESS_AUD || ""
  ).trim();

  if (!team || !audience) {
    throw new Error(
      "Missing Access verification settings"
    );
  }

  const token =
    request.headers.get("Cf-Access-Jwt-Assertion") ||
    cookieValue(request, "CF_Authorization");

  if (!token) return "no_token";

  const parts = token.split(".");

  if (parts.length !== 3) return "malformed_token";

  let header;
  let payload;

  try {
    header = decodeJSON(parts[0]);
    payload = decodeJSON(parts[1]);
  } catch {
    return "malformed_token";
  }

  if (
    header.alg !== "RS256" ||
    typeof header.kid !== "string"
  ) {
    return "bad_algorithm";
  }

  const now = Math.floor(Date.now() / 1000);

  if (
    !Number.isFinite(payload.exp) ||
    payload.exp <= now ||
    !Number.isFinite(payload.iat) ||
    payload.iat > now + 60 ||
    (Number.isFinite(payload.nbf) &&
      payload.nbf > now + 60)
  ) {
    return "token_expired";
  }

  // Verify Cloudflare Access issuer
  if (payload.iss !== `https://${team}`) {
    return "team_domain_mismatch";
  }

  // Correctly handle single or multiple audiences
  const audiences = Array.isArray(payload.aud)
    ? payload.aud
    : [payload.aud];

  if (!audiences.includes(audience)) {
    return "aud_mismatch";
  }

  // Retrieve Cloudflare Access signing keys
  const response = await fetch(
    `https://${team}/cdn-cgi/access/certs`
  );

  if (!response.ok) {
    throw new Error(
      "Unable to retrieve Access signing keys"
    );
  }

  const { keys = [] } = await response.json();

  const jwk = keys.find(
    k => k.kid === header.kid && k.kty === "RSA"
  );

  if (!jwk) return "signing_key_not_found";

  const key = await crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256"
    },
    false,
    ["verify"]
  );

  const signatureOk = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    base64urlBytes(parts[2]),
    new TextEncoder().encode(
      `${parts[0]}.${parts[1]}`
    )
  );

  return signatureOk ? "ok" : "bad_signature";
}

const allowed = [
  "New",
  "Contacted",
  "Qualified",
  "Proposal Sent",
  "Won",
  "Lost"
];

export async function onRequest({
  request,
  env,
  params
}) {
  let valid;

  try {
    valid = await authenticate(request, env);
  } catch (e) {
    console.error(
      "Access verification failed",
      e
    );

    return reply(
      {
        error:
          "Authentication configuration unavailable"
      },
      503
    );
  }

  if (valid !== "ok") {
    // Temporary diagnostic: reason code only, no secrets
    return reply(
      { error: "Unauthorized", reason: valid },
      401
    );
  }

  if (!env.DB) {
    return reply(
      {
        error: "Database binding DB is missing"
      },
      503
    );
  }

  const url = new URL(request.url);
  const method = request.method;

  const route = (
    Array.isArray(params.path)
      ? params.path.join("/")
      : params.path || ""
  ).replace(/\/$/, "");

  try {
    // GET customer leads
    if (route === "leads" && method === "GET") {
      const status =
        url.searchParams.get("status") || "";

      if (status && !allowed.includes(status)) {
        return reply(
          { error: "Invalid status" },
          400
        );
      }

      const q = (
        url.searchParams.get("q") || ""
      ).trim().slice(0, 100);

      const page = Math.max(
        1,
        Math.min(
          10000,
          Number.parseInt(
            url.searchParams.get("page") || "1",
            10
          ) || 1
        )
      );

      const size = 25;
      const offset = (page - 1) * size;

      let where = " WHERE 1=1";
      const bindings = [];

      if (status) {
        where += " AND status = ?";
        bindings.push(status);
      }

      if (q) {
        where +=
          " AND (business_name LIKE ? ESCAPE '\\' " +
          "OR contact_name LIKE ? ESCAPE '\\' " +
          "OR phone LIKE ? ESCAPE '\\' " +
          "OR email LIKE ? ESCAPE '\\')";

        const value =
          `%${q.replace(/[\\%_]/g, "\\$&")}%`;

        bindings.push(
          value,
          value,
          value,
          value
        );
      }

      const count = await env.DB.prepare(
        `SELECT COUNT(*) AS total FROM leads${where}`
      )
        .bind(...bindings)
        .first();

      const rows = await env.DB.prepare(
        `SELECT id, business_name, contact_name,
         phone, email, service, message,
         status, created_at
         FROM leads${where}
         ORDER BY id DESC
         LIMIT ? OFFSET ?`
      )
        .bind(...bindings, size, offset)
        .all();

      const stats = await env.DB.prepare(
        `SELECT status, COUNT(*) AS count
         FROM leads
         GROUP BY status`
      ).all();

      return reply({
        leads: rows.results || [],
        total: count?.total || 0,
        page,
        pageSize: size,
        stats: stats.results || []
      });
    }

    // PATCH customer lead status
    const match = /^leads\/(\d+)$/.exec(route);

    if (match && method === "PATCH") {
      const origin =
        request.headers.get("Origin");

      if (origin && origin !== url.origin) {
        return reply(
          { error: "Invalid origin" },
          403
        );
      }

      const contentType =
        request.headers.get("content-type") || "";

      if (!contentType.includes("application/json")) {
        return reply(
          { error: "Expected JSON" },
          415
        );
      }

      if (
        Number(
          request.headers.get("content-length") || 0
        ) > 2048
      ) {
        return reply(
          { error: "Request too large" },
          413
        );
      }

      let body;

      try {
        const raw = await request.text();

        if (
          new TextEncoder().encode(raw).length > 2048
        ) {
          return reply(
            { error: "Request too large" },
            413
          );
        }

        body = JSON.parse(raw);
      } catch {
        return reply(
          { error: "Invalid JSON" },
          400
        );
      }

      if (!allowed.includes(body?.status)) {
        return reply(
          { error: "Invalid status" },
          400
        );
      }

      const result = await env.DB.prepare(
        "UPDATE leads SET status=? WHERE id=?"
      )
        .bind(
          body.status,
          Number(match[1])
        )
        .run();

      if (!result.meta?.changes) {
        return reply(
          { error: "Lead not found" },
          404
        );
      }

      return reply({ ok: true });
    }

    return reply(
      { error: "Not found" },
      404
    );
  } catch (e) {
    console.error(
      "CRM query error",
      e
    );

    return reply(
      { error: "Unable to process request" },
      500
    );
  }
}
