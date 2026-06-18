// Anonymous heartbeat sink for redactr-community.
//
// Public endpoint (no API key — this is a rough active-user estimate, not an audit),
// so it is hardened against abuse:
//   - POST only
//   - application/json only
//   - tiny body size cap
//   - per-IP rate limiting (IP used ONLY transiently as the limiter key; never stored)
//   - defensive JSON parsing + strict field validation
//
// It derives coarse geo (country/city) from the Cloudflare edge and DISCARDS the IP.
// Stored: country, city, version, OS, and a rotating session id (not identity).

const MAX_BODY = 512; // bytes — a heartbeat is ~80 bytes
const SESSION_RE = /^[a-f0-9]{8,32}$/;

function res(status, body) {
  return new Response(body, { status, headers: { "cache-control": "no-store" } });
}

export default {
  async fetch(request, env) {
    // 1. POST only
    if (request.method !== "POST") {
      return new Response("method not allowed", { status: 405, headers: { allow: "POST" } });
    }

    // 2. JSON content-type only
    const ct = request.headers.get("content-type") || "";
    if (!ct.includes("application/json")) return res(415, "unsupported media type");

    // 3. reject oversized bodies up front (when Content-Length is present)
    const cl = Number(request.headers.get("content-length") || "0");
    if (Number.isNaN(cl) || cl > MAX_BODY) return res(413, "payload too large");

    // 4. per-IP rate limit (transient; the IP is NOT written anywhere)
    if (env.BEAT_LIMIT) {
      const ip = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
      const { success } = await env.BEAT_LIMIT.limit({ key: ip });
      if (!success) return new Response("rate limited", { status: 429, headers: { "retry-after": "60" } });
    }

    // 5. read with a hard cap, then parse defensively
    let raw;
    try {
      raw = await request.text();
    } catch {
      return res(400, "bad request");
    }
    if (raw.length > MAX_BODY) return res(413, "payload too large");

    let body;
    try {
      body = JSON.parse(raw);
    } catch {
      return res(400, "bad json");
    }
    if (typeof body !== "object" || body === null || Array.isArray(body)) {
      return res(400, "bad json");
    }

    // 6. strict field validation
    const session = String(body.session || "").slice(0, 32);
    const version = String(body.version || "").slice(0, 32);
    const os = String(body.os || "").slice(0, 16);
    if (!SESSION_RE.test(session)) return res(400, "bad session");

    // 7. coarse geo from the edge — IP is never read into storage
    const country = (request.cf && request.cf.country) || "XX";
    const city = (request.cf && request.cf.city) || "";

    if (env.TELEMETRY) {
      env.TELEMETRY.writeDataPoint({
        blobs: [country, city, version, os],
        indexes: [session], // sampling key; not identity
        doubles: [1],
      });
    }
    return res(200, "ok");
  },
};
