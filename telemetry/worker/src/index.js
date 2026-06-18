// Receives anonymous heartbeats. Derives coarse geo at the edge and DISCARDS the IP.
export default {
  async fetch(request, env) {
    if (request.method !== "POST") return new Response("ok", { status: 200 });
    let body = {};
    try { body = await request.json(); } catch { return new Response("bad", { status: 400 }); }

    const session = String(body.session || "").slice(0, 32);
    const version = String(body.version || "").slice(0, 32);
    const os = String(body.os || "").slice(0, 16);
    if (!session) return new Response("bad", { status: 400 });

    // Coarse geo from the Cloudflare edge — the IP is never read or stored.
    const country = (request.cf && request.cf.country) || "XX";
    const city = (request.cf && request.cf.city) || "";

    env.TELEMETRY.writeDataPoint({
      blobs: [country, city, version, os],
      indexes: [session], // sampling key; not identity
      doubles: [1],
    });
    return new Response("ok", { status: 200, headers: { "cache-control": "no-store" } });
  },
};
