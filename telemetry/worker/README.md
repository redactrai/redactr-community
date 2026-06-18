# redactr telemetry collector

Anonymous heartbeat sink. Reads country/city from the Cloudflare edge and discards the IP.
It stores only: country, city, app version, OS, and a rotating session id (not identity).

## Security (public, unauthenticated endpoint)
No API key — this is a rough active-user estimate, not an audit — so the endpoint is hardened
against random/abusive traffic:
- **POST only** (else 405); **`application/json` only** (else 415).
- **Body size cap** of 512 bytes (else 413) — a heartbeat is ~80 bytes.
- **Per-IP rate limiting** via the `BEAT_LIMIT` binding (100 req / 60 s). The IP is used only
  as the transient limiter key and is **never stored**.
- **Defensive parsing:** malformed/oversized/non-object JSON → 400; `session` must match
  `^[a-f0-9]{8,32}$` or the request is rejected.
- No secrets/keys in the Worker; nothing user-identifying is persisted.

## Deploy
    npx wrangler deploy
Then map a route (e.g. `t.redactrai.com/beat`) to this Worker in the Cloudflare dashboard,
and point the binary's `telemetryEndpoint` (in `cmd/redactr-community/main.go`) at it.

## Active users in the last 15 min, by country/city
    SELECT blob1 AS country, blob2 AS city, count(DISTINCT index1) AS active
    FROM redactr_community_heartbeats
    WHERE timestamp > now() - INTERVAL '15' MINUTE
    GROUP BY country, city
    ORDER BY active DESC
(Run via the Cloudflare Analytics Engine SQL API.)
