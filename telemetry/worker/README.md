# redactr telemetry collector

Anonymous heartbeat sink. Reads country/city from the Cloudflare edge and discards the IP.
It stores only: country, city, app version, OS, and a rotating session id (not identity).

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
