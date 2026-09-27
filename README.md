# VLESS over WebSocket - Node.js server (for Railway)

Tested locally end-to-end: TCP relay through the VLESS tunnel, expired-user rejection,
and unknown-UUID rejection all verified before delivery.

## Deploy on Railway

1. Create a new Railway project → "Deploy from GitHub repo" (push these files to a repo)
   or "Empty project" and use the Railway CLI (`railway up`) from this folder.
2. Railway auto-detects Node.js from `package.json` and runs `npm start`.
3. Set environment variables (Railway dashboard → Variables):
   - `ADMIN_PASSWORD` — **required**. Password for the `/admin` panel.
   - `DATA_FILE` — optional. Where config is saved. **Without a Volume, this resets on
     every redeploy.** To persist data: Railway dashboard → your service → Settings →
     Volumes → add a volume mounted at e.g. `/data`, then set `DATA_FILE=/data/data.json`.
   - `ADDRS` — optional. Comma/newline-separated `host[:port]` list to use in generated
     links if you put a custom domain in front of this app. Leave unset to just use
     whatever domain/host the request came in on.
   - `PORT` — set automatically by Railway; don't set it yourself.
4. Railway gives you a public domain with automatic HTTPS/WSS out of the box - no TLS
   setup needed on your side.

## After deploying

1. Open `https://<your-railway-domain>/admin` and log in with `ADMIN_PASSWORD`.
2. The "کاربران" (Users) tab has a default user with a VLESS link ready to use.
3. Copy the subscription link from "نمای کلی" (Overview) into your client and enable
   auto-update on a schedule (this app doesn't push updates to clients).

## What's different from the Cloudflare Workers version

- No ProxyIP relay, no "clean IP" fetching, no country filter - not needed, since this
  process can open a normal outbound connection to anywhere, including Cloudflare's own
  IPs (Workers specifically cannot; that's the whole reason those features existed there).
- No IP scanner - same reason it doesn't apply here; there's no analog for this
  deployment.
- Per-user expiry and data quota are exact here (one process, real counters), not the
  best-effort approximation the distributed Workers version needed.
- Storage is a single JSON file (`data.json` by default) instead of Cloudflare KV.

## Trade-off vs. the Workers version

Cloudflare Workers gives you IP-fronting: your traffic rides in on the same IP ranges as
countless unrelated Cloudflare-hosted sites, which is why it's harder to block. A Railway
app has its own dedicated IP with nothing else hiding behind it, so it's an easier target
to block outright. Consider this a secondary/backup deployment rather than a replacement,
unless your network's filtering isn't IP-range-based.
