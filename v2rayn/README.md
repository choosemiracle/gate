# v2rayN VLESS subscription (independent of VPN Gate SSTP)

This is an **additional** feature. Existing `public/nodes.txt`, SSTP health checks, and the pre-existing `alpha-beta-gamma` service are unchanged.

## Architecture

- The existing GitHub Actions `check.yml` runs every 30 minutes.
- Following the SSTP run, `v2rayn/check_ips.py` tests the public candidate IPv4 addresses using HTTPS, SNI and valid TLS certificates for `alpha-beta-gamma.innerlightmessage.dpdns.org`.
- Public GitHub Pages file `https://choosemiracle.github.io/gate/v2rayn-ips.json` contains only IPs and test metrics, **no credentials**.
- A **separate Cloudflare Worker** (`v2rayn/subscription-worker.mjs`) stores original VLESS links as a secret named `VLESS_LINKS` and a private subscription access token named `SUB_TOKEN`.
- A GET request to `https://<worker>.workers.dev/sub?token=<SUB_TOKEN>` yields a Base64-encoded list of standard VLESS links for v2rayN. In each generated link only the server address changes to a tested IP; UUID, port, TLS SNI, WebSocket Host/Path and other query parameters remain intact.

**Important:** The HTTP/TLS IP test is NOT an end-to-end VLESS/WebSocket validation. v2rayN must run its own connection and real-world download tests. A returned candidate may not work as a VLESS transport. No SSTP server is converted to VLESS.

## Configure (on the trusted Mac, never in a GitHub public file)

Install and authenticate Wrangler on the Mac. Deploy as a **new** Worker, not the existing SSTP check Worker:

```sh
npx wrangler deploy v2rayn/subscription-worker.mjs --name choosemiracle-v2rayn-sub
```

Generate a 32-byte token and store it securely on the Mac; write it to the Worker with Wrangler Secret. Do not commit or share the token.

```sh
mkdir -p "$HOME/.config/choosemiracle"
chmod 700 "$HOME/.config/choosemiracle"
openssl rand -hex 32 > "$HOME/.config/choosemiracle/v2rayn-token"
chmod 600 "$HOME/.config/choosemiracle/v2rayn-token"
npx wrangler secret put SUB_TOKEN --name choosemiracle-v2rayn-sub < "$HOME/.config/choosemiracle/v2rayn-token"
```

Next, use an **existing, verified VLESS TLS + WebSocket share link** from v2rayN, and set it in the Worker without entering it in chat. The full link must include `sni`, `host`, and `path`. Do not use an SSTP link. For one link:

```sh
npx wrangler secret put VLESS_LINKS --name choosemiracle-v2rayn-sub
```

Paste a full VLESS URI into the command prompt. For multiple links, supply one link per line using standard input from a private local file.

## Subscribe from v2rayN (Windows)

1. In v2rayN, open **订阅分组 → 订阅分组设置 → 添加**.
2. Set name to **奇迹工坊 · Cloudflare VLESS**.
3. Enter the HTTPS Worker subscription URL with the locally stored `SUB_TOKEN` as query parameter.
4. Save. Choose **更新订阅** and inspect the returned profiles.
5. Test TCP/TLS delay, real connection and download speed, then activate a working profile.

The URL token is a credential: do not publish it in screenshots, issue logs, or a public repository. The response also contains VLESS UUID values (Base64 is not encryption).

## Diagnostics

- `/health` returns `ready: false` until both secrets are set.
- `/sub` without the token returns HTTP 401.
- `/sub?token=<valid>` returns HTTP 503 when `VLESS_LINKS` is not configured, when links are not VLESS TLS WS, or when no IPs passed HTTPS tests. This deliberately avoids silently publishing invalid profiles.
- The existing public `nodes.txt` is for VPN Gate SSTP only; it is not a valid v2rayN subscription.
- The JSON IP list is a public report and does not contain the v2rayN subscription credentials.
- Keep your original known-working v2rayN profile as a fallback.

## Local tests

```sh
python3 -m unittest discover -s v2rayn -p 'test_*.py' -v
node --test v2rayn/test_subscription-worker.mjs
```


## Cloudflare V2: verified subscription

This feature adds a second-stage VLESS proxy test to the existing SSTP/V1
30-minute GitHub Actions workflow without modifying SSTP nodes or the
alpha-beta-gamma service.

- Generate 200 candidate IPv4 addresses from the official Cloudflare
  https://www.cloudflare.com/ips-v4/ ranges, rotating every 30 minutes.
- Run parallel HTTPS/TLS preflight, then test the best 55 candidates through
  a full Xray VLESS + TLS + WebSocket outbound and SOCKS5 HTTP request.
- Publish only actual successful VLESS IPs to
  https://choosemiracle.github.io/gate/v2rayn-ips-v2.json,
  ordered by end-to-end latency, with a 20-IP maximum.
- Public reports hold IPs/latencies only, never UUIDs or share links.
- The subscription Worker prefers V2 end-to-end verified IPs; if V2 has not
  succeeded, it retains V1 HTTPS-only fallback. Response header
  x-validation-level distinguishes xray-vless-end-to-end from https-only.
  HTTPS-only entries are never represented as real VLESS-verified nodes.
- The subscription output is capped at 20 total VLESS links, regardless of
  the number of private templates.

One-time activation: save a known-working VLESS+TLS+WebSocket URI as GitHub
Actions encrypted secret VLESS_PROBE_URI in choosemiracle/gate. Do not commit
this secret or echo it to logs. Cloudflare Worker still holds the separate
VLESS_LINKS secret; the GitHub secret is used exclusively for authenticated
probe attempts. Without it, V2 scanning skips and V1 continues.

V2 latency is measured from a GitHub-hosted runner, not from your Mac. Test
the actual subscription on the client before switching active nodes.
