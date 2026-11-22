// v2rayN subscription gateway. VLESS credentials live only in Worker Secrets.
const SOURCE_URL = "https://choosemiracle.github.io/gate/v2rayn-ips.json";
const V2_SOURCE_URL = "https://choosemiracle.github.io/gate/v2rayn-ips-v2.json";
const json = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" }
  });

function equalSecret(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || !b) return false;
  let delta = a.length ^ b.length;
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) delta |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return delta === 0;
}

function parseBaseLinks(secret) {
  const links = String(secret || "").split(/\r?\n/).map(x => x.trim()).filter(Boolean);
  if (!links.length) throw new Error("missing links");
  return links.map(link => {
    const uri = new URL(link);
    if (uri.protocol !== "vless:" || !uri.username || !uri.hostname || !uri.port)
      throw new Error("unsupported link");
    if (uri.searchParams.get("security") !== "tls" || uri.searchParams.get("type") !== "ws")
      throw new Error("only VLESS TLS + WebSocket is supported");
    if (!uri.searchParams.get("sni") || !uri.searchParams.get("host") || !uri.searchParams.get("path"))
      throw new Error("sni, host and path required");
    return uri;
  });
}

function encodeBase64(text) {
  const bytes = new TextEncoder().encode(text);
  let ascii = "";
  for (let i = 0; i < bytes.length; i += 8192)
    ascii += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return btoa(ascii);
}

function isIPv4(value) {
  if (typeof value !== "string") return false;
  const m = value.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m || !m.slice(1).every(x => Number(x) <= 255 && String(Number(x)) === x)) return false;
  const [a, b, c] = m.slice(1).map(Number);
  // Never generate subscription links with private, reserved or documentation IPv4.
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && (b === 168 || (b === 0 && c === 0) || (b === 0 && c === 2))) return false;
  if (a === 198 && ((b === 18 || b === 19) || (b === 51 && c === 100))) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  return true;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method !== "GET") return json({ error: "method not allowed" }, 405);
    if (url.pathname === "/health")
      return json({ service: "choosemiracle-v2rayn", ready: !!env.VLESS_LINKS && !!env.SUB_TOKEN });
    if (url.pathname !== "/sub") return json({ error: "not found" }, 404);
    const supplied = url.searchParams.get("token") || request.headers.get("authorization")?.replace(/^Bearer\s+/i, "") || "";
    if (!equalSecret(supplied, env.SUB_TOKEN))
      return json({ error: "unauthorized" }, 401);
    let baseLinks;
    try {
      baseLinks = parseBaseLinks(env.VLESS_LINKS);
    } catch {
      return json({ error: "VLESS_LINKS is missing or invalid; add a VLESS TLS WS share link using wrangler secret put" }, 503);
    }
    // Only v2rayn-ips-v2.json with an authenticated Xray request can claim
    // end-to-end VLESS verification. Legacy V1 entries remain TLS-only fallback.
    let entries = [];
    let validationLevel = "https-only";
    try {
      const response = await fetch(V2_SOURCE_URL, { cf: { cacheTtl: 300, cacheEverything: true } });
      if (response.ok) {
        const data = await response.json();
        if (data.version === 2 && Array.isArray(data.ips)) {
          entries = data.ips.filter(e => e && isIPv4(e.ip) &&
            e.verified === true && e.vless_verified === true &&
            Number.isFinite(e.latency_ms)).sort((a, b) => a.latency_ms - b.latency_ms)
            .slice(0, 20);
          if (entries.length) validationLevel = "xray-vless-end-to-end";
        }
      }
    } catch { /* V2 unavailable: continue with safe legacy fallback */ }
    if (!entries.length) {
      try {
        const response = await fetch(SOURCE_URL, { cf: { cacheTtl: 300, cacheEverything: true } });
        if (!response.ok) throw new Error("legacy IP source unavailable");
        const data = await response.json();
        entries = Array.isArray(data.ips) ?
          data.ips.filter(e => e && isIPv4(e.ip) && e.verified === true)
            .sort((a, b) => (a.latency_ms || Infinity) - (b.latency_ms || Infinity))
            .slice(0, 20) : [];
      } catch { /* no verified sources */ }
    }
    if (!entries.length) return json({ error: "no current verified Cloudflare IP candidates" }, 503);
    const links = [];
    for (const [index, entry] of entries.entries()) {
      for (const [linkIndex, base] of baseLinks.entries()) {
        const uri = new URL(base.href);
        uri.hostname = entry.ip; // Intentionally preserve TLS SNI, WS Host, WS path, UUID and port.
        const tag = entry.region_source_hint === "TW" || entry.region_source_hint === "US" ? `${entry.region_source_hint}-source` : "global";
        uri.hash = encodeURIComponent(`CF-${String(index + 1).padStart(2, "0")} ${tag} ${entry.latency_ms || "?"}ms ${linkIndex + 1}`);
        links.push(uri.href);
        if (links.length >= 20) break;
      }
      if (links.length >= 20) break;
    }
    return new Response(encodeBase64(links.join("\n") + "\n"), {
      status: 200,
      headers: {
        "content-type": "text/plain; charset=utf-8",
        "cache-control": "private, no-store",
        "x-content-type-options": "nosniff",
        "x-validation-level": validationLevel,
      }
    });
  }
};
