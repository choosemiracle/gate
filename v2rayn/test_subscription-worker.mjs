import test from "node:test";
import assert from "node:assert/strict";
import worker from "./subscription-worker.mjs";

const base = "vless://11111111-1111-4111-8111-111111111111@alpha-beta-gamma.innerlightmessage.dpdns.org:443?encryption=none&security=tls&sni=alpha-beta-gamma.innerlightmessage.dpdns.org&type=ws&host=alpha-beta-gamma.innerlightmessage.dpdns.org&path=%2Fsecret%3Fed%3D2048#Original";
const env = { VLESS_LINKS: base, SUB_TOKEN: "0123456789abcdef0123456789abcdef" };

test("without token, no subscription is returned", async () => {
  const res = await worker.fetch(new Request("https://sub.example/sub"), env);
  assert.equal(res.status, 401);
});

test("valid token returns base64 standard VLESS links preserving TLS and WS", async () => {
  const oldFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({
    ips: [
      { ip: "104.17.99.242", verified: true, latency_ms: 100 },
      { ip: "192.168.1.1", verified: true, latency_ms: 10 },
      { ip: "104.17.212.202", verified: false, latency_ms: 90 },
    ]
  }));
  try {
    const res = await worker.fetch(new Request("https://sub.example/sub?token=" + env.SUB_TOKEN), env);
    assert.equal(res.status, 200);
    const decoded = Buffer.from(await res.text(), "base64").toString("utf8").trim();
    const uri = new URL(decoded);
    assert.equal(uri.protocol, "vless:");
    assert.equal(uri.hostname, "104.17.99.242");
    assert.equal(uri.username, "11111111-1111-4111-8111-111111111111");
    assert.equal(uri.searchParams.get("sni"), "alpha-beta-gamma.innerlightmessage.dpdns.org");
    assert.equal(uri.searchParams.get("host"), "alpha-beta-gamma.innerlightmessage.dpdns.org");
    assert.equal(uri.searchParams.get("path"), "/secret?ed=2048");
    assert.equal(uri.port, "443");
    assert.equal(decoded.split("\n").length, 1);
  } finally {
    globalThis.fetch = oldFetch;
  }
});

test("not configured refuses to issue share links", async () => {
  const res = await worker.fetch(new Request("https://sub.example/sub?token=" + env.SUB_TOKEN), { SUB_TOKEN: env.SUB_TOKEN });
  assert.equal(res.status, 503);
});

test("wrong protocol or transport refuses conversion", async () => {
  const bad = { ...env, VLESS_LINKS: base.replace("type=ws", "type=tcp") };
  const res = await worker.fetch(new Request("https://sub.example/sub?token=" + env.SUB_TOKEN), bad);
  assert.equal(res.status, 503);
});

test("never turns unverified IPs into VLESS nodes", async () => {
  const oldFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ ips: [{ ip: "104.17.99.242", verified: false }] }));
  try {
    const res = await worker.fetch(new Request("https://sub.example/sub?token=" + env.SUB_TOKEN), env);
    assert.equal(res.status, 503);
  } finally {
    globalThis.fetch = oldFetch;
  }
});
