#!/usr/bin/env python3
"""Cloudflare V2: public TLS discovery + private end-to-end VLESS verification.

Never prints VLESS credentials. Only an IP with a successful Xray SOCKS request
receives vless_verified=true. A TLS pass alone is not sufficient.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import hashlib
import ipaddress
import json
import os
import pathlib
import random
import socket
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

OFFICIAL_RANGES = "https://www.cloudflare.com/ips-v4/"
TLS_TARGET = "alpha-beta-gamma.innerlightmessage.dpdns.org"
PROBE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
SEEDS = ("104.17.99.242", "104.17.212.202")
# Community labels identify provenance, not guaranteed ingress or exit country.
REGION_SOURCE = "https://raw.githubusercontent.com/LancelotRar/best-cf-ips/main/best-cf-ip-scanned-top400.txt"


def get_candidates(limit=200, rotation=0, ranges_text=None):
    if ranges_text is None:
        req = urllib.request.Request(OFFICIAL_RANGES, headers={"User-Agent": "choosemiracle-v2-checker/2"})
        with urllib.request.urlopen(req, timeout=12) as response:
            ranges_text = response.read(16384).decode("ascii")
    ranges = []
    for raw in ranges_text.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        net = ipaddress.ip_network(raw, strict=True)
        if net.version == 4 and net.is_global:
            ranges.append(net)
    if len(ranges) < 8:
        raise ValueError("Cloudflare source list unexpectedly small")
    # Allocate across all official ranges, rather than just sampling 104.16/13.
    rng = random.Random(int(rotation))
    seen = set()
    chosen = []
    def add(ip):
        address = ipaddress.ip_address(ip)
        if address.version == 4 and address.is_global and any(address in n for n in ranges) and ip not in seen:
            seen.add(ip); chosen.append(ip)
    for seed in SEEDS:
        add(seed)
    while len(chosen) < limit:
        for net in rng.sample(ranges, len(ranges)):
            if len(chosen) >= limit:
                break
            if net.num_addresses <= 2:
                continue
            offset = rng.randrange(1, net.num_addresses - 1)
            add(str(net.network_address + offset))
    return chosen


def get_region_hints(ranges_text=None, source_text=None, max_per_region=60):
    """Gather US/TW source-labelled IPs only if within official CF CIDR ranges."""
    if ranges_text is None:
        req = urllib.request.Request(OFFICIAL_RANGES, headers={"User-Agent": "choosemiracle/2"})
        with urllib.request.urlopen(req, timeout=12) as response:
            ranges_text = response.read(16384).decode("ascii")
    nets = [ipaddress.ip_network(x.strip()) for x in ranges_text.splitlines() if x.strip()]
    if source_text is None:
        req = urllib.request.Request(REGION_SOURCE, headers={"User-Agent": "choosemiracle/2"})
        with urllib.request.urlopen(req, timeout=12) as response:
            source_text = response.read(65000).decode("utf-8")
    hints = {"TW": [], "US": []}
    seen = set()
    for raw in source_text.splitlines():
        try:
            endpoint, suffix = raw.strip().split("#", 1)
            tag = suffix.strip().split()[0].upper()
            addr, port = endpoint.split(":", 1)
            ip = ipaddress.ip_address(addr)
            if tag not in hints or int(port) != 443 or not ip.is_global:
                continue
            if not any(ip in net for net in nets):
                continue
            value = str(ip)
            if value in seen or len(hints[tag]) >= max_per_region:
                continue
            hints[tag].append(value)
            seen.add(value)
        except (ValueError, IndexError):
            continue
    return hints

def prefer_region_mix(verified, limit=20, tw_slots=6, us_slots=8):
    """Reserve source-hint slots; backfill with any fast verified endpoints."""
    ranked = sorted(verified, key=lambda x: (x["latency_ms"], x["https_ms"], x["ip"]))
    chosen, seen = [], set()
    for region, slots in (("TW", tw_slots), ("US", us_slots)):
        for item in ranked:
            if slots == 0:
                break
            if item.get("region_source_hint") != region or item["ip"] in seen:
                continue
            chosen.append(item)
            seen.add(item["ip"])
            slots -= 1
    for item in ranked:
        if len(chosen) >= limit:
            break
        if item["ip"] not in seen:
            chosen.append(item)
            seen.add(item["ip"])
    return chosen[:limit]

def tls_check(ip, host=TLS_TARGET, timeout=5):
    cmd = ["curl", "-sS", "--noproxy", "*", "--connect-timeout", str(min(3, timeout)),
           "--max-time", str(timeout), "--resolve", f"{host}:443:{ip}",
           "--output", "/dev/null", "--write-out", "%{http_code} %{time_total}", f"https://{host}/"]
    try:
        run = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+2, check=True)
        status, elapsed = run.stdout.strip().split()
        if 200 <= int(status) < 500 and int(status) not in (407, 429):
            return {"ip": ip, "https_ms": max(1, int(float(elapsed)*1000)),
                    "https_status": int(status)}
    except (OSError, ValueError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        pass
    return None

def parse_template(raw):
    if not raw or "\n" in raw or "\r" in raw:
        raise ValueError("missing or invalid secret")
    link = urllib.parse.urlsplit(raw.strip())
    if link.scheme != "vless" or not link.username or not link.hostname:
        raise ValueError("invalid VLESS URL")
    q = urllib.parse.parse_qs(link.query)
    def get(key, default=""):
        return q.get(key, [default])[0]
    if get("security") != "tls" or get("type") != "ws" or not get("sni"):
        raise ValueError("requires TLS WebSocket VLESS")
    try:
        import uuid
        uuid.UUID(urllib.parse.unquote(link.username))
    except ValueError as err:
        raise ValueError("invalid UUID") from err
    return {"id": urllib.parse.unquote(link.username), "port": link.port or 443,
            "sni": get("sni"), "host": get("host", get("sni")),
            "path": get("path", "/"), "fingerprint": get("fp", "chrome")}

def make_xray_config(template, ip, port):
    return {
        "log": {"loglevel": "none"},
        "inbounds": [{"tag": "probe", "listen": "127.0.0.1", "port": port, "protocol": "socks",
                      "settings": {"auth": "noauth", "udp": False}}],
        "outbounds": [
            {"tag": "proxy", "protocol": "vless",
             "settings": {"vnext": [{"address": ip, "port": template["port"],
                                      "users": [{"id": template["id"], "encryption": "none"}]}]},
             "streamSettings": {"network": "ws", "security": "tls",
                 "tlsSettings": {"serverName": template["sni"], "fingerprint": template["fingerprint"]},
                 "wsSettings": {"path": template["path"],
                                "headers": {"Host": template["host"]}}}},
            {"tag": "direct", "protocol": "freedom"}
        ],
        "routing": {"domainStrategy": "AsIs", "rules": []}
    }

def probe_vless(candidate, template, xray="xray", timeout=9):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    with tempfile.TemporaryDirectory(prefix="v2rayn-v2-") as folder:
        config = pathlib.Path(folder) / "config.json"
        config.write_text(json.dumps(make_xray_config(template, candidate["ip"], port)))
        os.chmod(config, 0o600)
        process = None
        try:
            process = subprocess.Popen([xray, "run", "-config", str(config)],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.45)
            if process.poll() is not None:
                return None
            cmd = ["curl", "-sS", "--noproxy", "", "--max-time", str(timeout),
                   "--proxy", f"socks5h://127.0.0.1:{port}", "--output", "/dev/null",
                   "--write-out", "%{http_code} %{time_total}", PROBE_URL]
            result = subprocess.run(cmd, text=True, capture_output=True,
                                    timeout=timeout+2)
            if result.returncode != 0:
                return None
            code, seconds = result.stdout.strip().split()
            if not 200 <= int(code) < 400:
                return None
            ms = max(1, int(float(seconds)*1000))
            return {"ip": candidate["ip"], "verified": True, "vless_verified": True,
                    "latency_ms": ms, "https_ms": candidate["https_ms"],
                    "https_status": candidate["https_status"],
                    "verification": "Xray VLESS over TLS WebSocket, SOCKS5 HTTP request"}
        except (OSError, ValueError, subprocess.TimeoutExpired):
            return None
        finally:
            if process is not None:
                process.terminate()
                try: process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=2)

def scan(args):
    template = parse_template(os.environ.get("VLESS_PROBE_URI", ""))
    rotation = args.rotation if args.rotation is not None else int(time.time()//1800)
    candidates = get_candidates(args.candidates, rotation)
    hints = {"TW": [], "US": []}
    try:
        hints = get_region_hints(max_per_region=args.region_candidates)
    except (OSError, ValueError, UnicodeError):
        print("Region source unavailable; scanning official random candidates.")
    for ip in hints["TW"] + hints["US"]:
        if ip not in candidates:
            candidates.append(ip)
    region_of = {ip: label for label, ips in hints.items() for ip in ips}

    tls = []
    with cf.ThreadPoolExecutor(max_workers=args.https_workers) as executor:
        for item in executor.map(lambda ip: tls_check(ip, args.host, args.https_timeout), candidates):
            if item: tls.append(item)
    tls.sort(key=lambda x: (x["https_ms"], x["ip"]))
    short = tls[:args.shortlist]
    verified = []
    with cf.ThreadPoolExecutor(max_workers=args.vless_workers) as executor:
        for item in executor.map(lambda c: probe_vless(c, template, args.xray, args.vless_timeout), short):
            if item: verified.append(item)
    verified.sort(key=lambda x: (x["latency_ms"], x["https_ms"], x["ip"]))
    for entry in verified:
        if entry["ip"] in region_of:
            entry["region_source_hint"] = region_of[entry["ip"]]
    published = prefer_region_mix(verified)

    report = {
        "version": 2, "updated_at": datetime.now(timezone.utc).isoformat(),
        "target": args.host, "candidate_count": len(candidates),
        "tls_qualified": len(tls), "vless_probed": len(short),
        "vless_verified_count": len(verified),
        "regional_candidates": {label: len(ips) for label, ips in hints.items()},
        "published_region_hints": {label: sum(x.get("region_source_hint") == label for x in published) for label in ("TW", "US")},
        "region_note": "Source labels only; not verified ingress or egress geography.",

        "verification": "end-to-end VLESS TLS WebSocket through Xray",
        "ips": published
    }
    output = pathlib.Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    temp = output.with_suffix(output.suffix+".tmp")
    temp.write_text(json.dumps(report, indent=2)+"\n")
    os.replace(temp, output)
    print("Cloudflare V2 scan: candidates=%d HTTPS=%d VLESS_tested=%d VLESS_passed=%d published=%d" %
          (len(candidates),len(tls),len(short),len(verified),len(report["ips"])))

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--host", default=TLS_TARGET)
    ap.add_argument("--candidates", type=int, default=200)
    ap.add_argument("--shortlist", type=int, default=80)
    ap.add_argument("--region-candidates", type=int, default=60)
    ap.add_argument("--https-workers", type=int, default=24)
    ap.add_argument("--vless-workers", type=int, default=5)
    ap.add_argument("--https-timeout", type=int, default=6)
    ap.add_argument("--vless-timeout", type=int, default=9)
    ap.add_argument("--rotation", type=int)
    ap.add_argument("--xray", default="xray")
    ap.add_argument("--output", default="public/v2rayn-ips-v2.json")
    args=ap.parse_args()
    if not 20 <= args.candidates <= 300 or not 1 <= args.shortlist <= 80 or not 1 <= args.https_workers <= 40 or not 1 <= args.vless_workers <= 8 or not 0 <= args.region_candidates <= 60:
        ap.error("unsafe scan bounds")
    scan(args)

if __name__=="__main__":
    main()
