#!/usr/bin/env python3
"""Verify Cloudflare candidate IPs against a real HTTPS hostname (TLS/SNI + HTTP only).

This does NOT prove a VLESS WebSocket connection works; the client must test that.
Only writes public IP, HTTP status, and latency. No UUID or private link is used.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

def check(host: str, ip: str, timeout: int) -> dict | None:
    # Keep HTTPS hostname in URL and --resolve so SNI, certificate and Host are correct.
    command = [
        "curl", "--silent", "--show-error", "--noproxy", "*",
        "--connect-timeout", str(min(timeout, 5)), "--max-time", str(timeout),
        "--resolve", f"{host}:443:{ip}", "--output", "/dev/null",
        "--write-out", "%{http_code} %{time_appconnect} %{time_total}",
        f"https://{host}/",
    ]
    try:
        out = subprocess.run(command, text=True, capture_output=True, timeout=timeout + 3, check=True)
        status_s, tls_s, total_s = out.stdout.strip().split()
        status = int(status_s)
        if status < 200 or status >= 500 or status == 407 or status == 429 or float(tls_s) <= 0:
            return None
        return {
            "ip": ip,
            "latency_ms": round(float(total_s) * 1000),
            "tls_ms": round(float(tls_s) * 1000),
            "http_status": status,
            "verified": True,
            "verification": "TLS certificate and HTTPS reachability; NOT VLESS WebSocket",
        }
    except (subprocess.CalledProcessError, OSError, ValueError, subprocess.TimeoutExpired):
        return None

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--candidates", default="v2rayn/candidates.txt")
    parser.add_argument("--output", default="public/v2rayn-ips.json")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--max-ips", type=int, default=10)
    args = parser.parse_args()
    host = args.host.strip().lower()
    if not host or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789.-" for c in host):
        raise SystemExit("Invalid HTTPS host")
    candidates = []
    for line in Path(args.candidates).read_text(encoding="utf-8").splitlines():
        value = line.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            ip = ipaddress.ip_address(value)
            if ip.version != 4 or not ip.is_global:
                continue
        except ValueError:
            continue
        if value not in candidates:
            candidates.append(value)
    results = [entry for ip in candidates if (entry := check(host, ip, args.timeout))]
    results.sort(key=lambda entry: (entry["latency_ms"], entry["ip"]))
    payload = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "target": host,
        "verification": "TLS certificate + HTTPS only, not a working VLESS proof",
        "candidate_count": len(candidates),
        "ips": results[: max(args.max_ips, 0)],
    }
    dest = Path(args.output)
    dest.parent.mkdir(parents=True, exist_ok=True)
    temp = dest.with_suffix(dest.suffix + ".tmp")
    temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temp, dest)
    print(f"VLESS candidates: {len(candidates)}, HTTPS/TLS verified: {len(results)}, published: {len(payload['ips'])}")

if __name__ == "__main__":
    main()
