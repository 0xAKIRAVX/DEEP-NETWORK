#!/usr/bin/env python3
"""DEEP NETWORK — subscription end-to-end validator.

Fetches a /sub/ URL exactly the way v2rayNG does (same User-Agent, base64
acceptance) and validates EVERY row of the response:

  * the payload decodes (plain or base64)
  * every line is a parsable vless:// / vmess:// / trojan:// URI
  * vmess rows carry a decodable JSON body with the required fields
  * every row carries a name (the ⟦ … ⟧ display label)
  * per-group tallies so you can see the transport mix at a glance

Exit codes: 0 = all rows valid, 1 = fetch failed, 2 = validation failed.

Usage:
    python3 tools/sub_e2e.py https://panel.example.com/sub/<id> [base64]
"""
from __future__ import annotations

import base64
import json
import re
import sys
import urllib.request

UA = "v2rayNG/1.9.16"
FRAGMENT = re.compile(r"#(.+)$")
NEEDED_VMESS_FIELDS = ("add", "port", "id", "net")


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read()
    text = raw.decode("utf-8", "replace").strip()
    if text and not text.startswith(("vless://", "vmess://", "trojan://")):
        # base64-wrapped payload (the v2rayNG default)
        padded = text + "=" * (-len(text) % 4)
        try:
            text = base64.urlsafe_b64decode(padded).decode("utf-8", "replace").strip()
        except Exception as exc:  # noqa: BLE001
            sys.exit(f"payload is neither plain links nor base64: {exc}")
    return text


def parse_vmess(uri: str) -> dict:
    body = uri[len("vmess://"):]
    padded = body + "=" * (-len(body) % 4)
    return json.loads(base64.urlsafe_b64decode(padded).decode("utf-8", "replace"))


def classify(uri: str) -> tuple[str, str, str]:
    """Return (proto, transport, host) for a link line."""
    scheme, _, rest = uri.partition("://")
    if scheme == "vmess":
        cfg = parse_vmess(uri)
        host = str(cfg.get("add", ""))
        return "vmess", str(cfg.get("net", "")), host
    # vless / trojan: query-string carries type= and the host sits after @
    at = rest.find("@")
    host = rest[at + 1:].split(":")[0] if at >= 0 else ""
    host = host.split("/")[0]
    m = re.search(r"[?&]type=([a-z]+)", uri)
    transport = m.group(1) if m else "tcp"
    return scheme, transport, host


def main() -> int:
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    url = sys.argv[1]

    try:
        text = fetch(url)
    except Exception as exc:  # noqa: BLE001
        print(f"FETCH FAILED: {exc}")
        return 1

    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        print("EMPTY SUBSCRIPTION")
        return 2

    groups: dict[tuple[str, str], int] = {}
    problems = 0
    for idx, uri in enumerate(lines, 1):
        where = f"row {idx:2d}"
        if not uri.startswith(("vless://", "vmess://", "trojan://")):
            print(f"{where}: UNKNOWN SCHEME — {uri[:48]}")
            problems += 1
            continue
        try:
            proto, transport, host = classify(uri)
        except Exception as exc:  # noqa: BLE001
            print(f"{where}: PARSE FAILED ({exc}) — {uri[:48]}")
            problems += 1
            continue
        name = ""
        if proto == "vmess":
            # vmess keeps its display name in the base64 JSON 'ps' field
            try:
                name = str(parse_vmess(uri).get("ps", ""))
            except Exception:  # noqa: BLE001
                pass
        if not name:
            frag = FRAGMENT.search(uri)
            if frag:
                try:
                    name = urllib.request.unquote(frag.group(1))
                except Exception:  # noqa: BLE001
                    name = frag.group(1)
        if not name:
            print(f"{where}: MISSING NAME — {uri[:48]}")
            problems += 1
        if proto == "vmess":
            cfg = parse_vmess(uri)
            missing = [f for f in NEEDED_VMESS_FIELDS if not cfg.get(f)]
            if missing:
                print(f"{where}: vmess missing fields {missing}")
                problems += 1
        if not host:
            print(f"{where}: NO HOST — {uri[:48]}")
            problems += 1
        groups[(proto, transport)] = groups.get((proto, transport), 0) + 1
        label = name if len(name) <= 52 else name[:49] + "..."
        print(f"{where}: OK {proto}/{transport:<10} {label}")

    print(f"\nTOTAL {len(lines)} rows, {problems} problems")
    for (proto, transport), count in sorted(groups.items(), key=lambda kv: -kv[1]):
        print(f"  {proto}/{transport:<11} x{count}")
    return 2 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
