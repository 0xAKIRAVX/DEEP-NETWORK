#!/usr/bin/env python3
"""DEEP NETWORK — Lucity deployment status poller.

Polls the Lucity GraphQL API and prints a one-line status summary for every
service in every environment of the project, plus the active deployment's
rollout state. Designed for cron / watch loops:

    watch -n 30 python3 tools/lucity_status.py

Authentication (either works):
    * LUCITY_TOKEN env var  — a raw lucity_... API token
    * lucity_token file     --token /path/to/token (default ~/.lucity_token)

The token exchange mirrors the platform CLI: base64-decode the raw token into
ClientID:Secret:Org:Workspace, POST client_credentials to the issuer, then
call the GraphQL endpoint with the short-lived bearer token. No secrets are
ever written to disk by this script.
"""
from __future__ import annotations

import base64
import json
import os
import sys
import time
import urllib.parse
import urllib.request

BASE = "https://lucity.cloud"
GRAPHQL = BASE + "/graphql"
AUTH_CONFIG = BASE + "/auth/config"
USER_AGENT = "deep-network-tools/1.0"

STATUS_COLORS = {
    "HEALTHY": "\033[32m",    # green
    "DEPLOYING": "\033[33m",  # yellow
    "FAILED": "\033[31m",     # red
}
RESET = "\033[0m"


def http_json(method: str, url: str, body=None, headers=None):
    """Tiny JSON-over-HTTP helper (stdlib only)."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("User-Agent", USER_AGENT)
    req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def load_credentials(token_path: str | None):
    """Return (client_id, secret, workspace) from a raw lucity_ token."""
    raw = os.environ.get("LUCITY_TOKEN", "").strip()
    if not raw:
        path = token_path or os.path.expanduser("~/.lucity_token")
        if not os.path.exists(path):
            sys.exit("no token: set LUCITY_TOKEN or pass --token FILE")
        raw = open(path).read().strip()
    if not raw.startswith("lucity_"):
        sys.exit("token must start with 'lucity_'")
    decoded = base64.urlsafe_b64decode(raw[7:] + "=" * (-len(raw[7:]) % 4))
    parts = decoded.decode().split(":", 3)
    if len(parts) != 4:
        sys.exit("malformed token (expected 4 colon-separated fields)")
    client_id, secret, _org, workspace = parts
    return client_id, secret, _org, workspace


def exchange_access_token(client_id: str, secret: str, org_id: str) -> str:
    """client_credentials exchange (Basic auth) -> short-lived bearer."""
    cfg = http_json("GET", AUTH_CONFIG)
    issuer = (cfg.get("issuer") or "https://auth.lucity.cloud").rstrip("/")
    form = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "resource": cfg.get("audience", ""),
        "organization_id": org_id,
        "scope": "admin member deployer",
    }).encode()
    req = urllib.request.Request(issuer + "/token", data=form, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("Authorization", "Basic " + base64.b64encode(
        f"{client_id}:{secret}".encode()).decode())
    with urllib.request.urlopen(req, timeout=30) as resp:
        payload = json.loads(resp.read().decode())
    token = payload.get("access_token")
    if not token:
        sys.exit("auth exchange returned no access_token")
    return token


def gql(query: str, variables: dict | None, bearer: str, workspace: str):
    """One GraphQL round-trip; raises SystemExit on transport-level errors."""
    body = {"query": query}
    if variables:
        body["variables"] = variables
    out = http_json("POST", GRAPHQL, body, {
        "Authorization": "Bearer " + bearer,
        "X-Lucity-Workspace": workspace,
    })
    if out.get("errors"):
        msgs = "; ".join(e.get("message", "?") for e in out["errors"])
        sys.exit("GraphQL error: " + msgs[:300])
    return out["data"]


PROJECT_QUERY = """
query {
  projects {
    id
    environments {
      id
      resourceTier
      services {
        id
        name
        status
        endpoints { host protocol tls }
        activeDeployment {
          commit
          status
          rollout { status reason message restarts }
        }
      }
    }
  }
}
"""


def colorize(status: str) -> str:
    color = STATUS_COLORS.get(status, "")
    return f"{color}{status}{RESET}" if color else status


def main() -> int:
    token_path = None
    args = sys.argv[1:]
    if "--help" in args or "-h" in args:
        print(__doc__)
        return 0
    if "--token" in args:
        token_path = args[args.index("--token") + 1]

    client_id, secret, org_id, workspace = load_credentials(token_path)
    bearer = exchange_access_token(client_id, secret, org_id)
    data = gql(PROJECT_QUERY, None, bearer, workspace)

    projects = data.get("projects") or []
    if not projects:
        print("no projects in this workspace")
        return 1

    exit_code = 0
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{stamp}] workspace {workspace}")
    for project in projects:
        for env in project.get("environments") or []:
            tier = env.get("resourceTier", "?")
            print(f"  env {env['id']} (tier {tier})")
            for svc in env.get("services") or []:
                status = svc.get("status", "?")
                dep = svc.get("activeDeployment") or {}
                rollout = dep.get("rollout") or {}
                reason = rollout.get("reason") or ""
                commit = (dep.get("commit") or "")[:7]
                hosts = [e.get("host") for e in (svc.get("endpoints") or [])
                         if (e.get("protocol") == "HTTPS")]
                host = hosts[0] if hosts else "(no public domain)"
                line = f"    {svc['name']:<16} {colorize(status):<24}"
                if commit:
                    line += f" commit {commit}"
                if reason:
                    line += f"  rollout {rollout.get('status')}/{reason}"
                print(line)
                print(f"      {host}")
                if status != "HEALTHY":
                    exit_code = 2
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
