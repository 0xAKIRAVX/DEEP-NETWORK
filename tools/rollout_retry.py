#!/usr/bin/env python3
"""DEEP NETWORK — rollout retry campaign for a Lucity service.

When the platform cluster runs out of capacity, rollouts fail within seconds
with reason=UNSCHEDULABLE. This helper keeps firing `rollback` (which starts
a FRESH rollout — the deploy mutation is repo-only) at a fixed interval and
exits the moment the service goes HEALTHY. It is the same campaign the ops
runbook uses to grab capacity the second a node frees up:

    LUCITY_TOKEN=lucity_... python3 tools/rollout_retry.py <service-id>

Optional flags:
    --deployment ID   rollback target (default: the latest FAILED deployment)
    --interval SEC    seconds between fires (default 90)
    --budget SEC      total seconds before giving up (default 550)
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


def http_json(method: str, url: str, body=None, headers=None, form=None):
    data = json.dumps(body).encode() if body is not None else None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("User-Agent", "deep-network-tools/1.0")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    if form is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def credentials():
    raw = os.environ.get("LUCITY_TOKEN", "").strip()
    if not raw.startswith("lucity_"):
        sys.exit("set LUCITY_TOKEN to a raw lucity_... token")
    decoded = base64.urlsafe_b64decode(raw[7:] + "=" * (-len(raw[7:]) % 4))
    parts = decoded.decode().split(":", 3)
    if len(parts) != 4:
        sys.exit("malformed token")
    return parts[0], parts[1], parts[2], parts[3]


def make_gql():
    client_id, secret, org_id, workspace = credentials()
    cfg = http_json("GET", BASE + "/auth/config")
    issuer = (cfg.get("issuer") or "https://auth.lucity.cloud").rstrip("/")
    payload = http_json("POST", issuer + "/token", form={
        "grant_type": "client_credentials",
        "resource": cfg.get("audience", ""),
        "organization_id": org_id,
        "scope": "admin member deployer",
    }, headers={
        "Authorization": "Basic " + base64.b64encode(
            f"{client_id}:{secret}".encode()).decode(),
    })
    bearer = payload.get("access_token")
    if not bearer:
        sys.exit("auth exchange returned no access_token")

    def gql(query: str, variables: dict | None = None):
        body = {"query": query}
        if variables:
            body["variables"] = variables
        out = http_json("POST", GRAPHQL, body, {
            "Authorization": "Bearer " + bearer,
            "X-Lucity-Workspace": workspace,
        })
        return out

    return gql


SERVICE_QUERY = """
query($id: ServiceID!) {
  service(id: $id) {
    status
    deployments {
      id status createdAt
      rollout { status reason }
    }
  }
}
"""


def latest_failed_deployment(gql, service_id: str) -> str | None:
    out = gql(SERVICE_QUERY, {"id": service_id})
    if out.get("errors"):
        sys.exit("service query failed: " + json.dumps(out["errors"])[:200])
    deps = out["data"]["service"]["deployments"] or []
    for dep in deps:
        if dep.get("status") == "FAILED":
            return dep["id"]
    return deps[0]["id"] if deps else None


def main() -> int:
    argv = list(sys.argv[1:])
    if not argv or argv[0].startswith("--"):
        sys.exit(__doc__)
    service_id = argv.pop(0)

    flags = {"--deployment": None, "--interval": "90", "--budget": "550"}
    i = 0
    while i < len(argv) - 1:
        if argv[i] in flags:
            flags[argv[i]] = argv[i + 1]
            i += 2
        else:
            i += 1
    interval = float(flags["--interval"])
    budget = float(flags["--budget"])

    gql = make_gql()
    target = flags["--deployment"] or latest_failed_deployment(gql, service_id)
    if not target:
        sys.exit("no deployment to roll back to")
    print(f"retry target: {target}")
    print(f"interval {interval:.0f}s, budget {budget:.0f}s")

    t0 = time.time()
    fires = 0
    while time.time() - t0 < budget:
        fires += 1
        out = gql('mutation($d: DeploymentID!) { rollback(deployment: $d) }',
                 {"d": target})
        err = "; ".join(e.get("message", "") for e in out.get("errors") or [])
        state = out.get("data", {}).get("rollback")
        print(f"fire #{fires}: rollback={state} {err[:60]}")
        # poll for up to `interval` seconds
        deadline = time.time() + interval
        while time.time() < deadline:
            time.sleep(min(15, max(2, deadline - time.time())))
            out = gql(SERVICE_QUERY, {"id": service_id})
            svc = (out.get("data") or {}).get("service") or {}
            status = svc.get("status")
            if status == "HEALTHY":
                print(f"*** RECOVERED after {fires} fires "
                      f"({time.time() - t0:.0f}s)")
                return 0
    print(f"still down after {fires} fires")
    return 3


if __name__ == "__main__":
    sys.exit(main())
