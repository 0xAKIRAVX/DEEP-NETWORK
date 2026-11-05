# DEEP NETWORK — VPS edition (v3.26.0)

Single static Go binary: panel UI + API + subscriptions + Xray-core supervision
for a plain VPS (no domain, no CDN).

- **Transports** (all VLESS · Reality on the server IP):
  Vision `:8443` (fastest) · XHTTP `:2053` (DPI-robust) · gRPC `:2087` (h2)
  — ports auto-fallback when occupied.
- **First visit** → setup wizard: first/last name + photo → username/password → login.
- **Speed pack**: BBR + fq + 32MB kernel buffers (installer + boot self-heal),
  mux-off links, per-transport sockopts.
- **Doctor**: real end-to-end self-test through every transport with the same
  Xray core v2rayNG uses.
- Decoy site at `/`, panel at `/panel`, subs at `/sub/<token>` (+ `?fmt=xray`).

## Install
```bash
curl -LO https://github.com/0xAKIRAVX/DEEP-NETWORK/releases/download/v3.26.0/deep-network-v3.26.0-linux-amd64.sh
sudo bash deep-network-v3.26.0-linux-amd64.sh
```
(arm64 build also attached; run `sudo /opt/deep-network/out --banner` any time)

## Build
```bash
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o out .
go test ./...
```
