# syntax=docker/dockerfile:1
# ─────────── DEEP NETWORK — container image ───────────
# Build:  docker build -t ghcr.io/0xakiravx/deep-network:latest .
# Run:    docker run -p 8080:8080 -v deep-data:/data ghcr.io/0xakiravx/deep-network
#
# The panel is a single static Go binary (web UI embedded, xray supervised
# as a child process). This image ships:
#   /app/out          — the panel (API + UI + subscriptions + tunnel proxy)
#   /app/bin/xray     — Xray-core (official static linux-64 build)
#   /app/bin/deep-probe — fast TLS scanner helper (static, Go fallback built in)
# Initial credentials can be pinned with the ADMIN_PASSWORD / ADMIN_USER
# variables; without them a random password is generated on first boot
# and printed in the boot report (logs).

# ── stage 1: build the panel ──
FROM golang:1.23-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out .

# ── stage 2: fetch Xray-core (official static binary) ──
FROM debian:bookworm-slim AS xray
ADD https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip /tmp/xray.zip
RUN apt-get update && apt-get install -y --no-install-recommends unzip ca-certificates \
    && unzip -j /tmp/xray.zip xray -d /out \
    && chmod +x /out/xray \
    && rm -rf /var/lib/apt/lists/*

# ── stage 3: runtime ──
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /out /app/out
COPY --from=xray /out/xray /app/bin/xray
COPY bin/deep-probe /app/bin/deep-probe
RUN chmod +x /app/out /app/bin/xray /app/bin/deep-probe && mkdir -p /data
ENV PORT=8080 TZ=UTC
EXPOSE 8080
ENTRYPOINT ["/app/out"]
