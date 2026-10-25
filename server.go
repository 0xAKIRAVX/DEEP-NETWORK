package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"embed"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// ─────────── HTTP front: panel UI + API + subscriptions + tunnel proxy (replaces nginx) ───────────

//go:embed web
var webFS embed.FS

var onlineTunnelsVal int64

func onlineTunnels() int64 { return atomic.LoadInt64(&onlineTunnelsVal) }

type tunnelCountWriter struct {
	http.ResponseWriter
}

var securityHeaders = map[string]string{
	"X-Content-Type-Options": "nosniff",
	"Referrer-Policy":        "no-referrer",
	// NOTE(v3.4): X-Frame-Options is intentionally NOT global anymore —
	// the panel must be frameable so Telegram Web (web.telegram.org)
	// can embed it as a Mini App. /sub and the decoy still send DENY.
}

type proxyRoute struct {
	prefix  string // path prefix ("/ws", custom inbound paths)
	backend string // 127.0.0.1:10001
	isGRPC  bool
	proxy   *httputil.ReverseProxy
}

var proxyMu atomic.Value // []proxyRoute
var proxyConns atomic.Int64

func buildProxyRoutes() []proxyRoute {
	var routes []proxyRoute
	add := func(path, backend string, grpc bool) {
		r := proxyRoute{prefix: path, backend: backend, isGRPC: grpc}
		target, _ := url.Parse("http://" + backend)
		p := &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(target)
				pr.Out.Host = pr.In.Host
				pr.SetXForwarded()
			},
			FlushInterval: -1,
			Transport:     h1Transport,
		}
		if grpc {
			p.Transport = h2Transport
		}
		r.proxy = p
		routes = append(routes, r)
	}
	if protoEnabled("vless-ws") {
		add(wsPath(), "127.0.0.1:10001", false)
	}
	if protoEnabled("vmess-ws") {
		add(vmessPath(), "127.0.0.1:10004", false)
	}
	if protoEnabled("trojan-ws") {
		add(trojanPath(), "127.0.0.1:10005", false)
	}
	if protoEnabled("vless-hu") {
		add(huPath(), "127.0.0.1:10006", false)
	}
	if protoEnabled("vless-xhttp") {
		add(xhttpPath(), "127.0.0.1:10002", false)
	}
	stateMu.RLock()
	var customs []*Inbound
	for _, ib := range state.Inbounds {
		cp := *ib
		if cp.Security == "tls" {
			customs = append(customs, &cp)
		}
	}
	stateMu.RUnlock()
	for _, ib := range customs {
		add(ib.Path, "127.0.0.1:"+itoa(ib.LPort), ib.Network == "grpc")
	}
	return routes
}

func refreshProxyRoutes() {
	proxyMu.Store(buildProxyRoutes())
}

var h1Transport = &http.Transport{
	Proxy:                 nil,
	DialContext:           (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 120 * time.Second}).DialContext,
	MaxIdleConns:          512,
	MaxIdleConnsPerHost:   256,
	IdleConnTimeout:       120 * time.Second,
	DisableCompression:    true,
	ForceAttemptHTTP2:     false,
	TLSHandshakeTimeout:   10 * time.Second,
	ResponseHeaderTimeout: 0,
	ExpectContinueTimeout: 0,
}

// h2Transport speaks cleartext h2 to xray's gRPC inbounds (h2c origin).
var h2Transport = &http2.Transport{
	AllowHTTP: true,
	DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	},
}

// ─────────── helpers ───────────

func wsPath() string     { return normPath(osGetenv("WS_PATH"), "/ws") }
func xhttpPath() string  { return normPath(osGetenv("XHTTP_PATH"), "/xhttp") }
func huPath() string     { return normPath(osGetenv("HU_PATH"), "/hu") }
func vmessPath() string  { return normPath(osGetenv("VMESS_PATH"), "/vmess") }
func trojanPath() string { return normPath(osGetenv("TROJAN_PATH"), "/trojan") }

func logf(format string, args ...any) {
	fmt.Printf(format+"\n", args...)
}

func appDir() string {
	exe, err := exeAbs()
	if err != nil {
		return "."
	}
	return dirOf(exe)
}

// ─────────── root handler ───────────

type responseWriterWrap struct {
	http.ResponseWriter
	status int
}

func (w *responseWriterWrap) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "" {
		path = "/"
	}

	// security headers on everything
	for k, v := range securityHeaders {
		w.Header().Set(k, v)
	}

	// 1) panel API
	if strings.HasPrefix(path, "/panel/api/") {
		w.Header().Set("Cache-Control", "no-store")
		handleAPI(w, r, path)
		return
	}

	// 1b) Telegram webhook (secret-token guarded — no session auth)
	if path == "/panel/tgwebhook" {
		handleTelegramWebhook(w, r)
		return
	}

	// 2) panel UI
	if path == "/panel/avatar.png" {
		serveAvatar(w, r)
		return
	}
	if path == "/panel" || path == "/panel/" || strings.HasPrefix(path, "/panel/") {
		w.Header().Set("Cache-Control", "no-store")
		servePanelAsset(w, r, path)
		return
	}

	// 3) subscriptions
	if strings.HasPrefix(path, "/sub/") {
		handleSub(w, r, strings.Trim(strings.TrimPrefix(path, "/sub/"), "/"))
		return
	}

	// 4) tunnel proxy routes (dynamic; longest prefix wins)
	if routes, ok := proxyMu.Load().([]proxyRoute); ok && len(routes) > 0 {
		best := -1
		for i, rt := range routes {
			if path == rt.prefix || strings.HasPrefix(path, rt.prefix+"/") ||
				(rt.prefix != "/" && strings.HasPrefix(path, rt.prefix+"?")) {
				if best < 0 || len(routes[i].prefix) > len(routes[best].prefix) {
					best = i
				}
			}
		}
		if best >= 0 {
			rt := routes[best]
			if isUpgrade(r) {
				proxyConns.Add(1)
				atomic.AddInt64(&onlineTunnelsVal, 1)
				defer func() {
					proxyConns.Add(-1)
					atomic.AddInt64(&onlineTunnelsVal, -1)
				}()
			}
			rt.proxy.ServeHTTP(w, r)
			return
		}
	}

	// 5) decoy site (everything else → index.html)
	serveDecoy(w, r)
}

func isUpgrade(r *http.Request) bool {
	for _, v := range r.Header.Values("Connection") {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), "upgrade") {
				return true
			}
		}
	}
	return false
}

// ─────────── panel assets (embedded) ───────────

func servePanelAsset(w http.ResponseWriter, r *http.Request, path string) {
	rel := strings.TrimPrefix(path, "/panel")
	rel = strings.TrimPrefix(rel, "/")
	if rel == "" {
		rel = "index.html"
	}
	if rel == "api" {
		http.NotFound(w, r)
		return
	}
	b, err := webFS.ReadFile("web/" + rel)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ctype := contentTypeFor(rel)
	w.Header().Set("Content-Type", ctype)
	if strings.Contains(rel, ".woff2") || strings.Contains(rel, "img/") || strings.Contains(rel, "fonts/") {
		w.Header().Set("Cache-Control", "public, max-age=86400")
	} else {
		w.Header().Set("Cache-Control", "no-store")
	}
	if ctype == "text/html; charset=utf-8" {
		b = bytes.ReplaceAll(b, []byte("__PANEL_VER__"), []byte(Version))
	}
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") && len(b) > 1024 {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		_, _ = gz.Write(b)
		gz.Close()
		if buf.Len() < len(b) {
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Length", itoa(buf.Len()))
			w.WriteHeader(200)
			_, _ = w.Write(buf.Bytes())
			return
		}
	}
	w.Header().Set("Content-Length", itoa(len(b)))
	w.WriteHeader(200)
	_, _ = w.Write(b)
}

func contentTypeFor(name string) string {
	switch {
	case strings.HasSuffix(name, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(name, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(name, ".js"):
		return "application/javascript; charset=utf-8"
	case strings.HasSuffix(name, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(name, ".png"):
		return "image/png"
	case strings.HasSuffix(name, ".jpg"), strings.HasSuffix(name, ".jpeg"):
		return "image/jpeg"
	case strings.HasSuffix(name, ".woff2"):
		return "font/woff2"
	default:
		return "application/octet-stream"
	}
}

// serveDecoy serves the landing page at / (masking the tunnel paths).
func serveDecoy(w http.ResponseWriter, r *http.Request) {
	b, err := webFS.ReadFile("web/decoy.html")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Length", itoa(len(b)))
	w.WriteHeader(200)
	_, _ = w.Write(b)
}

// ─────────── auth ───────────

func clientIP(r *http.Request) string {
	if xr := r.Header.Get("X-Real-IP"); xr != "" {
		return strings.TrimSpace(xr)
	}
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		parts := strings.Split(xf, ",")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func requestHost(r *http.Request) string {
	h := osGetenv("DOMAIN")
	if h == "" {
		h = r.Header.Get("X-Forwarded-Host")
	}
	if h == "" {
		h = r.Host
	}
	host := strings.TrimSpace(strings.Split(strings.Split(h, ",")[0], ":")[0])
	return host
}

func authSession(r *http.Request) (string, bool) {
	c, err := r.Cookie("sid")
	if err != nil || c.Value == "" {
		return "", false
	}
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	exp, ok := sessions[c.Value]
	if !ok || !exp.After(time.Now()) {
		return "", false
	}
	sessions[c.Value] = time.Now().Add(sessionTTL())
	return c.Value, true
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, sid string, maxAge int) {
	secure := "; Secure"
	if r != nil && r.TLS == nil {
		proto := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]))
		if proto != "https" {
			secure = "" // local http dev (production always rides behind the https edge)
		}
	}
	w.Header().Add("Set-Cookie", "sid="+sid+"; Path=/; HttpOnly; SameSite=Strict; Max-Age="+itoa(maxAge)+secure)
}

func clearSessionCookie(w http.ResponseWriter) {
	w.Header().Add("Set-Cookie", "sid=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
}

func constantTimeEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func newSession() string {
	sid := randHex(24)
	sessionsMu.Lock()
	sessions[sid] = time.Now().Add(sessionTTL())
	sessionsMu.Unlock()
	return sid
}

func dropAllSessions(keep string) {
	sessionsMu.Lock()
	sessions = map[string]time.Time{}
	if keep != "" {
		sessions[keep] = time.Now().Add(sessionTTL())
	}
	sessionsMu.Unlock()
}

func loginAllowed(ip string) bool {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	var recent []time.Time
	for _, t := range loginFails[ip] {
		if time.Since(t) < loginFailWindow {
			recent = append(recent, t)
		}
	}
	loginFails[ip] = recent
	return len(recent) < 8
}

func recordLoginFail(ip string) {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	loginFails[ip] = append(loginFails[ip], time.Now())
}

// ─────────── server start ───────────

func startServer(port int) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", rootHandler)

	h2s := &http2.Server{}
	handler := h2c.NewHandler(mux, h2s)

	srv := &http.Server{
		Addr:              ":" + itoa(port),
		Handler:           handler,
		ReadHeaderTimeout: 20 * time.Second,
		IdleTimeout:       150 * time.Second,
	}
	logf("DEEP NETWORK %s listening on :%d", Version, port)
	return srv.ListenAndServe()
}
