package main

import (
        "bytes"
        "compress/gzip"
        "crypto/subtle"
        "embed"
        "fmt"
        "net"
        "net/http"
        "strings"
        "sync"
        "time"
)

// ─────────── HTTP front: panel UI + API + subscriptions ───────────

//go:embed web
var webFS embed.FS

var securityHeaders = map[string]string{
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy":        "no-referrer",
}

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

func rootHandler(w http.ResponseWriter, r *http.Request) {
        path := r.URL.Path
        if path == "" {
                path = "/"
        }
        for k, v := range securityHeaders {
                w.Header().Set(k, v)
        }

        // 1) panel API
        if strings.HasPrefix(path, "/panel/api/") {
                w.Header().Set("Cache-Control", "no-store")
                handleAPI(w, r, path)
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

        // 4) decoy site
        serveDecoy(w, r)
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

// serveDecoy serves the innocent landing page at /.
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

// ─────────── auth plumbing ───────────

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

// requestHost: the host the ADMIN's browser used — links always ride the same
// host (works identically with a bare IP or a future domain). The port is
// preserved when non-standard (PORT=8080 deployments must carry it in links).
func requestHost(r *http.Request) string {
        h := osGetenv("DOMAIN")
        if h == "" {
                h = r.Header.Get("X-Forwarded-Host")
        }
        if h == "" {
                h = r.Host
        }
        h = strings.TrimSpace(strings.Split(h, ",")[0])
        if h == "" {
                return h
        }
        // strip only the STANDARD ports — custom ports must survive
        host, port, err := net.SplitHostPort(h)
        if err != nil || port == "" {
                return h
        }
        if port == "80" || port == "443" {
                return host
        }
        if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
                return "[" + host + "]:" + port
        }
        return host + ":" + port
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
        w.Header().Add("Set-Cookie", "sid="+sid+"; Path=/; HttpOnly; SameSite=Strict; Max-Age="+itoa(maxAge))
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
        srv := &http.Server{
                Addr:              ":" + itoa(port),
                Handler:           mux,
                ReadHeaderTimeout: 20 * time.Second,
                IdleTimeout:       150 * time.Second,
        }
        logf("DEEP NETWORK %s listening on :%d", Version, port)
        return srv.ListenAndServe()
}

func listenTCP(addr string) (net.Listener, error) {
        return net.Listen("tcp", addr)
}

// publicHost resolves the address shown in --banner (public IP via ipify,
// falling back to the last Host header seen, then the env DOMAIN).
func publicHost() string {
        if d := strings.TrimSpace(osGetenv("DOMAIN")); d != "" {
                return d
        }
        if ip := cachedPublicIP(); ip != "" {
                return ip
        }
        stateMu.RLock()
        lh := state.LastHost
        stateMu.RUnlock()
        if lh != "" && !strings.Contains(lh, "127.") && !strings.Contains(lh, "localhost") {
                return lh
        }
        return "<SERVER-IP>"
}

var (
        pubIPMu  sync.Mutex
        pubIPVal string
        pubIPAt  time.Time
)


func cachedPublicIP() string {
        pubIPMu.Lock()
        defer pubIPMu.Unlock()
        if pubIPVal != "" && time.Since(pubIPAt) < 10*time.Minute {
                return pubIPVal
        }
        client := http.Client{Timeout: 5 * time.Second}
        for _, u := range []string{"https://api.ipify.org", "http://checkip.amazonaws.com"} {
                resp, err := client.Get(u)
                if err != nil {
                        continue
                }
                buf := make([]byte, 64)
                n, _ := resp.Body.Read(buf)
                resp.Body.Close()
                ip := strings.TrimSpace(string(buf[:n]))
                if net.ParseIP(ip) != nil {
                        pubIPVal = ip
                        pubIPAt = time.Now()
                        return ip
                }
        }
        return pubIPVal
}
