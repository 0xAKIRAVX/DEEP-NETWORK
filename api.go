package main

import (
        "encoding/base64"
        "encoding/json"
        "fmt"
        "io"
        "net"
        "net/http"
        "regexp"
        "strconv"
        "strings"
        "time"
)

// ─────────── /panel/api/* — full JSON API (v3, Go rewrite of the Python panel) ───────────

func sendJSON(w http.ResponseWriter, code int, obj any) {
        w.Header().Set("Content-Type", "application/json; charset=utf-8")
        b, _ := json.Marshal(obj)
        w.Header().Set("Content-Length", itoa(len(b)))
        w.WriteHeader(code)
        _, _ = w.Write(b)
}

func sendBytes(w http.ResponseWriter, code int, body []byte, ctype string, extra map[string]string) {
        w.Header().Set("Content-Type", ctype)
        w.Header().Set("Content-Length", itoa(len(body)))
        for k, v := range extra {
                w.Header().Set(k, v)
        }
        w.WriteHeader(code)
        _, _ = w.Write(body)
}

func readJSONBody(r *http.Request) map[string]any {
        defer r.Body.Close()
        b, err := io.ReadAll(io.LimitReader(r.Body, 262144))
        if err != nil {
                return map[string]any{}
        }
        var d map[string]any
        if json.Unmarshal(b, &d) != nil {
                return map[string]any{}
        }
        return d
}

func jstr(d map[string]any, k string) string {
        if v, ok := d[k]; ok {
                if s, ok := v.(string); ok {
                        return s
                }
        }
        return ""
}

func jint(d map[string]any, k string) int64 {
        if v, ok := d[k]; ok {
                switch x := v.(type) {
                case float64:
                        return int64(x)
                case int:
                        return int64(x)
                case int64:
                        return x
                }
        }
        return 0
}

func jbool(d map[string]any, k string) bool {
        if v, ok := d[k]; ok {
                if b, ok := v.(bool); ok {
                        return b
                }
        }
        return false
}

// trunc runes-safe truncation: never splits a UTF-8 character (Persian names stay intact).
func trunc(s string, n int) string {
        if n <= 0 {
                return ""
        }
        if len(s) <= n {
                return s
        }
        out := []rune(s)
        if len(out) <= n {
                return s
        }
        return string(out[:n])
}

// handleSub serves /sub/<token> — default: base64 link list for v2rayNG-style
// clients. ?fmt=json → [{name,url}] array; ?fmt=xray → full ready-to-import
// Xray client config (the "most optimal" JSON sub — speed pack baked in).
func handleSub(w http.ResponseWriter, r *http.Request, tok string) {
        if tok == "" {
                sendBytes(w, 404, []byte("not found"), "text/plain; charset=utf-8", nil)
                return
        }
        stateMu.RLock()
        var match *Client
        for _, c := range state.Clients {
                if constantTimeEq(subToken(c.ID), tok) {
                        cp := *c
                        match = &cp
                        break
                }
        }
        stateMu.RUnlock()
        if match == nil {
                sendBytes(w, 404, []byte("not found"), "text/plain; charset=utf-8", nil)
                return
        }
        info := []string{fmt.Sprintf("upload=%d", match.Up), fmt.Sprintf("download=%d", match.Down)}
        if match.Quota > 0 {
                info = append(info, fmt.Sprintf("total=%d", match.Quota))
        }
        if match.ExpireAt > 0 {
                info = append(info, fmt.Sprintf("expire=%d", match.ExpireAt))
        }
        hdrs := map[string]string{
                "Profile-Title":           "base64:" + base64.StdEncoding.EncodeToString([]byte(match.Name)),
                "Profile-Update-Interval": "12",
                "Subscription-Userinfo":   strings.Join(info, "; "),
                "X-Frame-Options":         "DENY",
        }
        switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("fmt"))) {
        case "json":
                links := buildLinks(match, requestHost(r))
                var arr []map[string]string
                for _, l := range links {
                        arr = append(arr, map[string]string{"name": linkDisplayName(l), "url": l.URL})
                }
                b, _ := json.MarshalIndent(arr, "", "  ")
                sendBytes(w, 200, b, "application/json; charset=utf-8", hdrs)
        case "xray":
                cfg := clientConfigJSON(match, requestHost(r), "")
                if _, hasErr := cfg["error"]; hasErr {
                        sendJSON(w, 400, cfg)
                        return
                }
                b, _ := json.MarshalIndent(cfg, "", "  ")
                sendBytes(w, 200, b, "application/json; charset=utf-8", hdrs)
        default:
                links := buildLinks(match, requestHost(r))
                var lines []string
                for _, l := range links {
                        lines = append(lines, l.URL)
                }
                body := base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n")))
                sendBytes(w, 200, []byte(body), "text/plain; charset=utf-8", hdrs)
        }
}

// ─────────── main API dispatcher ───────────

func handleAPI(w http.ResponseWriter, r *http.Request, path string) {
        switch r.Method {
        case http.MethodGet, http.MethodHead:
                // speedblob is public: it serves plain zero bytes and is fetched through
                // the CDN edge (no session cookie can ride along) — used by edgespeed.
                if path == "/panel/api/speedblob" {
                        handleSpeedBlob(w, r)
                        return
                }
                if !apiAuth(w, r) {
                        return
                }
                switch {
                case path == "/panel/api/ping":
                        sendJSON(w, 200, map[string]any{"ok": true, "t": time.Now().UnixMilli()})
                case path == "/panel/api/stats":
                        sendJSONGz(r, w, 200, statsPayload())
                case path == "/panel/api/state":
                        sendJSONGz(r, w, 200, statePayload(r))
                case path == "/panel/api/log":
                        sendJSONGz(r, w, 200, map[string]any{"lines": logTail(150)})
                case path == "/panel/api/health":
                        sendJSON(w, 200, healthPayload())
                case path == "/panel/api/online":
                        // v3.10: live user sessions — who is using the panel
                        // right now, for how long, and when they went offline.
                        sendJSONGz(r, w, 200, onlinePayload())
                case path == "/panel/api/localmode":
                        // v3.11: national-internet kit — settings + relay guide.
                        sendJSONGz(r, w, 200, localModePayload(requestHost(r)))
                case path == "/panel/api/localmode/kit":
                        // v3.11: offline survival kit (download & save BEFORE a cutoff).
                        sendBytes(w, 200, []byte(localModeKitText(requestHost(r))),
                                "text/plain; charset=utf-8", map[string]string{
                                        "Content-Disposition": "attachment; filename=deep-network-local-mode-kit.txt"})
                case path == "/panel/api/whoami":
                        handleWhoami(w, r)
                case path == "/panel/api/server-config":
                        b, _ := json.MarshalIndent(buildXrayConfig(), "", "  ")
                        sendBytes(w, 200, b, "application/json; charset=utf-8", map[string]string{
                                "Content-Disposition": "attachment; filename=xray-server.json"})
                case path == "/panel/api/backup":
                        handleBackup(w)
                case path == "/panel/api/qr":
                        handleQR(w, r)
                case strings.HasPrefix(path, "/panel/api/client/"):
                        handleClientConfig(w, r, strings.Trim(strings.TrimPrefix(path, "/panel/api/client/"), "/"))
                default:
                        sendJSON(w, 404, map[string]any{"error": "not found"})
                }
        case http.MethodPost:
                if path == "/panel/api/login" {
                        handleLogin(w, r)
                        return
                }
                if path == "/panel/api/logout" {
                        if sid, ok := authSession(r); ok {
                                sessionsMu.Lock()
                                delete(sessions, sid)
                                sessionsMu.Unlock()
                        }
                        clearSessionCookie(w)
                        sendJSON(w, 200, map[string]any{"ok": true})
                        return
                }
                if !apiAuth(w, r) {
                        return
                }
                switch path {
                case "/panel/api/clients":
                        handleClientAdd(w, r)
                case "/panel/api/clients/edit":
                        handleClientEdit(w, r)
                case "/panel/api/clients/bulk":
                        handleClientBulk(w, r)
                case "/panel/api/clients/delete":
                        handleClientDelete(w, r)
                case "/panel/api/clients/regen":
                        handleClientRegen(w, r)
                case "/panel/api/reset-traffic-all":
                        stateMu.Lock()
                        for _, c := range state.Clients {
                                c.Up, c.Down = 0, 0
                        }
                        saveStateLocked()
                        stateMu.Unlock()
                        sendJSON(w, 200, map[string]any{"ok": true})
                case "/panel/api/restore":
                        handleRestore(w, r)
                case "/panel/api/inbounds":
                        handleInboundAdd(w, r)
                case "/panel/api/inbounds/delete":
                        handleInboundDelete(w, r)
                case "/panel/api/settings":
                        handleSettings(w, r)
                case "/panel/api/avatar":
                        handleAvatarUpload(w, r)
                case "/panel/api/avatar/delete":
                        handleAvatarDelete(w, r)
                case "/panel/api/restart":
                        restartXray()
                        refreshProxyRoutes()
                        sendJSON(w, 200, map[string]any{"ok": true})
                case "/panel/api/ipscan":
                        handleIPScan(w, r)
                case "/panel/api/bunnyedges":
                        handleBunnyEdges(w, r)
                case "/panel/api/probe":
                        handleProbe(w, r)
                case "/panel/api/edgespeed":
                        handleEdgeSpeed(w, r)
                case "/panel/api/telegram":
                        handleTelegramConnect(w, r)
                default:
                        sendJSON(w, 404, map[string]any{"error": "not found"})
                }
        case http.MethodDelete:
                if !apiAuth(w, r) {
                        return
                }
                if path == "/panel/api/telegram" {
                        handleTelegramDisconnect(w, r)
                        return
                }
                sendJSON(w, 404, map[string]any{"error": "not found"})
        default:
                sendJSON(w, 405, map[string]any{"error": "method not allowed"})
        }
}

func apiAuth(w http.ResponseWriter, r *http.Request) bool {
        if _, ok := authSession(r); ok {
                return true
        }
        sendJSON(w, 401, map[string]any{"error": "unauthorized"})
        return false
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
        ip := clientIP(r)
        if !loginAllowed(ip) {
                sendJSON(w, 429, map[string]any{"error": "تلاش‌های ناموفق زیاد — چند دقیقه بعد دوباره امتحان کنید"})
                return
        }
        d := readJSONBody(r)
        // ── Telegram Mini-App login (v3.4): no password needed when the
        // initData signature verifies AND the Telegram user id matches the
        // admin id configured in Settings → the bot owner opens the panel
        // inside Telegram with one tap.
        if tgd := jstr(d, "tg_init_data"); tgd != "" {
                stateMu.RLock()
                token, adminID := state.TGToken, state.TGAdminID
                au := state.AdminUser
                stateMu.RUnlock()
                if token != "" && adminID != "" {
                        if uid, ok := validateTGInitData(tgd, token); ok && strconvFormatInt(uid) == adminID {
                                sid := newSession()
                                setSessionCookie(w, r, sid, int(sessionTTL().Seconds()))
                                sendJSON(w, 200, map[string]any{"ok": true, "user": au, "via": "telegram"})
                                return
                        }
                }
                sendJSON(w, 401, map[string]any{"error": "ورود تلگرام فعال نیست یا شناسه شما مطابقت ندارد — با رمز عبور وارد شوید"})
                return
        }
        user, pass := jstr(d, "user"), jstr(d, "pass")
        stateMu.RLock()
        au, ap := state.AdminUser, state.AdminPass
        stateMu.RUnlock()
        if user != au || !constantTimeEq(pass, ap) {
                recordLoginFail(ip)
                time.Sleep(700 * time.Millisecond)
                sendJSON(w, 401, map[string]any{"error": "نام کاربری یا رمز عبور اشتباه است"})
                return
        }
        sid := newSession()
        setSessionCookie(w, r, sid, int(sessionTTL().Seconds()))
        sendJSON(w, 200, map[string]any{"ok": true, "user": user})
}

func handleWhoami(w http.ResponseWriter, r *http.Request) {
        ip := clientIP(r)
        e := lookupWhoami(ip)
        if e == nil {
                sendJSON(w, 200, map[string]any{"ip": ip, "operator": "auto", "label": "خودکار"})
                return
        }
        sendJSON(w, 200, map[string]any{
                "ip": ip, "operator": e.op, "label": e.label, "cc": e.cc, "city": e.city,
                "lat": e.lat, "lon": e.lon,
        })
}

func statePayload(r *http.Request) map[string]any {
        host := requestHost(r)
        scheme := "https"
        if v := strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]; strings.TrimSpace(v) == "http" {
                scheme = "http"
        }
        stateMu.RLock()
        clients := append([]*Client(nil), state.Clients...)
        settings := map[string]any{
                "user": state.AdminUser, "address": state.Address,
                "sni_override": state.SNIOverride, "random_sni": state.RandomSNI,
                "reality_sni": state.RealitySNI, "cfg_fmt": state.CfgFmt,
                "session_hours": state.SessionHours, "operators": operatorProfiles,
                "tuning":    tuningSanitize(state.Tuning),
                "tcp_ready": tcpReady(),
                "top_edges": state.TopEdges, "multi_edge": state.MultiEdge,
                "local_mode": localModeGet(),
                "telegram": map[string]any{"connected": state.TGToken != "",
                        "bot_username": state.TGBotUser, "admin_id": state.TGAdminID},
        }
        stateMu.RUnlock()
        stateMu.RLock()
        protocols := map[string]bool{}
        for _, k := range protoKeys {
                protocols[k] = state.Protocols == nil || state.Protocols[k]
        }
        stateMu.RUnlock()
        settings["protocols"] = protocols

        now := time.Now()
        var out []map[string]any
        for _, c := range clients {
                exp := c.ExpireAt
                days := 0
                if exp > now.Unix() {
                        days = int((exp-now.Unix())/86400) + 1
                }
                out = append(out, map[string]any{
                        "name": c.Name, "id": c.ID, "main": c.ID == mainUUID(),
                        "sub_url": scheme + "://" + host + "/sub/" + subToken(c.ID),
                        "links":   buildLinks(c, host),
                        "quota":   c.Quota, "up": c.Up, "down": c.Down, "expire_at": exp,
                        "status": clientStatus(c, now), "days_left": days, "note": c.Note,
                        "protocols": sortedProtoKeys(c),
                        // v3.10: online monitor fields (live flag + last seen)
                        "online": userOnlineNow(c.ID), "last_seen": c.LastSeen,
                        "online_dur": onlineDurFor(c.ID),
                })
        }
        protoNotes := map[string]string{
                "vless-ws":      "سازگارترین گزینه؛ روی اغلب کلاینت‌ها کار می‌کند",
                "vless-xhttp":   "حالت packet-up؛ مخصوص عبور از پروکسی‌های HTTP",
                "vless-hu":      "سبک و سریع، شبیه WebSocket",
                "vmess-ws":      "برای کلاینت‌های قدیمی و برخی فیلترشکن‌های اندروید",
                "trojan-ws":     "رمز = UUID کاربر",
                "vless-reality": "نیازمند TCP Proxy در پلتفرم (در Lucity غیرفعال)",
        }
        var protoList []map[string]any
        for _, k := range protoKeys {
                protoList = append(protoList, map[string]any{"key": k, "name": protoLabels[k],
                        "path": pathOfProto(k), "note": protoNotes[k]})
        }
        var customs []map[string]any
        stateMu.RLock()
        for _, ib := range state.Inbounds {
                customs = append(customs, map[string]any{"tag": ib.Tag, "name": ib.Name,
                        "protocol": ib.Protocol, "network": ib.Network, "security": ib.Security,
                        "port": ib.Port, "path": ib.Path, "sni": ib.SNI})
        }
        stateMu.RUnlock()
        return map[string]any{
                "version": Version, "clients": out, "protocols": protoList, "inbounds": customs,
                "settings": settings, "cipher_presets": cipherPresets,
                "fps": fpsList, "alpn_modes": alpnModes,
        }
}

func pathOfProto(k string) string {
        switch k {
        case "vless-ws":
                return wsPath()
        case "vless-xhttp":
                return xhttpPath()
        case "vless-hu":
                return huPath()
        case "vmess-ws":
                return vmessPath()
        case "trojan-ws":
                return trojanPath()
        default:
                return ""
        }
}

func handleClientConfig(w http.ResponseWriter, r *http.Request, cid string) {
        stateMu.RLock()
        var c *Client
        for _, x := range state.Clients {
                if x.ID == cid {
                        cp := *x
                        c = &cp
                        break
                }
        }
        stateMu.RUnlock()
        if c == nil {
                sendJSON(w, 404, map[string]any{"error": "کاربر پیدا نشد"})
                return
        }
        prof := strings.TrimSpace(r.URL.Query().Get("profile"))
        if prof != "" && prof != "fast" {
                if _, ok := operatorProfiles[prof]; !ok {
                        sendJSON(w, 400, map[string]any{"error": "پروفایل اپراتور نامعتبر است"})
                        return
                }
        }
        safe := sanitizeName(c.Name)
        cfg := clientConfigJSON(c, requestHost(r), prof)
        if _, hasErr := cfg["error"]; hasErr {
                sendJSON(w, 400, cfg)
                return
        }
        b, _ := json.MarshalIndent(cfg, "", "  ")
        suffix := ""
        if prof != "" {
                suffix = "-" + prof
        }
        sendBytes(w, 200, b, "application/json; charset=utf-8", map[string]string{
                "Content-Disposition": "attachment; filename=deepnetwork-" + safe + suffix + ".json"})
}

var nameClean = regexp.MustCompile(`[^A-Za-z0-9_.\-]`)

func sanitizeName(n string) string {
        s := nameClean.ReplaceAllString(n, "")
        if len(s) > 24 {
                s = s[:24]
        }
        if s == "" {
                return "user"
        }
        return s
}

// validAddress accepts a hostname, an IPv4 literal, or an IPv6 literal
// (bare or [bracketed]) for the settings "address" field (v3.7 IPv6).
func validAddress(a string) bool {
        a = strings.TrimSpace(a)
        if a == "" || len(a) > 253 {
                return false
        }
        bare := strings.Trim(a, "[]")
        if ip := net.ParseIP(bare); ip != nil {
                return !(ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified())
        }
        return hostRe.MatchString(a)
}

func handleBackup(w http.ResponseWriter) {
        stateMu.RLock()
        snap := map[string]any{
                "ng_backup": 3, "version": Version, "exported": time.Now().Unix(),
                "state": map[string]any{
                        "address": state.Address, "reality_sni": state.RealitySNI,
                        "sni_override": state.SNIOverride, "tuning": state.Tuning,
                        "cfg_fmt": state.CfgFmt,
                        "protocols": func() map[string]bool {
                                m := map[string]bool{}
                                for _, k := range protoKeys {
                                        m[k] = state.Protocols == nil || state.Protocols[k]
                                }
                                return m
                        }(),
                        "session_hours": state.SessionHours,
                        "clients":       func() []*Client { return append([]*Client(nil), state.Clients...) }(),
                        "inbounds":      func() []*Inbound { return append([]*Inbound(nil), state.Inbounds...) }(),
                },
        }
        stateMu.RUnlock()
        b, _ := json.MarshalIndent(snap, "", "  ")
        sendBytes(w, 200, b, "application/json; charset=utf-8", map[string]string{
                "Content-Disposition": "attachment; filename=deepnetwork-backup-" + time.Now().Format("20060102") + ".json"})
}

func handleQR(w http.ResponseWriter, r *http.Request) {
        data := r.URL.Query().Get("data")
        if data == "" || len(data) > 800 {
                sendJSON(w, 400, map[string]any{"error": "متن QR نامعتبر یا طولانی است"})
                return
        }
        svg, err := qrSVG(data)
        if err != nil {
                sendJSON(w, 400, map[string]any{"error": "ساخت QR ممکن نشد"})
                return
        }
        sendBytes(w, 200, []byte(svg), "image/svg+xml; charset=utf-8", nil)
}

// ─────────── POST handlers ───────────

func handleClientAdd(w http.ResponseWriter, r *http.Request) {
        d := readJSONBody(r)
        name := trunc(strings.TrimSpace(jstr(d, "name")), 30)
        if name == "" {
                sendJSON(w, 400, map[string]any{"error": "نام کاربر را وارد کنید"})
                return
        }
        quota := jint(d, "quota")
        if quota < 0 || quota > 1<<40 {
                sendJSON(w, 400, map[string]any{"error": "حجم نامعتبر است"})
                return
        }
        days := jint(d, "days")
        if days < 0 || days > 3650 {
                sendJSON(w, 400, map[string]any{"error": "روز نامعتبر است"})
                return
        }
        id := uuidv4()
        if v := jstr(d, "id"); v != "" {
                id = v
        }
        protos := strList(d["protocols"])
        for _, p := range protos {
                if !inProtoKeys(p) {
                        sendJSON(w, 400, map[string]any{"error": "پروتکل نامعتبر است"})
                        return
                }
        }
        c := &Client{Name: name, ID: id, Quota: quota, Note: jstr(d, "note"), Protocols: protos}
        if days > 0 {
                c.ExpireAt = time.Now().Add(time.Duration(days) * 86400e9).Unix()
        }
        stateMu.Lock()
        if len(state.Clients) >= 100 {
                stateMu.Unlock()
                sendJSON(w, 400, map[string]any{"error": "حداکثر ۱۰۰ کاربر مجاز است"})
                return
        }
        state.Clients = append(state.Clients, c)
        saveStateLocked()
        stateMu.Unlock()
        syncXray()
        sendJSON(w, 200, map[string]any{"ok": true, "id": id})
}

func inProtoKeys(k string) bool {
        for _, p := range protoKeys {
                if p == k {
                        return true
                }
        }
        return false
}

func strList(v any) []string {
        l, ok := v.([]any)
        if !ok {
                return nil
        }
        var out []string
        for _, x := range l {
                if s, ok := x.(string); ok {
                        out = append(out, s)
                }
        }
        return out
}

func min(a, b int) int {
        if a < b {
                return a
        }
        return b
}

func handleClientEdit(w http.ResponseWriter, r *http.Request) {
        d := readJSONBody(r)
        cid := jstr(d, "id")
        if cid == "" {
                sendJSON(w, 400, map[string]any{"error": "شناسه کاربر لازم است"})
                return
        }
        stateMu.Lock()
        var c *Client
        for _, x := range state.Clients {
                if x.ID == cid {
                        c = x
                        break
                }
        }
        if c == nil {
                stateMu.Unlock()
                sendJSON(w, 404, map[string]any{"error": "کاربر پیدا نشد"})
                return
        }
        if v, ok := d["quota"]; ok {
                q := int64(v.(float64))
                if q < 0 || q > 1<<40 {
                        stateMu.Unlock()
                        sendJSON(w, 400, map[string]any{"error": "حجم نامعتبر است"})
                        return
                }
                c.Quota = q
        }
        if v, ok := d["days"]; ok {
                days := int64(v.(float64))
                if days < 0 || days > 3650 {
                        stateMu.Unlock()
                        sendJSON(w, 400, map[string]any{"error": "روز نامعتبر است"})
                        return
                }
                if days == 0 {
                        c.ExpireAt = 0
                } else {
                        base := c.ExpireAt
                        if base < time.Now().Unix() {
                                base = time.Now().Unix()
                        }
                        c.ExpireAt = base + days*86400
                }
        }
        if jbool(d, "reset_usage") {
                c.Up, c.Down = 0, 0
        }
        if name := jstr(d, "name"); name != "" {
                c.Name = trunc(name, 30)
        }
        if v, ok := d["note"]; ok {
                if s, ok := v.(string); ok && len(s) <= 140 {
                        c.Note = s
                }
        }
        if v, ok := d["protocols"]; ok {
                protos := strList(v)
                for _, p := range protos {
                        if !inProtoKeys(p) {
                                stateMu.Unlock()
                                sendJSON(w, 400, map[string]any{"error": "پروتکل نامعتبر است"})
                                return
                        }
                }
                c.Protocols = protos
        }
        saveStateLocked()
        stateMu.Unlock()
        syncXray()
        sendJSON(w, 200, map[string]any{"ok": true})
}

func handleClientBulk(w http.ResponseWriter, r *http.Request) {
        d := readJSONBody(r)
        ids := strList(d["ids"])
        action := jstr(d, "action")
        var clean []string
        for _, i := range ids {
                if i != mainUUID() {
                        clean = append(clean, i)
                }
        }
        if len(clean) > 100 {
                clean = clean[:100]
        }
        if len(clean) == 0 || (action != "delete" && action != "reset" && action != "extend") {
                sendJSON(w, 400, map[string]any{"error": "درخواست نامعتبر است"})
                return
        }
        days := jint(d, "days")
        if action == "extend" && (days <= 0 || days > 3650) {
                sendJSON(w, 400, map[string]any{"error": "روز نامعتبر است"})
                return
        }
        now := time.Now().Unix()
        stateMu.Lock()
        touched := 0
        var keep []*Client
        for _, c := range state.Clients {
                if containsStr(clean, c.ID) {
                        touched++
                        if action == "delete" {
                                continue
                        }
                        if action == "reset" {
                                c.Up, c.Down = 0, 0
                        } else if action == "extend" {
                                base := c.ExpireAt
                                if base < now {
                                        base = now
                                }
                                c.ExpireAt = base + days*86400
                        }
                }
                keep = append(keep, c)
        }
        state.Clients = keep
        if touched > 0 {
                saveStateLocked()
        }
        stateMu.Unlock()
        if touched > 0 {
                restartXray()
        }
        sendJSON(w, 200, map[string]any{"ok": true, "affected": touched})
}

func containsStr(list []string, s string) bool {
        for _, x := range list {
                if x == s {
                        return true
                }
        }
        return false
}

// strconvFormatInt keeps telegram.go free of a direct strconv import.
func strconvFormatInt(n int64) string { return strconv.FormatInt(n, 10) }

func handleClientDelete(w http.ResponseWriter, r *http.Request) {
        d := readJSONBody(r)
        cid := jstr(d, "id")
        if cid == mainUUID() {
                sendJSON(w, 400, map[string]any{"error": "کاربر اصلی قابل حذف نیست"})
                return
        }
        stateMu.Lock()
        before := len(state.Clients)
        var keep []*Client
        for _, c := range state.Clients {
                if c.ID != cid {
                        keep = append(keep, c)
                }
        }
        state.Clients = keep
        changed := len(state.Clients) != before
        if changed {
                saveStateLocked()
        }
        stateMu.Unlock()
        if changed {
                sessionDrop(cid) // v3.10: no ghost online entries for deleted users
                restartXray()
        }
        sendJSON(w, 200, map[string]any{"ok": true})
}

func handleClientRegen(w http.ResponseWriter, r *http.Request) {
        d := readJSONBody(r)
        cid := jstr(d, "id")
        if cid == mainUUID() {
                sendJSON(w, 400, map[string]any{"error": "UUID کاربر اصلی قابل تغییر نیست"})
                return
        }
        stateMu.Lock()
        var c *Client
        for _, x := range state.Clients {
                if x.ID == cid {
                        c = x
                        break
                }
        }
        if c == nil {
                stateMu.Unlock()
                sendJSON(w, 404, map[string]any{"error": "کاربر پیدا نشد"})
                return
        }
        c.ID = uuidv4()
        c.Up, c.Down = 0, 0
        c.LastSeen = 0
        newID := c.ID
        saveStateLocked()
        stateMu.Unlock()
        sessionDrop(cid) // v3.10: old id's sessions/history are gone with it
        restartXray()
        sendJSON(w, 200, map[string]any{"ok": true, "id": newID})
}

func handleRestore(w http.ResponseWriter, r *http.Request) {
        d := readJSONBody(r)
        snap, _ := d["state"].(map[string]any)
        if snap == nil {
                sendJSON(w, 400, map[string]any{"error": "فایل پشتیبان نامعتبر است"})
                return
        }
        rawClients, _ := snap["clients"].([]any)
        if len(rawClients) > 100 {
                sendJSON(w, 400, map[string]any{"error": "تعداد کاربران بیش از حد مجاز است"})
                return
        }
        var newClients []*Client
        seen := map[string]bool{}
        for _, rc0 := range rawClients {
                rc, _ := rc0.(map[string]any)
                if rc == nil || jstr(rc, "id") == "" || jstr(rc, "name") == "" {
                        sendJSON(w, 400, map[string]any{"error": "داده کاربر نامعتبر است"})
                        return
                }
                rid := jstr(rc, "id")
                if len(rid) > 64 {
                        rid = rid[:64]
                }
                if seen[rid] {
                        sendJSON(w, 400, map[string]any{"error": "UUID تکراری در فایل پشتیبان"})
                        return
                }
                seen[rid] = true
                note := jstr(rc, "note")
                if len(note) > 140 {
                        note = trunc(note, 140)
                }
                protos := strList(rc["protocols"])
                var validProtos []string
                for _, p := range protos {
                        if inProtoKeys(p) {
                                validProtos = append(validProtos, p)
                        }
                }
                newClients = append(newClients, &Client{
                        Name: trunc(jstr(rc, "name"), 30), ID: rid,
                        Quota: maxI64(0, jint(rc, "quota")), ExpireAt: maxI64(0, jint(rc, "expire_at")),
                        Up: maxI64(0, jint(rc, "up")), Down: maxI64(0, jint(rc, "down")),
                        Note: note, Protocols: validProtos,
                })
        }
        hasMain := false
        for _, c := range newClients {
                if c.ID == mainUUID() {
                        hasMain = true
                }
        }
        if !hasMain {
                newClients = append([]*Client{{Name: "main", ID: mainUUID()}}, newClients...)
        }
        var newInbounds []*Inbound
        usedPaths := map[string]bool{}
        for _, p := range []string{wsPath(), xhttpPath(), huPath(), vmessPath(), trojanPath()} {
                usedPaths[strings.ToLower(p)] = true
        }
        usedPorts := map[int]bool{}
        for p := range builtinPorts {
                usedPorts[p] = true
        }
        rawInbounds, _ := snap["inbounds"].([]any)
        for _, ri0 := range rawInbounds {
                if len(newInbounds) >= 20 {
                        break
                }
                ri, _ := ri0.(map[string]any)
                if ri == nil {
                        continue
                }
                name := trunc(strings.TrimSpace(jstr(ri, "name")), 30)
                proto := strings.ToLower(jstr(ri, "protocol"))
                netw := strings.ToLower(jstr(ri, "network"))
                sec := strings.ToLower(jstr(ri, "security"))
                if name == "" || !inList(proto, []string{"vless", "vmess", "trojan"}) ||
                        !inList(netw, []string{"ws", "xhttp", "httpupgrade", "grpc", "tcp"}) ||
                        !inList(sec, []string{"tls", "reality"}) {
                        continue
                }
                ib := &Inbound{Tag: "ib-" + randHex(4), Name: name, Protocol: proto, Network: netw, Security: sec}
                if sec == "reality" {
                        if proto != "vless" || !inList(netw, []string{"tcp", "xhttp", "grpc"}) || realityPriv == "" {
                                continue
                        }
                        port := int(jint(ri, "port"))
                        if port < 1024 || port > 65535 || usedPorts[port] || (port >= 10100 && port <= 10999) {
                                continue
                        }
                        sni := strings.ToLower(jstr(ri, "sni"))
                        if sni == "" {
                                sni = strings.ToLower(jstr(snap, "reality_sni"))
                        }
                        if sni == "" {
                                stateMu.RLock()
                                sni = state.RealitySNI
                                stateMu.RUnlock()
                        }
                        if !hostRe.MatchString(sni) {
                                continue
                        }
                        ib.Port = port
                        ib.SNI = sni
                        usedPorts[port] = true
                } else {
                        if netw == "tcp" || (proto == "vmess" && netw == "xhttp") {
                                continue
                        }
                        raw := strings.TrimSpace(jstr(ri, "path"))
                        var pathv string
                        if raw != "" {
                                pathv = normPath(raw, "")
                        } else {
                                pathv = "/" + randHex(4)
                        }
                        if len(pathv) < 3 || strings.HasPrefix(strings.ToLower(pathv), "/panel") ||
                                strings.HasPrefix(strings.ToLower(pathv), "/sub") || usedPaths[strings.ToLower(pathv)] {
                                continue
                        }
                        ib.Path = pathv
                        usedPaths[strings.ToLower(pathv)] = true
                        for p := 10100; p < 11000; p++ {
                                if !usedPorts[p] {
                                        ib.LPort = p
                                        usedPorts[p] = true
                                        break
                                }
                        }
                }
                newInbounds = append(newInbounds, ib)
        }
        stateMu.Lock()
        s, _ := snap["protocols"].(map[string]any)
        addr := trunc(strings.TrimSpace(jstr(snap, "address")), 253)
        if addr != "" && !hostRe.MatchString(addr) {
                addr = ""
        }
        state.Address = addr
        sni := strings.ToLower(strings.TrimSpace(jstr(snap, "reality_sni")))
        if hostRe.MatchString(sni) {
                state.RealitySNI = sni
        }
        fmtv := trunc(strings.Join(strings.Fields(jstr(snap, "cfg_fmt")), " "), 100)
        if fmtv == "" {
                fmtv = "{name}-{label}"
        }
        state.CfgFmt = fmtv
        protocols := map[string]bool{}
        for _, k := range protoKeys {
                if v, ok := s[k].(bool); ok {
                        protocols[k] = v
                } else {
                        protocols[k] = true
                }
        }
        state.Protocols = protocols
        if sh := jint(snap, "session_hours"); sh > 0 && sh <= 336 {
                state.SessionHours = int(sh)
        }
        state.Clients = newClients
        state.Inbounds = newInbounds
        so := strings.TrimSpace(jstr(snap, "sni_override"))
        if hostRe.MatchString(so) {
                state.SNIOverride = so
        } else {
                state.SNIOverride = ""
        }
        if t0, ok := snap["tuning"].(map[string]any); ok {
                tb, _ := json.Marshal(t0)
                var t Tuning
                if json.Unmarshal(tb, &t) == nil {
                        state.Tuning = tuningSanitize(&t)
                }
        }
        saveStateLocked()
        stateMu.Unlock()
        restartXray()
        refreshProxyRoutes()
        sendJSON(w, 200, map[string]any{"ok": true, "clients": len(newClients), "inbounds": len(newInbounds)})
}

func inList(s string, list []string) bool { return containsStr(list, s) }

// mergeTuning overlays only the fields present in the incoming partial tuning map
// onto the current tuning, then sanitizes. Prevents the settings form from
// silently resetting custom fragment lengths / delays / fingerprint.
func mergeTuning(cur *Tuning, patch map[string]any) *Tuning {
        base := tuningSanitize(cur)
        if base == nil {
                base = defaultTuning()
        }
        if s, ok := patch["profile"].(string); ok {
                if s != base.Profile {
                        // switching profiles: drop the old profile-implied values so the
                        // new profile's presets apply (explicit patch keys still win below)
                        base.Profile = s
                        base.FragLengths = ""
                        base.FragDelays = ""
                        base.FP = ""
                } else {
                        base.Profile = s
                }
        }
        if b, ok := patch["enabled"].(bool); ok {
                base.Enabled = b
        }
        if b, ok := patch["frag_on"].(bool); ok {
                base.FragOn = b
        }
        if b, ok := patch["noise_on"].(bool); ok {
                base.NoiseOn = b
        }
        if s, ok := patch["fp"].(string); ok {
                base.FP = s
        }
        if s, ok := patch["cipher_suites"].(string); ok {
                base.CipherSuites = s
        }
        if s, ok := patch["alpn"].(string); ok {
                base.ALPN = s
        }
        if s, ok := patch["frag_packets"].(string); ok {
                base.FragPackets = s
        }
        if s, ok := patch["frag_lengths"].(string); ok {
                base.FragLengths = s
        }
        if s, ok := patch["frag_delays"].(string); ok {
                base.FragDelays = s
        }
        if s, ok := patch["frag_maxsplit"].(string); ok {
                base.FragMaxsplit = s
        }
        if s, ok := patch["noise_rand"].(string); ok {
                base.NoiseRand = s
        }
        if s, ok := patch["noise_delay"].(string); ok {
                base.NoiseDelay = s
        }
        if b, ok := patch["mux_off"].(bool); ok {
                base.MuxOff = b
        }
        return tuningSanitize(base)
}

func maxI64(a, b int64) int64 {
        if a > b {
                return a
        }
        return b
}

var grpcSvcRe = regexp.MustCompile(`^[A-Za-z0-9_\-]{3,40}$`)

func handleInboundAdd(w http.ResponseWriter, r *http.Request) {
        d := readJSONBody(r)
        stateMu.Lock()
        ib, err := validateInboundLocked(d)
        if err != "" {
                stateMu.Unlock()
                sendJSON(w, 400, map[string]any{"error": err})
                return
        }
        state.Inbounds = append(state.Inbounds, ib)
        saveStateLocked()
        stateMu.Unlock()
        restartXray()
        refreshProxyRoutes()
        sendJSON(w, 200, map[string]any{"ok": true, "tag": ib.Tag})
}

func validateInboundLocked(d map[string]any) (*Inbound, string) {
        name := trunc(strings.TrimSpace(jstr(d, "name")), 30)
        proto := strings.ToLower(jstr(d, "protocol"))
        netw := strings.ToLower(jstr(d, "network"))
        sec := strings.ToLower(jstr(d, "security"))
        if name == "" {
                return nil, "نام اینباند را وارد کنید"
        }
        if len(state.Inbounds) >= 20 {
                return nil, "حداکثر ۲۰ اینباند سفارشی مجاز است"
        }
        if !inList(proto, []string{"vless", "vmess", "trojan"}) ||
                !inList(netw, []string{"ws", "xhttp", "httpupgrade", "grpc", "tcp"}) ||
                !inList(sec, []string{"tls", "reality"}) {
                return nil, "انتخاب نامعتبر است"
        }
        ib := &Inbound{Tag: "ib-" + randHex(4), Name: name, Protocol: proto, Network: netw, Security: sec}
        if sec == "reality" {
                if proto != "vless" || !inList(netw, []string{"tcp", "xhttp", "grpc"}) {
                        return nil, "Reality فقط با VLESS و ترنسپورت TCP یا XHTTP یا gRPC کار می‌کند"
                }
                if realityPriv == "" {
                        return nil, "کلید Reality آماده نیست"
                }
                port := int(jint(d, "port"))
                if port == 0 {
                        return nil, "پورت را وارد کنید"
                }
                taken := map[int]bool{}
                for p := range builtinPorts {
                        taken[p] = true
                }
                for _, x := range state.Inbounds {
                        taken[x.Port] = true
                }
                if port < 1024 || port > 65535 || taken[port] || (port >= 10100 && port <= 10999) {
                        return nil, "این پورت نامعتبر است یا قبلاً استفاده شده"
                }
                sni := strings.ToLower(jstr(d, "sni"))
                if sni == "" {
                        sni = state.RealitySNI
                }
                if !hostRe.MatchString(sni) {
                        return nil, "SNI نامعتبر است"
                }
                ib.Port = port
                ib.SNI = sni
        } else {
                if netw == "tcp" {
                        return nil, "TCP خام فقط با Reality ممکن است (TLS را دامنه انجام می‌دهد)"
                }
                if proto == "vmess" && netw == "xhttp" {
                        return nil, "VMess با XHTTP پشتیبانی نمی‌شود؛ VLESS یا Trojan را انتخاب کنید"
                }
                lports := map[int]bool{}
                for _, x := range state.Inbounds {
                        lports[x.LPort] = true
                }
                for p := 10100; p < 11000; p++ {
                        if !lports[p] {
                                ib.LPort = p
                                break
                        }
                }
        }
        if netw != "tcp" {
                raw := strings.TrimSpace(jstr(d, "path"))
                if netw == "grpc" {
                        svc := strings.Trim(raw, "/")
                        if svc == "" {
                                svc = randHex(4)
                        }
                        if !grpcSvcRe.MatchString(svc) {
                                return nil, "Service name فقط حروف انگلیسی/عدد/خط تیره (۳ تا ۴۰ نویسه)"
                        }
                        ib.Path = "/" + svc
                } else {
                        var pathv string
                        if raw != "" {
                                pathv = normPath(raw, "")
                        } else {
                                pathv = "/" + randHex(4)
                        }
                        if len(pathv) < 3 {
                                return nil, "مسیر نامعتبر است (حداقل ۲ نویسه؛ فقط حروف انگلیسی، عدد، - _ . /)"
                        }
                        ib.Path = pathv
                }
                low := strings.ToLower(ib.Path)
                if strings.HasPrefix(low, "/panel") || strings.HasPrefix(low, "/sub") {
                        return nil, "این مسیر رزرو شده است"
                }
                if sec == "tls" {
                        used := map[string]bool{}
                        for _, p := range []string{wsPath(), xhttpPath(), huPath(), vmessPath(), trojanPath()} {
                                used[strings.ToLower(p)] = true
                        }
                        for _, x := range state.Inbounds {
                                if x.Security == "tls" && x.Path != "" {
                                        used[strings.ToLower(x.Path)] = true
                                }
                        }
                        if used[low] {
                                return nil, "این مسیر قبلاً استفاده شده است"
                        }
                }
        }
        return ib, ""
}

func handleInboundDelete(w http.ResponseWriter, r *http.Request) {
        d := readJSONBody(r)
        tag := jstr(d, "tag")
        stateMu.Lock()
        before := len(state.Inbounds)
        var keep []*Inbound
        for _, ib := range state.Inbounds {
                if ib.Tag != tag {
                        keep = append(keep, ib)
                }
        }
        state.Inbounds = keep
        changed := len(state.Inbounds) != before
        if changed {
                saveStateLocked()
        }
        stateMu.Unlock()
        if changed {
                restartXray()
                refreshProxyRoutes()
        }
        sendJSON(w, 200, map[string]any{"ok": true})
}

func handleSettings(w http.ResponseWriter, r *http.Request) {
        d := readJSONBody(r)
        needRestart := false
        stateMu.Lock()
        if u := strings.TrimSpace(jstr(d, "user")); u != "" {
                state.AdminUser = trunc(u, 40)
        }
        if p := jstr(d, "pass"); p != "" {
                if len(p) < 6 {
                        stateMu.Unlock()
                        sendJSON(w, 400, map[string]any{"error": "رمز عبور باید حداقل ۶ نویسه باشد"})
                        return
                }
                state.AdminPass = p
                state.PassIsAuto = false
                stateMu.Unlock()
                sid, _ := authSession(r)
                dropAllSessions(sid)
                stateMu.Lock()
        }
        if v, ok := d["address"]; ok {
                a := strings.TrimSpace(fmt.Sprintf("%v", v))
                if a != "" && !validAddress(a) {
                        stateMu.Unlock()
                        sendJSON(w, 400, map[string]any{"error": "آدرس نامعتبر است"})
                        return
                }
                state.Address = a
        }
        if v, ok := d["sni_override"]; ok {
                so := strings.TrimSpace(fmt.Sprintf("%v", v))
                if so != "" && !hostRe.MatchString(so) {
                        stateMu.Unlock()
                        sendJSON(w, 400, map[string]any{"error": "SNI جایگزین نامعتبر است (دامنه وارد کنید)"})
                        return
                }
                state.SNIOverride = so
        }
        if v, ok := d["random_sni"].(bool); ok {
                state.RandomSNI = v
        }
        // v3.9 all-operator pack: graded edge set + subscription expansion toggle.
        if v, ok := d["multi_edge"].(bool); ok {
                state.MultiEdge = v
        }
        if v, ok := d["top_edges"]; ok {
                edges := parseTopEdges(v)
                if len(edges) == 0 {
                        // explicit empty array = clear the set (and disable expansion)
                        state.TopEdges = nil
                        state.MultiEdge = false
                } else {
                        state.TopEdges = edges
                        if len(edges) > 0 && !state.MultiEdge {
                                state.MultiEdge = true
                        }
                }
        }
        // v3.11: national-internet kit (relay / direct-IP / white-SNI).
        if v, ok := d["local_mode"]; ok {
                if m, ok := v.(map[string]any); ok {
                        lm := &LocalModeState{}
                        if b, ok := m["enabled"].(bool); ok {
                                lm.Enabled = b
                        }
                        if rh, ok := m["relay_host"]; ok {
                                lm.RelayHost = strings.TrimSpace(fmt.Sprintf("%v", rh))
                        }
                        if rp, ok := m["relay_port"]; ok {
                                switch x := rp.(type) {
                                case float64:
                                        lm.RelayPort = int(x)
                                case int:
                                        lm.RelayPort = x
                                }
                        }
                        if fs, ok := m["fake_sni"]; ok {
                                lm.FakeSNI = strings.TrimSpace(fmt.Sprintf("%v", fs))
                        }
                        if dip, ok := m["direct_ip"]; ok {
                                lm.DirectIP = strings.TrimSpace(fmt.Sprintf("%v", dip))
                        }
                        clean := localModeSanitize(lm)
                        // Enabling with nothing configured is allowed: the 🛡️
                        // direct-IP variant is auto-built from the panel host;
                        // relay / white-SNI simply stay off until filled in.
                        if clean.RelayHost != "" && clean.RelayPort == 0 {
                                clean.RelayPort = 443
                        }
                        state.LocalMode = &clean
                }
        }
        if v, ok := d["tuning"]; ok {
                if t0, ok := v.(map[string]any); ok {
                        // Partial merge: only keys present in the request are changed,
                        // so saving the settings form never wipes custom fragment values.
                        state.Tuning = mergeTuning(state.Tuning, t0)
                }
        }
        if v, ok := d["reality_sni"]; ok {
                s := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", v)))
                if !hostRe.MatchString(s) {
                        stateMu.Unlock()
                        sendJSON(w, 400, map[string]any{"error": "SNI نامعتبر است"})
                        return
                }
                if s != state.RealitySNI {
                        state.RealitySNI = s
                        needRestart = true
                }
        }
        if v, ok := d["cfg_fmt"]; ok {
                fmtv := strings.Join(strings.Fields(fmt.Sprintf("%v", v)), " ")
                if len(fmtv) > 100 {
                        stateMu.Unlock()
                        sendJSON(w, 400, map[string]any{"error": "قالب نام کانفیگ حداکثر ۱۰۰ نویسه است"})
                        return
                }
                if fmtv == "" {
                        fmtv = "{name}-{label}"
                }
                state.CfgFmt = fmtv
        }
        if v, ok := d["protocols"]; ok {
                req, ok := v.(map[string]any)
                if !ok {
                        stateMu.Unlock()
                        sendJSON(w, 400, map[string]any{"error": "پروتکل‌ها نامعتبر است"})
                        return
                }
                newp := map[string]bool{}
                anyOn := false
                for _, k := range protoKeys {
                        b, ok := req[k].(bool)
                        newp[k] = ok && b
                        if newp[k] {
                                anyOn = true
                        }
                }
                if !anyOn {
                        stateMu.Unlock()
                        sendJSON(w, 400, map[string]any{"error": "حداقل یک پروتکل باید فعال بماند"})
                        return
                }
                if !mapsEqual(newp, state.Protocols) {
                        state.Protocols = newp
                        needRestart = true
                }
        }
        if _, ok := d["session_hours"]; ok {
                h := jint(d, "session_hours")
                if h < 1 || h > 336 {
                        stateMu.Unlock()
                        sendJSON(w, 400, map[string]any{"error": "نشست باید بین ۱ تا ۳۳۶ ساعت باشد"})
                        return
                }
                state.SessionHours = int(h)
        }
        saveStateLocked()
        stateMu.Unlock()
        if needRestart {
                restartXray()
                refreshProxyRoutes()
        }
        sendJSON(w, 200, map[string]any{"ok": true})
}

func handleIPScan(w http.ResponseWriter, r *http.Request) {
        d := readJSONBody(r)
        raw, _ := d["targets"].([]any)
        var targets []string
        for _, x := range raw {
                if len(targets) >= 80 {
                        break
                }
                if s, ok := x.(string); ok {
                        targets = append(targets, s)
                }
        }
        if len(targets) == 0 {
                sendJSON(w, 400, map[string]any{"error": "هیچ هدفی برای اسکن وارد نشده است"})
                return
        }
        port := int(jint(d, "port"))
        if port == 0 {
                port = 443
        }
        if port < 1 || port > 65535 {
                sendJSON(w, 400, map[string]any{"error": "پورت نامعتبر است"})
                return
        }
        timeoutMs := jint(d, "timeout_ms")
        if timeoutMs < 500 || timeoutMs > 4000 {
                timeoutMs = 2000
        }
        rounds := int(jint(d, "rounds"))
        if rounds < 1 || rounds > 3 {
                rounds = 1
        }
        var clean []string
        var pt []ProbeTarget
        for _, t := range targets {
                if isValidScanTarget(t) {
                        clean = append(clean, t)
                        pt = append(pt, ProbeTarget{IP: t, Port: port, Rounds: rounds})
                }
        }
        if len(clean) > 64 {
                clean = clean[:64]
                pt = pt[:64]
        }
        res := runDeepProbe(pt, int(timeoutMs))
        var results []map[string]any
        for _, x := range res {
                results = append(results, map[string]any{"target": x.Target, "ok": x.OK, "ms": x.TCPMs})
        }
        sendJSON(w, 200, map[string]any{"results": results, "from": "server", "count": len(results)})
}

func handleBunnyEdges(w http.ResponseWriter, r *http.Request) {
        dom := strings.TrimSpace(osGetenv("DOMAIN"))
        if dom == "" {
                dom = requestHost(r)
        }
        if dom == "" || isIPLiteral(dom) || dom == "127.0.0.1" || dom == "localhost" || dom == "::1" {
                sendJSON(w, 400, map[string]any{"error": "دامنه عمومی سرویس پیدا نشد — متغیر DOMAIN را روی دامنه لوسیتی ست کنید"})
                return
        }
        // v3.7 IPv6: ?family=4 (default) | 6 — which bunny edge list to verify.
        fam := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("family")))
        if fam == "" {
                if d := readJSONBody(r); d != nil {
                        if s, ok := d["family"].(string); ok {
                                fam = strings.ToLower(strings.TrimSpace(s))
                        }
                }
        }
        if fam != "6" {
                fam = "4"
        }
        edges, geo, cached := bunnyEdgesFor(dom, fam)
        sendJSONGz(r, w, 200, map[string]any{"ok": true, "domain": dom, "family": fam,
                "edges": edges, "geo": geo,
                "verified": len(edges), "cached": cached})
}

func handleProbe(w http.ResponseWriter, r *http.Request) {
        d := readJSONBody(r)
        raw, _ := d["targets"].([]any)
        var targets []string
        for _, x := range raw {
                if s, ok := x.(string); ok && isValidScanTarget(s) {
                        targets = append(targets, s)
                }
        }
        if len(targets) == 0 {
                sendJSON(w, 400, map[string]any{"error": "هدفی برای بررسی وارد نشده است"})
                return
        }
        port := int(jint(d, "port"))
        if port == 0 {
                port = 443
        }
        if port < 1 || port > 65535 {
                sendJSON(w, 400, map[string]any{"error": "پورت نامعتبر است"})
                return
        }
        sni := jstr(d, "sni")
        var pt []ProbeTarget
        for _, t := range targets {
                if isIPLiteral(t) {
                        pt = append(pt, ProbeTarget{IP: t, Port: port, SNI: sni})
                } else if hostRe.MatchString(t) {
                        ips := resolveHost(t)
                        for _, x := range ips {
                                pt = append(pt, ProbeTarget{IP: x, Port: port, SNI: sni})
                        }
                }
        }
        res := runDeepProbe(pt, 2500)
        sendJSON(w, 200, map[string]any{"results": res, "count": len(res)})
}
