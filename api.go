package main

import (
        "encoding/base64"
        "encoding/json"
        "fmt"
        "io"
        "net/http"
        "os"
        "regexp"
        "strconv"
        "strings"
        "time"
)

// ─────────── /panel/api/* ───────────

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
        b, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
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

func strList(v any) []string {
        if arr, ok := v.([]any); ok {
                var out []string
                for _, x := range arr {
                        if s, ok := x.(string); ok {
                                out = append(out, s)
                        }
                }
                return out
        }
        return nil
}

// ─────────── auth ───────────

func apiAuth(w http.ResponseWriter, r *http.Request) bool {
        if _, ok := authSession(r); ok {
                return true
        }
        sendJSON(w, 401, map[string]any{"error": "unauthorized"})
        return false
}

// handleSetup — the first-run wizard claim: name, surname, photo, username,
// password. Only works while the panel is unclaimed; the claimer becomes owner.
func handleSetup(w http.ResponseWriter, r *http.Request) {
        if profileClaimed() {
                sendJSON(w, 409, map[string]any{"error": "حساب مدیر از قبل ساخته شده است — وارد شوید"})
                return
        }
        ip := clientIP(r)
        if !loginAllowed(ip) {
                sendJSON(w, 429, map[string]any{"error": "تلاش‌های ناموفق زیاد — چند دقیقه بعد دوباره امتحان کنید"})
                return
        }
        d := readJSONBody(r)
        first := trunc(strings.TrimSpace(jstr(d, "first")), 40)
        last := trunc(strings.TrimSpace(jstr(d, "last")), 40)
        user := strings.TrimSpace(jstr(d, "user"))
        pass := jstr(d, "pass")
        avatarB64 := jstr(d, "avatar")

        if first == "" || last == "" {
                sendJSON(w, 400, map[string]any{"error": "نام و نام خانوادگی را وارد کنید"})
                return
        }
        if !validUsername(user) {
                sendJSON(w, 400, map[string]any{"error": "نام کاربری باید ۲ تا ۳۲ حرف انگلیسی/عدد باشد"})
                return
        }
        if len(pass) < 8 {
                sendJSON(w, 400, map[string]any{"error": "رمز عبور باید حداقل ۸ کاراکتر باشد"})
                return
        }

        // photo (optional at this step — can be changed later in settings)
        if avatarB64 != "" {
                if i := strings.Index(avatarB64, ";base64,"); i >= 0 {
                        avatarB64 = avatarB64[i+8:]
                }
                if data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(avatarB64)); err == nil && len(data) > 0 && len(data) <= 8<<20 {
                        storeAvatarBytes(data)
                }
        }

        salt := randHex(16)
        prof := &Profile{
                First: first, Last: last, User: user,
                PassSalt: salt, PassHash: hashPass(pass, salt),
                ClaimedAt: time.Now().Unix(),
        }
        stateMu.Lock()
        state.Profile = prof
        state.AdminUser, state.AdminPass = "", ""
        saveStateLocked()
        stateMu.Unlock()

        sid := newSession()
        setSessionCookie(w, r, sid, int(sessionTTL().Seconds()))
        logf("owner claimed the panel: %s %s (@%s)", first, last, user)
        sendJSON(w, 200, map[string]any{"ok": true, "user": user})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
        ip := clientIP(r)
        if !loginAllowed(ip) {
                sendJSON(w, 429, map[string]any{"error": "تلاش‌های ناموفق زیاد — چند دقیقه بعد دوباره امتحان کنید"})
                return
        }
        d := readJSONBody(r)
        user, pass := jstr(d, "user"), jstr(d, "pass")
        stateMu.RLock()
        prof := state.Profile
        stateMu.RUnlock()
        if prof == nil || !prof.claimed() {
                recordLoginFail(ip)
                time.Sleep(500 * time.Millisecond)
                sendJSON(w, 401, map[string]any{"error": "حسابی ساخته نشده است — اول ثبت نام کن", "setup": true})
                return
        }
        if user != prof.User || hashPass(pass, prof.PassSalt) != prof.PassHash {
                recordLoginFail(ip)
                time.Sleep(700 * time.Millisecond)
                sendJSON(w, 401, map[string]any{"error": "نام کاربری یا رمز عبور اشتباه است"})
                return
        }
        sid := newSession()
        setSessionCookie(w, r, sid, int(sessionTTL().Seconds()))
        sendJSON(w, 200, map[string]any{"ok": true, "user": user})
}

// ─────────── payloads ───────────

func statePayload(r *http.Request) map[string]any {
        host := requestHost(r)
        scheme := "http"
        if v := strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]; strings.TrimSpace(v) == "https" {
                scheme = "https"
        }
        if r.TLS != nil {
                scheme = "https"
        }
        stateMu.RLock()
        clients := append([]*Client(nil), state.Clients...)
        prof := state.Profile
        ports := *state.Ports
        snis := *state.SNIs
        doctor := append([]DocRes(nil), state.Doctor...)
        doctorAt := state.DoctorAt
        sessionHours := state.SessionHours
        migrated := state.Migrated
        stateMu.RUnlock()

        settings := map[string]any{
                "setup_required": !profileClaimed(),
                "server":         host,
                "session_hours":  sessionHours,
                "ports":          map[string]int{"vision": ports.Vision, "xhttp": ports.XHTTP, "grpc": ports.GRPC},
                "snis":           map[string]string{"vision": snis.Vision, "xhttp": snis.XHTTP, "grpc": snis.GRPC},
                "doctor":         doctor,
                "doctor_at":      doctorAt,
                "migrated_from":  migrated,
                "sysctl_ok":      stateSysctlOK(),
        }
        if prof != nil && prof.claimed() {
                settings["user"] = prof.User
                settings["first"] = prof.First
                settings["last"] = prof.Last
        }

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
                        "status":  clientStatus(c, now), "days_left": days, "note": c.Note,
                        "online":  userOnlineNow(c.ID), "last_seen": c.LastSeen,
                        "online_dur": onlineDurFor(c.ID),
                        "created_at": c.CreatedAt,
                })
        }

        return map[string]any{
                "version": Version, "clients": out, "settings": settings,
                "geo": serverGeoPayload(),
        }
}

func stateSysctlOK() bool {
        stateMu.RLock()
        defer stateMu.RUnlock()
        return state.SysctlOK
}

// ─────────── dispatcher ───────────

func handleAPI(w http.ResponseWriter, r *http.Request, path string) {
        rememberHost(r)
        switch r.Method {
        case http.MethodGet, http.MethodHead:
                // public: tells the frontend (before any session) whether the
                // first-run wizard or the login page should show.
                if path == "/panel/api/mode" {
                        sendJSON(w, 200, map[string]any{
                                "setup_required": !profileClaimed(),
                                "version":        Version,
                        })
                        return
                }
                if path == "/panel/api/speedblob" {
                        sendBytes(w, 200, make([]byte, 1<<20), "application/octet-stream", nil)
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
                        sendJSONGz(r, w, 200, onlinePayload())
                case path == "/panel/api/whoami":
                        handleWhoami(w, r)
                case path == "/panel/api/server-config":
                        b, _ := json.MarshalIndent(buildXrayConfig(), "", "  ")
                        sendBytes(w, 200, b, "application/json; charset=utf-8", map[string]string{
                                "Content-Disposition": "attachment; filename=xray-server.json"})
                case path == "/panel/api/backup":
                        handleBackup(w)
                case path == "/panel/api/doctor":
                        sendJSONGz(r, w, 200, map[string]any{"results": doctorResults(), "at": doctorAt()})
                case path == "/panel/api/rahnama":
                        sendBytes(w, 200, []byte(rahnamaText()), "text/plain; charset=utf-8", map[string]string{
                                "Content-Disposition": "attachment; filename=RAHNAMA.txt"})
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
                if path == "/panel/api/setup" {
                        handleSetup(w, r)
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
                case "/panel/api/settings":
                        handleSettings(w, r)
                case "/panel/api/profile":
                        handleProfileUpdate(w, r)
                case "/panel/api/avatar":
                        handleAvatarUpload(w, r)
                case "/panel/api/avatar/delete":
                        handleAvatarDelete(w, r)
                case "/panel/api/restart":
                        restartXray()
                        sendJSON(w, 200, map[string]any{"ok": true})
                case "/panel/api/doctor":
                        go doctorRun()
                        sendJSON(w, 200, map[string]any{"started": true})
                default:
                        sendJSON(w, 404, map[string]any{"error": "not found"})
                }
        default:
                sendJSON(w, 404, map[string]any{"error": "not found"})
        }
}

func doctorResults() []DocRes {
        stateMu.RLock()
        defer stateMu.RUnlock()
        return append([]DocRes(nil), state.Doctor...)
}

func doctorAt() int64 {
        stateMu.RLock()
        defer stateMu.RUnlock()
        return state.DoctorAt
}

// rememberHost stores the last Host header (public-IP fallback for --banner).
var hostRe = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

func rememberHost(r *http.Request) {
        h := requestHost(r)
        if h == "" || isIPLiteralStr(h) || !hostRe.MatchString(h) {
                return
        }
        stateMu.Lock()
        changed := state.LastHost != h
        state.LastHost = h
        if changed {
                saveStateLocked()
        }
        stateMu.Unlock()
}

func isIPLiteralStr(s string) bool {
        return strings.Contains(s, ":") || ipIsLiteral(s)
}

func ipIsLiteral(s string) bool {
        for _, c := range s {
                if (c < '0' || c > '9') && c != '.' {
                        return false
                }
        }
        return strings.Contains(s, ".")
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
        cfg := clientConfigJSON(c, requestHost(r))
        b, _ := json.MarshalIndent(cfg, "", "  ")
        sendBytes(w, 200, b, "application/json; charset=utf-8", map[string]string{
                "Content-Disposition": "attachment; filename=deepnetwork-" + sanitizeName(c.Name) + ".json"})
}

func handleBackup(w http.ResponseWriter) {
        stateMu.RLock()
        snap := map[string]any{
                "dn_backup": 4, "version": Version, "exported": time.Now().Unix(),
                "state": map[string]any{
                        "uuid":          state.UUID,
                        "profile":       state.Profile,
                        "ports":         state.Ports,
                        "snis":          state.SNIs,
                        "session_hours": state.SessionHours,
                        "clients":       append([]*Client(nil), state.Clients...),
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
        var expire int64
        if days > 0 {
                expire = time.Now().AddDate(0, 0, int(days)).Unix()
        }
        c := &Client{Name: name, ID: id, Quota: quota, ExpireAt: expire, Note: trunc(jstr(d, "note"), 200), CreatedAt: time.Now().Unix()}
        stateMu.Lock()
        state.Clients = append(state.Clients, c)
        saveStateLocked()
        stateMu.Unlock()
        go syncXray()
        sendJSON(w, 200, map[string]any{"ok": true, "id": id, "name": name})
}

func handleClientEdit(w http.ResponseWriter, r *http.Request) {
        d := readJSONBody(r)
        id := jstr(d, "id")
        stateMu.Lock()
        defer stateMu.Unlock()
        for _, c := range state.Clients {
                if c.ID == id {
                        if v, ok := d["name"]; ok {
                                if s := trunc(strings.TrimSpace(v.(string)), 30); s != "" {
                                        c.Name = s
                                }
                        }
                        if v, ok := d["note"]; ok {
                                c.Note = trunc(v.(string), 200)
                        }
                        if v, ok := d["quota"]; ok {
                                q := int64(0)
                                switch x := v.(type) {
                                case float64:
                                        q = int64(x)
                                }
                                if q < 0 || q > 1<<40 {
                                        sendJSON(w, 400, map[string]any{"error": "حجم نامعتبر است"})
                                        return
                                }
                                c.Quota = q
                        }
                        if v, ok := d["days"]; ok {
                                dy := int64(0)
                                switch x := v.(type) {
                                case float64:
                                        dy = int64(x)
                                }
                                if dy < 0 || dy > 3650 {
                                        sendJSON(w, 400, map[string]any{"error": "روز نامعتبر است"})
                                        return
                                }
                                if dy == 0 {
                                        c.ExpireAt = 0
                                } else {
                                        base := time.Now().Unix()
                                        if c.ExpireAt > base {
                                                base = c.ExpireAt
                                        }
                                        c.ExpireAt = base + dy*86400
                                }
                        }
                        if v, ok := d["reset_traffic"]; ok && v == true {
                                c.Up, c.Down = 0, 0
                        }
                        saveStateLocked()
                        sendJSON(w, 200, map[string]any{"ok": true})
                        return
                }
        }
        sendJSON(w, 404, map[string]any{"error": "کاربر پیدا نشد"})
}

func handleClientDelete(w http.ResponseWriter, r *http.Request) {
        d := readJSONBody(r)
        id := jstr(d, "id")
        if id == mainUUID() {
                sendJSON(w, 400, map[string]any{"error": "کاربر اصلی قابل حذف نیست"})
                return
        }
        stateMu.Lock()
        var out []*Client
        for _, c := range state.Clients {
                if c.ID != id {
                        out = append(out, c)
                }
        }
        state.Clients = out
        saveStateLocked()
        stateMu.Unlock()
        go syncXray()
        sendJSON(w, 200, map[string]any{"ok": true})
}

func handleClientRegen(w http.ResponseWriter, r *http.Request) {
        d := readJSONBody(r)
        id := jstr(d, "id")
        if id == mainUUID() {
                sendJSON(w, 400, map[string]any{"error": "شناسه کاربر اصلی قابل تغییر نیست"})
                return
        }
        nid := uuidv4()
        stateMu.Lock()
        for _, c := range state.Clients {
                if c.ID == id {
                        c.ID = nid
                }
        }
        saveStateLocked()
        stateMu.Unlock()
        go syncXray()
        sendJSON(w, 200, map[string]any{"ok": true, "id": nid})
}

// handleSettings: Reality SNIs (advanced) + session hours.
func handleSettings(w http.ResponseWriter, r *http.Request) {
        d := readJSONBody(r)
        stateMu.Lock()
        if v, ok := d["sni_vision"]; ok {
                if s := cleanSNI(v.(string)); s != "" {
                        state.SNIs.Vision = s
                }
        }
        if v, ok := d["sni_xhttp"]; ok {
                if s := cleanSNI(v.(string)); s != "" {
                        state.SNIs.XHTTP = s
                }
        }
        if v, ok := d["sni_grpc"]; ok {
                if s := cleanSNI(v.(string)); s != "" {
                        state.SNIs.GRPC = s
                }
        }
        if v, ok := d["session_hours"]; ok {
                if f, ok := v.(float64); ok {
                        h := int(f)
                        if h >= 1 && h <= 336 {
                                state.SessionHours = h
                        }
                }
        }
        saveStateLocked()
        stateMu.Unlock()
        // ports may need re-resolution (SNIs changed → xray restart needed)
        go func() {
                restartXray()
        }()
        sendJSON(w, 200, map[string]any{"ok": true})
}

var sniRe = regexp.MustCompile(`^[a-zA-Z0-9._-]{3,253}$`)

func cleanSNI(s string) string {
        s = strings.ToLower(strings.TrimSpace(s))
        if !sniRe.MatchString(s) || !strings.Contains(s, ".") {
                return ""
        }
        return s
}

// handleProfileUpdate: name / surname / username / password change.
func handleProfileUpdate(w http.ResponseWriter, r *http.Request) {
        d := readJSONBody(r)
        stateMu.RLock()
        prof := state.Profile
        stateMu.RUnlock()
        if prof == nil || !prof.claimed() {
                sendJSON(w, 409, map[string]any{"error": "حسابی ساخته نشده است"})
                return
        }
        curPass := jstr(d, "current_pass")
        newPass := jstr(d, "pass")

        stateMu.Lock()
        if v, ok := d["first"]; ok {
                if s := trunc(strings.TrimSpace(v.(string)), 40); s != "" {
                        state.Profile.First = s
                }
        }
        if v, ok := d["last"]; ok {
                if s := trunc(strings.TrimSpace(v.(string)), 40); s != "" {
                        state.Profile.Last = s
                }
        }
        if v, ok := d["user"]; ok {
                if s := strings.TrimSpace(v.(string)); s != "" {
                        if !validUsername(s) {
                                stateMu.Unlock()
                                sendJSON(w, 400, map[string]any{"error": "نام کاربری نامعتبر است"})
                                return
                        }
                        state.Profile.User = s
                }
        }
        if newPass != "" {
                if len(newPass) < 8 {
                        stateMu.Unlock()
                        sendJSON(w, 400, map[string]any{"error": "رمز جدید باید حداقل ۸ کاراکتر باشد"})
                        return
                }
                if hashPass(curPass, state.Profile.PassSalt) != state.Profile.PassHash {
                        stateMu.Unlock()
                        recordLoginFail(clientIP(r))
                        sendJSON(w, 403, map[string]any{"error": "رمز فعلی اشتباه است"})
                        return
                }
                salt := randHex(16)
                state.Profile.PassSalt = salt
                state.Profile.PassHash = hashPass(newPass, salt)
        }
        saveStateLocked()
        stateMu.Unlock()
        sendJSON(w, 200, map[string]any{"ok": true})
}

func storeAvatarBytes(data []byte) bool {
        return processAndStoreAvatar(data)
}

var _ = fmt.Sprintf
var _ = strconv.Itoa
var _ = os.Getenv
