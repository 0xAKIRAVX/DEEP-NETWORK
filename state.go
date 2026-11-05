package main

import (
        "crypto/hmac"
        "crypto/sha256"
        "encoding/hex"
        "encoding/json"
        "os"
        "path/filepath"
        "regexp"
        "sort"
        "strings"
        "sync"
        "time"

        "golang.org/x/crypto/scrypt"
)

// ─────────── persistent state ───────────
// v3.26 keeps the v3.2x client model (clients + UUID + sub-token derivation)
// and replaces the preset admin password with a claimed Profile (wizard).

type Client struct {
        Name      string `json:"name"`
        ID        string `json:"id"`
        Quota     int64  `json:"quota,omitempty"`
        ExpireAt  int64  `json:"expire_at,omitempty"`
        Up        int64  `json:"up,omitempty"`
        Down      int64  `json:"down,omitempty"`
        Note      string `json:"note,omitempty"`
        LastSeen  int64  `json:"last_seen,omitempty"`
        CreatedAt int64  `json:"created_at,omitempty"`
}

// Profile is the owner identity created by the first-run wizard.
type Profile struct {
        First     string `json:"first"`
        Last      string `json:"last"`
        User      string `json:"user"`
        PassSalt  string `json:"pass_salt"`
        PassHash  string `json:"pass_hash"`
        ClaimedAt int64  `json:"claimed_at,omitempty"`
}

func (p *Profile) claimed() bool { return p != nil && p.ClaimedAt > 0 && p.User != "" }

// Ports: the three Reality inbound ports (0 = use preferred default).
type Ports struct {
        Vision int `json:"vision,omitempty"`
        XHTTP  int `json:"xhttp,omitempty"`
        GRPC   int `json:"grpc,omitempty"`
}

// SNIs: Reality dest/serverName per transport.
type SNIs struct {
        Vision string `json:"vision,omitempty"`
        XHTTP  string `json:"xhttp,omitempty"`
        GRPC string `json:"grpc,omitempty"`
}

// DocRes: one transport's doctor (self-test) verdict.
type DocRes struct {
        Name string `json:"name"`
        OK   bool   `json:"ok"`
        MS   int64  `json:"ms,omitempty"`
        Err  string `json:"err,omitempty"`
        At   int64  `json:"at,omitempty"`
}

type TSnap struct {
        D int64 `json:"d"`
        T int64 `json:"t"`
}

type State struct {
        UUID         string   `json:"uuid"`
        Profile      *Profile `json:"profile,omitempty"`
        AdminUser    string   `json:"admin_user,omitempty"` // legacy (pre-3.26) — kept for migration only
        AdminPass    string   `json:"admin_pass,omitempty"` // legacy
        Ports        *Ports   `json:"ports,omitempty"`
        SNIs         *SNIs    `json:"snis,omitempty"`
        SessionHours int      `json:"session_hours"`
        Clients      []*Client `json:"clients"`
        TSnaps       []TSnap  `json:"tsnaps,omitempty"`
        Doctor       []DocRes `json:"doctor,omitempty"`
        DoctorAt     int64    `json:"doctor_at,omitempty"`
        LastHost     string   `json:"last_host,omitempty"`
        SysctlOK     bool     `json:"sysctl_ok,omitempty"`
        Migrated     string   `json:"migrated_from,omitempty"`
}

var (
        stateMu sync.RWMutex
        state   *State

        sessionsMu sync.Mutex
        sessions   = map[string]time.Time{}
        loginFails = map[string][]time.Time{}
)

const defaultSessionHours = 24
const loginFailWindow = 10 * time.Minute

// preferred ports + fallback ladder (legacy stack may hold some of them)
var portLadder = []int{8443, 2053, 2087, 2095, 8880, 2082, 2086, 2052, 8444, 9443, 2054, 2055}

const (
        prefVision = 8443
        prefXHTTP  = 2053
        prefGRPC   = 2087
)

var defaultSNIs = SNIs{
        Vision: "www.microsoft.com",
        XHTTP:  "www.cloudflare.com",
        GRPC:   "www.bing.com",
}

func statePath() string {
        d := os.Getenv("DATA_DIR")
        if d == "" {
                d = "/opt/deep-network"
        }
        if d == "" {
                d = "."
        }
        if err := os.MkdirAll(d, 0o755); err != nil {
                d = "/tmp"
        }
        probe := filepath.Join(d, ".t")
        if f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY, 0o644); err != nil {
                d = "/tmp"
        } else {
                f.Close()
                os.Remove(probe)
        }
        return filepath.Join(d, "state.json")
}

func dataDir() string { return filepath.Dir(statePath()) }

func saveState() {
        stateMu.Lock()
        defer stateMu.Unlock()
        saveStateLocked()
}

func saveStateLocked() {
        b, _ := json.Marshal(state)
        tmp := statePath() + ".tmp"
        if err := os.WriteFile(tmp, b, 0o600); err == nil {
                os.Rename(tmp, statePath())
        }
}

func envStr(name, def string) string {
        if v := os.Getenv(name); v != "" {
                return v
        }
        return def
}

func envInt(name string, def int) int {
        if v := os.Getenv(name); v != "" {
                var n int
                if _, err := fmtSscan(v, &n); err == nil {
                        return n
                }
        }
        return def
}

func uuidv4() string {
        b := make([]byte, 16)
        randRead(b)
        b[6] = (b[6] & 0x0f) | 0x40
        b[8] = (b[8] & 0x3f) | 0x80
        return hex.EncodeToString(b[0:4]) + "-" + hex.EncodeToString(b[4:6]) + "-" + hex.EncodeToString(b[6:8]) + "-" + hex.EncodeToString(b[8:10]) + "-" + hex.EncodeToString(b[10:16])
}

func randHex(n int) string {
        b := make([]byte, n)
        randRead(b)
        return hex.EncodeToString(b)
}

// subToken derives the stable per-user subscription token from SECRET
// (same derivation as v3.2x — old sub URLs keep working across the upgrade).
func subToken(cid string) string {
        mac := hmac.New(sha256.New, []byte(secret()))
        mac.Write([]byte("sub:" + cid))
        return hex.EncodeToString(mac.Sum(nil))[:32]
}

func secret() string {
        if s := os.Getenv("SECRET"); s != "" {
                return s
        }
        return mainUUID()
}

func mainUUID() string {
        if s := os.Getenv("UUID"); s != "" {
                return s
        }
        stateMu.RLock()
        defer stateMu.RUnlock()
        if state != nil && state.UUID != "" {
                return state.UUID
        }
        return ""
}

// ─────────── password hashing (scrypt) ───────────

func hashPass(pass, salt string) string {
        h, err := scrypt.Key([]byte(pass), []byte(salt), 16384, 8, 1, 32)
        if err != nil {
                // cannot happen with valid params, but never store raw
                sum := sha256.Sum256([]byte(salt + ":" + pass))
                return hex.EncodeToString(sum[:])
        }
        return hex.EncodeToString(h)
}

func profileClaimed() bool {
        stateMu.RLock()
        defer stateMu.RUnlock()
        return state != nil && state.Profile != nil && state.Profile.claimed()
}

func resetProfile() {
        stateMu.Lock()
        state.Profile = nil
        state.AdminUser, state.AdminPass = "", ""
        saveStateLocked()
        stateMu.Unlock()
        dropAllSessions("")
}

func clientStatus(c *Client, now time.Time) string {
        if c.ExpireAt != 0 && now.Unix() >= c.ExpireAt {
                return "expired"
        }
        if c.Quota != 0 && c.Up+c.Down >= c.Quota {
                return "quota"
        }
        return "active"
}

func activeClientsLocked() []*Client {
        now := time.Now()
        var out []*Client
        for _, c := range state.Clients {
                if clientStatus(c, now) == "active" {
                        out = append(out, c)
                }
        }
        return out
}

func sessionTTL() time.Duration {
        stateMu.RLock()
        h := state.SessionHours
        stateMu.RUnlock()
        if h < 1 {
                h = defaultSessionHours
        }
        if h > 336 {
                h = 336
        }
        return time.Duration(h) * time.Hour
}

func pruneSessions() {
        now := time.Now()
        sessionsMu.Lock()
        defer sessionsMu.Unlock()
        for t, exp := range sessions {
                if !exp.After(now) {
                        delete(sessions, t)
                }
        }
        for ip, times := range loginFails {
                var recent []time.Time
                for _, x := range times {
                        if now.Sub(x) < loginFailWindow {
                                recent = append(recent, x)
                        }
                }
                if len(recent) > 0 {
                        loginFails[ip] = recent
                } else {
                        delete(loginFails, ip)
                }
        }
}

// ─────────── load + v3.25 migration ───────────

// legacyState mirrors the v3.2x schema — only the fields we carry forward.
type legacyState struct {
        UUID         string          `json:"uuid"`
        AdminUser    string          `json:"admin_user"`
        AdminPass    string          `json:"admin_pass"`
        SessionHours int             `json:"session_hours"`
        Clients      []*Client       `json:"clients"`
        RealitySNI   string          `json:"reality_sni"`
        Raw          json.RawMessage `json:"-"`
}

func loadState() {
        p := statePath()
        st := &State{}
        raw, err := os.ReadFile(p)
        if err == nil && len(raw) > 2 {
                var probe map[string]json.RawMessage
                if json.Unmarshal(raw, &probe) == nil {
                        if _, hasProfile := probe["profile"]; hasProfile {
                                // v3.26 native state
                                if json.Unmarshal(raw, st) == nil && st.UUID != "" && st.Profile != nil && st.Profile.claimed() {
                                        finishLoad(st, "")
                                        return
                                }
                        }
                        // v3.2x state → migrate (backup once)
                        var lg legacyState
                        if json.Unmarshal(raw, &lg) == nil {
                                os.WriteFile(p+".v325bak", raw, 0o600)
                                st = migrateLegacy(&lg, probe)
                                finishLoad(st, "v3.2x")
                                return
                        }
                }
                // unknown shape → back up, start fresh
                os.WriteFile(p+".unknown.bak", raw, 0o600)
        }

        // fresh state
        st.UUID = envStr("UUID", uuidv4())
        if envStr("UUID", "") != "" {
                st.UUID = envStr("UUID", "")
        }
        st.Profile = nil // unclaimed → setup wizard
        finishLoad(st, "")
}

func migrateLegacy(lg *legacyState, probe map[string]json.RawMessage) *State {
        st := &State{
                UUID:         lg.UUID,
                SessionHours: lg.SessionHours,
                Clients:      lg.Clients,
                Migrated:     "v3.2x",
        }
        if st.UUID == "" {
                st.UUID = envStr("UUID", uuidv4())
        }
        if envStr("UUID", "") != "" {
                st.UUID = envStr("UUID", "")
        }
        // keep client list healthy
        var clients []*Client
        for _, c := range st.Clients {
                if c.ID != "" && c.Name != "" {
                        if c.CreatedAt == 0 {
                                c.CreatedAt = time.Now().Unix()
                        }
                        clients = append(clients, c)
                }
        }
        st.Clients = clients
        // main user always present
        main := st.UUID
        hasMain := false
        for _, c := range st.Clients {
                if c.ID == main {
                        hasMain = true
                }
        }
        if !hasMain {
                st.Clients = append([]*Client{{Name: "main", ID: main, CreatedAt: time.Now().Unix()}}, st.Clients...)
        }
        // carry the old reality SNI into the Vision slot when it was customised
        if lg.RealitySNI != "" && lg.RealitySNI != "www.microsoft.com" {
                if st.SNIs == nil {
                        st.SNIs = &SNIs{}
                }
                st.SNIs.Vision = lg.RealitySNI
        }
        _ = probe
        // admin account is NOT carried: the wizard (first visit) creates the new
        // owner identity — exactly the flow the user asked for.
        return st
}

func finishLoad(st *State, from string) {
        if st.SessionHours < 1 {
                st.SessionHours = defaultSessionHours
        }
        if st.Ports == nil {
                st.Ports = &Ports{}
        }
        if st.SNIs == nil {
                st.SNIs = &SNIs{}
        }
        if st.Ports.Vision == 0 {
                st.Ports.Vision = prefVision
        }
        if st.Ports.XHTTP == 0 {
                st.Ports.XHTTP = prefXHTTP
        }
        if st.Ports.GRPC == 0 {
                st.Ports.GRPC = prefGRPC
        }
        if st.SNIs.Vision == "" {
                st.SNIs.Vision = defaultSNIs.Vision
        }
        if st.SNIs.XHTTP == "" {
                st.SNIs.XHTTP = defaultSNIs.XHTTP
        }
        if st.SNIs.GRPC == "" {
                st.SNIs.GRPC = defaultSNIs.GRPC
        }
        // the main client (owner UUID) always exists — its sub link is the one
        // --banner prints and the default subscription for the owner.
        main := mainIDFromState(st)
        hasMain := false
        var clients []*Client
        for _, c := range st.Clients {
                if c.ID != "" && c.Name != "" {
                        if c.CreatedAt == 0 {
                                c.CreatedAt = time.Now().Unix()
                        }
                        clients = append(clients, c)
                        if c.ID == main {
                                hasMain = true
                        }
                }
        }
        if !hasMain {
                clients = append([]*Client{{Name: "main", ID: main, CreatedAt: time.Now().Unix()}}, clients...)
        }
        st.Clients = clients
        // tsnaps cap
        if len(st.TSnaps) > 720 {
                st.TSnaps = st.TSnaps[len(st.TSnaps)-720:]
        }
        state = st
        saveStateLocked()
        _ = from
}

func mainIDFromState(st *State) string {
        if s := os.Getenv("UUID"); s != "" {
                return s
        }
        if st.UUID != "" {
                return st.UUID
        }
        return uuidv4()
}

// effectivePorts resolves the three inbound ports, probing for occupancy and
// walking the fallback ladder so the legacy stack's ports are never touched.
type effPorts struct{ Vision, XHTTP, GRPC int }
type effSNIs struct{ Vision, XHTTP, GRPC string }

var (
        effMu    sync.Mutex
        effCache *effPorts
        effWhen  time.Time
)

func portFree(p int) bool {
        if p <= 0 || p > 65535 {
                return false
        }
        if l, err := listenTCP("0.0.0.0:" + itoa(p)); err == nil {
                l.Close()
                return true
        }
        return false
}

func pickPort(preferred int, taken map[int]bool) int {
        if preferred > 0 && !taken[preferred] && portFree(preferred) {
                taken[preferred] = true
                return preferred
        }
        for _, p := range portLadder {
                if !taken[p] && portFree(p) {
                        taken[p] = true
                        return p
                }
        }
        taken[preferred] = true
        return preferred // last resort — xray will report the bind error
}

func effectivePorts() effPorts {
        effMu.Lock()
        defer effMu.Unlock()
        if effCache != nil && time.Since(effWhen) < 10*time.Minute {
                return *effCache
        }
        stateMu.RLock()
        wanted := *state.Ports
        stateMu.RUnlock()
        // the panel HTTP port is never a candidate
        taken := map[int]bool{envInt("PORT", 80): true, apiPort: true}
        out := effPorts{}
        out.Vision = pickPort(wanted.Vision, taken)
        out.XHTTP = pickPort(wanted.XHTTP, taken)
        out.GRPC = pickPort(wanted.GRPC, taken)
        // persist what actually bound so links stay stable across reboots when free
        stateMu.Lock()
        if state.Ports.Vision != out.Vision || state.Ports.XHTTP != out.XHTTP || state.Ports.GRPC != out.GRPC {
                state.Ports.Vision, state.Ports.XHTTP, state.Ports.GRPC = out.Vision, out.XHTTP, out.GRPC
                saveStateLocked()
        }
        stateMu.Unlock()
        effCache = &out
        effWhen = time.Now()
        return out
}

func effectiveSNIs() effSNIs {
        stateMu.RLock()
        defer stateMu.RUnlock()
        s := *state.SNIs
        if s.Vision == "" {
                s.Vision = defaultSNIs.Vision
        }
        if s.XHTTP == "" {
                s.XHTTP = defaultSNIs.XHTTP
        }
        if s.GRPC == "" {
                s.GRPC = defaultSNIs.GRPC
        }
        return effSNIs(s)
}

// ─────────── misc small helpers shared by views ───────────

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

var userRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]{2,32}$`)

func validUsername(u string) bool { return userRe.MatchString(u) }

func sortedClients() []*Client {
        stateMu.RLock()
        out := append([]*Client(nil), state.Clients...)
        stateMu.RUnlock()
        sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
        return out
}

type subEntry struct{ name, token string }

func subList() []subEntry {
        var out []subEntry
        for _, c := range sortedClients() {
                out = append(out, subEntry{name: c.Name, token: subToken(c.ID)})
        }
        return out
}

func firstN(s string, n int) string {
        r := []rune(strings.TrimSpace(s))
        if len(r) <= n {
                return string(r)
        }
        return string(r[:n])
}
