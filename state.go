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
)

// ─────────── persistent state (schema-compatible with the Python v2.9 state.json) ───────────

type Client struct {
        Name      string   `json:"name"`
        ID        string   `json:"id"`
        Quota     int64    `json:"quota,omitempty"`
        ExpireAt  int64    `json:"expire_at,omitempty"`
        Up        int64    `json:"up,omitempty"`
        Down      int64    `json:"down,omitempty"`
        Note      string   `json:"note,omitempty"`
        Protocols []string `json:"protocols,omitempty"`
        // v3.10: unix time of the user's last tunnel traffic (online monitor).
        LastSeen int64 `json:"last_seen,omitempty"`
}

type Inbound struct {
        Tag      string `json:"tag"`
        Name     string `json:"name"`
        Protocol string `json:"protocol"`
        Network  string `json:"network"`
        Security string `json:"security"`
        Port     int    `json:"port,omitempty"`
        LPort    int    `json:"lport,omitempty"`
        SNI      string `json:"sni,omitempty"`
        Path     string `json:"path,omitempty"`
}

type TSnap struct {
        D int64 `json:"d"`
        T int64 `json:"t"`
}

// EdgeScore (v3.9): one graded CDN edge with both-end metrics — browser-side
// RTT/jitter/loss plus server-side edge→origin handshake & throughput.
type EdgeScore struct {
        IP        string  `json:"ip"`
        Med       float64 `json:"med"`       // browser median RTT (ms)
        Jit       float64 `json:"jit"`       // jitter (ms)
        Loss      float64 `json:"loss"`      // packet loss %
        OriginMs  float64 `json:"origin_ms"` // edge→origin handshake (ms)
        SpeedKbps float64 `json:"kbps"`      // edge→origin throughput (KB/s)
        Score     float64 `json:"score"`     // total path estimate (lower=better)
        CC        string  `json:"cc,omitempty"`
        City      string  `json:"city,omitempty"`
        TS        int64   `json:"ts,omitempty"`
        IROk      int     `json:"ir_ok,omitempty"`   // v3.15: reachable from Iranian probe nodes (count)
        IRAt      int64   `json:"ir_at,omitempty"`   // v3.18: IROk now carries the TLS-level verdict
        IRTLS     int     `json:"ir_tls,omitempty"` // v3.18.1 verdict: 1 = TLS ok from ≥1 IR node, 0 = dead from all, -1 = probe unavailable (legacy 2 = dead)
        IRTLSAt   int64   `json:"ir_tls_at,omitempty"`
}

// DocRes is one transport's doctor (self-test) verdict — a REAL end-to-end
// tunnel probe through the CDN edge with the exact link parameters users get.
type DocRes struct {
        OK   bool   `json:"ok"`
        MS   int64  `json:"ms,omitempty"`
        Err  string `json:"err,omitempty"`
        Edge string `json:"edge,omitempty"` // edge IP the probe rode
}

type Tuning struct {
        Enabled      bool   `json:"enabled"`
        Profile      string `json:"profile"`
        FP           string `json:"fp"`
        CipherSuites string `json:"cipher_suites"`
        ALPN         string `json:"alpn"`
        FragOn       bool   `json:"frag_on"`
        FragPackets  string `json:"frag_packets"`
        FragLengths  string `json:"frag_lengths"`
        FragDelays   string `json:"frag_delays"`
        FragMaxsplit string `json:"frag_maxsplit"`
        NoiseOn      bool   `json:"noise_on"`
        NoiseRand    string `json:"noise_rand"`
        NoiseDelay   string `json:"noise_delay"`
        // Speed pack (v3.7): MuxOff=true disables connection multiplexing in the
        // exported client JSON configs. Default false = mux ON (faster on Iranian
        // mobile networks: one handshake per tunnel instead of one per request).
        MuxOff bool `json:"mux_off"`
}

type State struct {
        UUID         string          `json:"uuid"`
        AdminUser    string          `json:"admin_user"`
        AdminPass    string          `json:"admin_pass"`
        Address      string          `json:"address"`
        RealitySNI   string          `json:"reality_sni"`
        CfgFmt       string          `json:"cfg_fmt"`
        Protocols    map[string]bool `json:"protocols"`
        SessionHours int             `json:"session_hours"`
        SNIOverride  string          `json:"sni_override"`
        PassIsAuto   bool            `json:"pass_is_auto"`
        RandomSNI    bool            `json:"random_sni"`
        // All-operator optimization (v3.9): graded edge set + subscription expansion.
        TopEdges  []*EdgeScore `json:"top_edges,omitempty"`
        MultiEdge bool         `json:"multi_edge,omitempty"`
        // v3.19: edge IPs the ADMIN reported as dead for their own ISP ("-1") —
        // never shipped in any subscription and never re-added by the scanner.
        // The probe nodes cannot see every Iranian ISP; this is the user's ground
        // truth override.
        EdgeBlock []string `json:"edge_block,omitempty"`
        // National-internet kit (v3.11): survival variants (relay/direct).
        LocalMode *LocalModeState `json:"local_mode,omitempty"`
        // Auto edge scanner (v3.14): the panel scans & applies best edges.
        AutoScan   bool   `json:"auto_scan,omitempty"`
        AutoScanAt int64  `json:"auto_scan_at,omitempty"`
        AutoAddr   bool   `json:"auto_addr,omitempty"` // Address was set by auto-scan
        LastHost   string `json:"last_host,omitempty"` // last seen public Host header
        // v3.15: scan cadence in hours (default 1), SNI front, doctor, Iran probe.
        AutoScanHours int    `json:"auto_scan_hours,omitempty"` // 0 → 1h
        FrontSNI      string `json:"front_sni,omitempty"`       // active front base domain ("" = off)
        FrontRand     bool   `json:"front_rand,omitempty"`      // front cert is a wildcard → random label
        FrontAt       int64  `json:"front_at,omitempty"`        // last successful front probe
        FrontMode     string `json:"front_mode,omitempty"`       // "" = auto, "off", or custom domain
        Doctor        map[string]DocRes `json:"doctor,omitempty"` // per-transport E2E health
        DoctorAt      int64  `json:"doctor_at,omitempty"`
        DomainIR      int    `json:"domain_ir,omitempty"`       // 0 unknown, 1 reachable, 2 poisoned/blocked
        DomainIRAt    int64  `json:"domain_ir_at,omitempty"`
        FrontIR       int    `json:"front_ir,omitempty"`        // v3.16: SNI front from Iran — 0 unknown, 1 passes, 2 blocked
        FrontIRAt     int64  `json:"front_ir_at,omitempty"`
        FrontPicks    []FrontPick `json:"front_picks,omitempty"`     // v3.17: proven front candidates + IR verdicts (🎭 variants)
        FrontPicksAt  int64  `json:"front_picks_at,omitempty"`      // when the picks were last evaluated
        // Telegram bot / Mini App (v3.4)
        TGToken      string     `json:"tg_token,omitempty"`
        TGAdminID    string     `json:"tg_admin_id,omitempty"`
        TGBotUser    string     `json:"tg_bot_user,omitempty"`
        TGBotName    string     `json:"tg_bot_name,omitempty"`
        TGHookSecret string     `json:"tg_hook_secret,omitempty"`
        Tuning       *Tuning    `json:"tuning"`
        TuningV      int        `json:"tuning_v,omitempty"`
        Clients      []*Client  `json:"clients"`
        Inbounds     []*Inbound `json:"inbounds"`
        TSnaps       []TSnap    `json:"tsnaps,omitempty"`
}

var (
        stateMu sync.RWMutex
        state   *State

        sessionsMu sync.Mutex
        sessions   = map[string]time.Time{}
        loginFails = map[string][]time.Time{}
)

const defaultSessionHours = 12
const loginFailWindow = 10 * time.Minute

var protoKeys = []string{"vless-ws", "vless-xhttp", "vless-hu", "vmess-ws", "trojan-ws", "vless-reality"}

var protoLabels = map[string]string{
        "vless-ws": "VLESS · WebSocket", "vless-xhttp": "VLESS · XHTTP",
        "vless-hu": "VLESS · HTTPUpgrade", "vmess-ws": "VMess · WebSocket",
        "trojan-ws": "Trojan · WebSocket", "vless-reality": "VLESS · Reality (TCP)",
}

func statePath() string {
        d := os.Getenv("DATA_DIR")
        if d == "" {
                d = "/data"
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

// saveState persists state under the lock (used by API handlers that already
// changed state with stateMu held or unlocked).
func saveState() {
        stateMu.Lock()
        defer stateMu.Unlock()
        saveStateLocked()
}

func saveStateLocked() {
        b, _ := json.Marshal(state)
        tmp := statePath() + ".tmp"
        if err := os.WriteFile(tmp, b, 0o644); err == nil {
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

var pathRe = regexp.MustCompile(`^/[A-Za-z0-9/_\-.]*$`)

func normPath(value, def string) string {
        p := strings.TrimSpace(value)
        if p == "" {
                p = def
        }
        if !strings.HasPrefix(p, "/") {
                p = "/" + p
        }
        p = strings.TrimRight(p, "/")
        if p == "" {
                return def
        }
        if !pathRe.MatchString(p) {
                return def
        }
        return p
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

// subToken derives the stable per-user subscription token from SECRET.
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

func clientStatus(c *Client, now time.Time) string {
        if c.ExpireAt != 0 && now.Unix() >= c.ExpireAt {
                return "expired"
        }
        if c.Quota != 0 && c.Up+c.Down >= c.Quota {
                return "quota"
        }
        return "active"
}

// userProtocols resolves the effective protocol set (per-user override wins).
func userProtocols(c *Client) map[string]bool {
        stateMu.RLock()
        defer stateMu.RUnlock()
        return userProtocolsLocked(c)
}

func userProtocolsLocked(c *Client) map[string]bool {
        out := map[string]bool{}
        if len(c.Protocols) > 0 {
                for _, k := range c.Protocols {
                        out[k] = true
                }
                return out
        }
        for _, k := range protoKeys {
                if state.Protocols == nil || state.Protocols[k] {
                        out[k] = true
                }
        }
        return out
}

func protoEnabled(key string) bool {
        stateMu.RLock()
        defer stateMu.RUnlock()
        if state.Protocols == nil {
                return true
        }
        v, ok := state.Protocols[key]
        return !ok || v
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

func loadState() {
        p := statePath()
        st := &State{}
        rawKeys := map[string]json.RawMessage{}
        if b, err := os.ReadFile(p); err == nil {
                _ = json.Unmarshal(b, st)
                _ = json.Unmarshal(b, &rawKeys)
        }
        if st.UUID == "" {
                st.UUID = envStr("UUID", uuidv4())
        }
        if envStr("UUID", "") != "" {
                st.UUID = envStr("UUID", "")
        }
        if st.AdminUser == "" {
                st.AdminUser = envStr("ADMIN_USER", "admin")
        }
        if st.AdminPass == "" {
                st.AdminPass = envStr("ADMIN_PASSWORD", mainIDFrom(st))
        }
        if st.RealitySNI == "" {
                st.RealitySNI = "www.microsoft.com"
        }
        if st.CfgFmt == "" {
                st.CfgFmt = "{name}-{label}"
        }
        if st.Protocols == nil {
                st.Protocols = map[string]bool{}
                for _, k := range protoKeys {
                        st.Protocols[k] = true
                }
        } else {
                for _, k := range protoKeys {
                        if _, ok := st.Protocols[k]; !ok {
                                st.Protocols[k] = true
                        }
                }
        }
        if st.SessionHours < 1 {
                st.SessionHours = defaultSessionHours
        }
        st.PassIsAuto = st.PassIsAuto || os.Getenv("ADMIN_PASSWORD") == ""
        if _, ok := rawKeys["random_sni"]; !ok {
                st.RandomSNI = true
        }
        if _, ok := rawKeys["pass_is_auto"]; !ok {
                st.PassIsAuto = os.Getenv("ADMIN_PASSWORD") == ""
        }
        if st.Tuning == nil {
                st.Tuning = defaultTuning()
        } else {
                st.Tuning = tuningSanitize(st.Tuning)
        }
        // v3.11: national-internet kit defaults (off until the admin opts in).
        if st.LocalMode == nil {
                st.LocalMode = &LocalModeState{}
        } else {
                lm := localModeSanitize(st.LocalMode)
                st.LocalMode = &lm
        }
        if st.TuningV < 2 {
                st.TuningV = 2
                if st.Tuning.Profile == "auto" && st.Tuning.FragLengths == "10-20" && st.Tuning.FragDelays == "10-20" {
                        st.Tuning = defaultTuning()
                }
        }
        var clients []*Client
        for _, c := range st.Clients {
                if c.ID != "" && c.Name != "" {
                        clients = append(clients, c)
                }
        }
        st.Clients = clients
        main := mainIDFrom(st)
        hasMain := false
        for _, c := range st.Clients {
                if c.ID == main {
                        hasMain = true
                }
        }
        if !hasMain {
                st.Clients = append([]*Client{{Name: "main", ID: main}}, st.Clients...)
        }
        state = st
        b, _ := json.Marshal(st)
        _ = os.WriteFile(p, b, 0o644)
}

func mainIDFrom(st *State) string {
        if s := os.Getenv("UUID"); s != "" {
                return s
        }
        return st.UUID
}

// sortedProtoKeys returns the user's protocol keys in canonical order.
func sortedProtoKeys(c *Client) []string {
        m := userProtocols(c)
        var out []string
        for _, k := range protoKeys {
                if m[k] {
                        out = append(out, k)
                }
        }
        sort.Strings(out)
        return out
}
