package main

import (
        "encoding/json"
        "os"
        "testing"
        "time"
)

func resetOnlineState(t *testing.T) {
        t.Helper()
        onlineMu.Lock()
        liveSess = map[string]*liveSession{}
        offlineLog = nil
        offlineDirty = false
        lastOfflineW = time.Time{}
        onlineMu.Unlock()
}

func seedState(t *testing.T, clients ...*Client) {
        t.Helper()
        old := state
        state = &State{Clients: clients}
        t.Cleanup(func() { state = old })
}

// Sessions open on traffic, accumulate bytes, and close after the grace
// window with the exact last-seen timestamp as the offline time.
func TestSessionLifecycle(t *testing.T) {
        resetOnlineState(t)
        seedState(t, &Client{Name: "ali", ID: "id-ali"}, &Client{Name: "sara", ID: "id-sara"})

        t0 := time.Now()
        // first sample: ali starts using the panel
        applyUserStats(map[string][2]int64{"id-ali": {1024, 2048}}, t0)
        if n := onlineCount(); n != 1 {
                t.Fatalf("ali should be online, count=%d", n)
        }
        if !userOnlineNow("id-ali") {
                t.Fatal("ali online flag missing")
        }
        if userOnlineNow("id-sara") {
                t.Fatal("sara should be offline")
        }

        // sara joins; ali keeps flowing
        applyUserStats(map[string][2]int64{"id-ali": {100, 100}, "id-sara": {50, 500}}, t0.Add(6*time.Second))
        if n := onlineCount(); n != 2 {
                t.Fatalf("both should be online, count=%d", n)
        }

        // nobody sends anything for 3 more samples → still within grace
        applyUserStats(nil, t0.Add(30*time.Second))
        if n := onlineCount(); n != 2 {
                t.Fatalf("grace must keep users online, count=%d", n)
        }

        // after grace: both closed, offline events recorded
        applyUserStats(nil, t0.Add(100*time.Second))
        if n := onlineCount(); n != 0 {
                t.Fatalf("grace expired — everyone offline, count=%d", n)
        }
        onlineMu.Lock()
        if len(offlineLog) != 2 {
                onlineMu.Unlock()
                t.Fatalf("expected 2 offline events, got %d", len(offlineLog))
        }
        aliEv := offlineLog[0]
        onlineMu.Unlock()
        if aliEv.ID != "id-sara" { // newest first
                t.Errorf("newest event first: got %s", aliEv.ID)
        }
        if aliEv.Name != "sara" {
                t.Errorf("event name = %q, want sara", aliEv.Name)
        }
        if aliEv.SessUp != 50 || aliEv.SessDown != 500 {
                t.Errorf("sara session bytes = %d/%d, want 50/500", aliEv.SessUp, aliEv.SessDown)
        }
        // offline_at must equal the LAST TRAFFIC time (t0+6s), not the detection time
        if diff := aliEv.OfflineAt - t0.Add(6*time.Second).Unix(); diff < -1 || diff > 1 {
                t.Errorf("offline_at should be last traffic time (t0+6s), diff=%ds", diff)
        }

        // usage totals were folded into the clients
        stateMu.RLock()
        var ali *Client
        for _, c := range state.Clients {
                if c.ID == "id-ali" {
                        ali = c
                }
        }
        stateMu.RUnlock()
        if ali == nil || ali.Up != 1124 || ali.Down != 2148 {
                t.Fatalf("ali totals = %+v, want up=1124 down=2148", ali)
        }
}

// A user going idle (no traffic) but reconnecting before the grace expires
// keeps ONE continuous session (no false offline event).
func TestSessionContinuityWithinGrace(t *testing.T) {
        resetOnlineState(t)
        seedState(t, &Client{Name: "x", ID: "x1"})

        t0 := time.Now()
        applyUserStats(map[string][2]int64{"x1": {10, 10}}, t0)
        applyUserStats(nil, t0.Add(80*time.Second)) // idle but < grace (90s)
        applyUserStats(map[string][2]int64{"x1": {10, 10}}, t0.Add(88*time.Second)) // resumed!
        if n := onlineCount(); n != 1 {
                t.Fatalf("session should survive the idle gap, count=%d", n)
        }
        onlineMu.Lock()
        n := len(offlineLog)
        onlineMu.Unlock()
        if n != 0 {
                t.Fatalf("no offline event expected, got %d", n)
        }
        // …but a gap longer than grace closes it
        applyUserStats(nil, t0.Add(200*time.Second))
        if n := onlineCount(); n != 0 {
                t.Fatalf("session should be closed, count=%d", n)
        }
}

// The online payload resolves names, sorts by session start, and reports
// durations and speeds for each online user.
func TestOnlinePayloadShape(t *testing.T) {
        resetOnlineState(t)
        seedState(t,
                &Client{Name: "main", ID: "m1"},
                &Client{Name: "zari", ID: "z9"},
        )

        // m1's session started 5 minutes ago and is STILL flowing right now
        applyUserStats(map[string][2]int64{"m1": {1 << 20, 2 << 20}}, time.Now().Add(-5*time.Minute))
        applyUserStats(map[string][2]int64{"m1": {1 << 20, 2 << 20}, "z9": {1, 1}}, time.Now())

        p := onlinePayload()
        raw, _ := json.Marshal(p)
        var d struct {
                Online []map[string]any `json:"online"`
                Count  int             `json:"count"`
        }
        if err := json.Unmarshal(raw, &d); err != nil {
                t.Fatalf("payload not JSON-marshalable: %v", err)
        }
        if d.Count != 2 || len(d.Online) != 2 {
                t.Fatalf("count=%d len=%d, want 2/2", d.Count, len(d.Online))
        }
        // sorted by since: m1 (earlier) first
        if d.Online[0]["name"] != "main" {
                t.Errorf("oldest session should sort first, got %v", d.Online[0]["name"])
        }
        if d.Online[0]["dur_s"].(float64) < 290 {
                t.Errorf("dur_s too small: %v", d.Online[0]["dur_s"])
        }
        if d.Online[0]["status"] != "active" {
                t.Errorf("fresh traffic → active, got %v", d.Online[0]["status"])
        }

        // idle flag: traffic 31s ago → still online, but flagged idle
        resetOnlineState(t)
        seedState(t, &Client{Name: "main", ID: "m1"})
        applyUserStats(map[string][2]int64{"m1": {1, 1}}, time.Now().Add(-31*time.Second))
        p2 := onlinePayload()
        raw2, _ := json.Marshal(p2)
        var d2 struct {
                Online []map[string]any `json:"online"`
        }
        _ = json.Unmarshal(raw2, &d2)
        if len(d2.Online) != 1 {
                t.Fatalf("idle user stays online: %d", len(d2.Online))
        }
        if d2.Online[0]["status"] != "idle" {
                t.Errorf("stale session should be idle: %v", d2.Online[0]["status"])
        }
}

// sessionDrop removes every trace of a deleted user.
func TestSessionDrop(t *testing.T) {
        resetOnlineState(t)
        seedState(t, &Client{Name: "a", ID: "a1"})

        now := time.Now()
        applyUserStats(map[string][2]int64{"a1": {5, 5}}, now)
        applyUserStats(nil, now.Add(onlineGrace+time.Second)) // a1 → offline log
        sessionDrop("a1")

        if userOnlineNow("a1") {
                t.Error("live entry not dropped")
        }
        onlineMu.Lock()
        if len(offlineLog) != 0 {
                t.Errorf("offline history not dropped: %d", len(offlineLog))
        }
        onlineMu.Unlock()
}

// The offline log is capped at offlineHistoryMax.
func TestOfflineLogCap(t *testing.T) {
        resetOnlineState(t)
        seedState(t, &Client{Name: "a", ID: "a1"})

        base := time.Now()
        for i := 0; i < offlineHistoryMax+25; i++ {
                applyUserStats(map[string][2]int64{"a1": {1, 1}}, base.Add(time.Duration(i)*time.Second))
                applyUserStats(nil, base.Add(time.Duration(i)*time.Second+onlineGrace+time.Second))
        }
        onlineMu.Lock()
        n := len(offlineLog)
        onlineMu.Unlock()
        if n != offlineHistoryMax {
                t.Fatalf("offline log len=%d, want %d", n, offlineHistoryMax)
        }
}

// The persisted offline log round-trips through disk.
func TestOfflineLogPersistence(t *testing.T) {
        dir := t.TempDir()
        os.Setenv("DATA_DIR", dir)
        defer os.Unsetenv("DATA_DIR")

        resetOnlineState(t)
        seedState(t, &Client{Name: "a", ID: "a1"})

        now := time.Now()
        applyUserStats(map[string][2]int64{"a1": {7, 9}}, now)
        applyUserStats(nil, now.Add(onlineGrace+time.Second))

        onlineMu.Lock()
        offlineDirty = true
        lastOfflineW = time.Time{} // force write
        onlineMu.Unlock()
        persistOfflineLog()

        b, err := os.ReadFile(offlineLogPath())
        if err != nil {
                t.Fatalf("offline log not written: %v", err)
        }
        var d struct {
                Events []OfflineEvent `json:"events"`
        }
        if json.Unmarshal(b, &d) != nil || len(d.Events) != 1 {
                t.Fatalf("round-trip failed: %s", b)
        }
        if d.Events[0].Name != "a" || d.Events[0].SessUp != 7 || d.Events[0].SessDown != 9 {
                t.Errorf("event = %+v", d.Events[0])
        }

        // a fresh boot restores it
        resetOnlineState(t)
        loadOfflineLog()
        onlineMu.Lock()
        n := len(offlineLog)
        onlineMu.Unlock()
        if n != 1 {
                t.Fatalf("loadOfflineLog restored %d events, want 1", n)
        }
}

// The stats CLI args: the destructive read carries -reset, the peek does not.
func TestXrayStatsArgs(t *testing.T) {
        reset := xrayStatsArgs(true)
        peek := xrayStatsArgs(false)
        if !containsStr(reset, "-reset") {
                t.Errorf("reset args missing -reset: %v", reset)
        }
        if containsStr(peek, "-reset") {
                t.Errorf("peek args must not reset: %v", peek)
        }
        if !containsStr(peek, "user>>>") || !containsStr(reset, "user>>>") {
                t.Errorf("pattern missing: %v / %v", peek, reset)
        }
}
