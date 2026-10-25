package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// ─────────── v3.10: live user sessions — who is online RIGHT NOW ───────────
// The Xray StatsService reports per-user traffic deltas (email = client ID).
// A user is "online" while traffic keeps flowing; when the flow stops for
// onlineGrace the session is closed and moved to the offline history with
// the exact time they stopped using the panel.

const (
	onlineSampleEvery = 2 * time.Second  // sampling cadence of the stats reader
	onlineIdleAt      = 30 * time.Second // no traffic for this long → "idle" (still online)
	onlineGrace       = 90 * time.Second // no traffic for this long → offline
	offlineHistoryMax = 300              // recent-offline events kept (newest first)
	offlinePersistMin = 10 * time.Second // throttle for persisting the offline log
)

type liveSession struct {
	ID          string
	OnlineSince time.Time
	LastSeen    time.Time
	SessUp      int64 // session bytes user→server (user upload)
	SessDown    int64 // session bytes server→user (user download)
	UpBps       float64
	DownBps     float64
}

type OfflineEvent struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	OnlineSince int64  `json:"since"`
	OfflineAt   int64  `json:"offline_at"`
	SessUp      int64  `json:"up"`
	SessDown    int64  `json:"down"`
}

var (
	onlineMu     sync.Mutex
	liveSess     = map[string]*liveSession{}
	offlineLog   []OfflineEvent // newest first
	offlineDirty bool
	lastOfflineW time.Time

	// usageDirty avoids rewriting state.json every 30s on an idle server
	// (the old collectUsage only wrote when a stats sample arrived).
	usageDirty atomic.Bool

	// statsReadMu serializes every Xray stats-API read. The CLI reads with
	// -reset, so two concurrent readers would each walk away with only a
	// slice of the window and traffic would be silently under-counted.
	statsReadMu sync.Mutex
)

func offlineLogPath() string { return filepath.Join(dataDir(), "online_log.json") }

// loadOfflineLog restores the recent-offline history after a redeploy.
func loadOfflineLog() {
	b, err := os.ReadFile(offlineLogPath())
	if err != nil {
		return
	}
	var d struct {
		Events []OfflineEvent `json:"events"`
	}
	if jsonUnmarshal(b, &d) == nil && len(d.Events) > 0 {
		if len(d.Events) > offlineHistoryMax {
			d.Events = d.Events[:offlineHistoryMax]
		}
		onlineMu.Lock()
		offlineLog = d.Events
		onlineMu.Unlock()
	}
}

// persistOfflineLog writes the history atomically (throttled).
func persistOfflineLog() {
	onlineMu.Lock()
	if !offlineDirty || time.Since(lastOfflineW) < offlinePersistMin {
		onlineMu.Unlock()
		return
	}
	events := append([]OfflineEvent(nil), offlineLog...)
	offlineDirty = false
	lastOfflineW = time.Now()
	onlineMu.Unlock()
	b, _ := json.Marshal(map[string]any{"events": events})
	tmp := offlineLogPath() + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil {
		_ = os.Rename(tmp, offlineLogPath())
	}
}

// drainUserStats is THE single regular reader of the Xray user counters:
// it reads (and resets) the deltas and feeds both the usage totals and the
// live-session tracker. Callers must not hold stateMu or onlineMu.
func drainUserStats() {
	if !xrayRunning() {
		return
	}
	statsReadMu.Lock()
	stats := xrayStats()
	statsReadMu.Unlock()
	if stats == nil {
		// read failed (xray restarting) — sessions survive the blip
		return
	}
	applyUserStats(stats, time.Now())
}

// applyUserStats folds one stats sample into the persistent totals and the
// live sessions (kept separate from drainUserStats so tests can drive it
// with synthetic samples and synthetic clocks).
func applyUserStats(stats map[string][2]int64, now time.Time) {
	if len(stats) > 0 {
		stateMu.Lock()
		for _, c := range state.Clients {
			if s, ok := stats[c.ID]; ok && (s[0] > 0 || s[1] > 0) {
				c.Up += s[0]
				c.Down += s[1]
				c.LastSeen = now.Unix()
				usageDirty.Store(true)
			}
		}
		stateMu.Unlock()
	}
	// ALWAYS evaluate idle/offline transitions — an empty sample means
	// "no traffic at all right now", which is exactly when sessions must age
	// out. Skipping this on empty samples left ghost online users forever.
	applySessions(stats, now)
}

// applySessions updates live sessions from a sample and closes the ones
// whose traffic stopped for longer than the grace window.
func applySessions(stats map[string][2]int64, now time.Time) {
	onlineMu.Lock()
	defer onlineMu.Unlock()
	secs := onlineSampleEvery.Seconds()
	for id, s := range stats {
		if s[0] <= 0 && s[1] <= 0 {
			continue
		}
		ls := liveSess[id]
		if ls == nil {
			ls = &liveSession{ID: id, OnlineSince: now, LastSeen: now}
			liveSess[id] = ls
		}
		ls.LastSeen = now
		ls.SessUp += s[0]
		ls.SessDown += s[1]
		ls.UpBps = ls.UpBps*0.65 + (float64(s[0])/secs)*0.35
		ls.DownBps = ls.DownBps*0.65 + (float64(s[1])/secs)*0.35
	}
	for id, ls := range liveSess {
		if now.Sub(ls.LastSeen) <= onlineGrace {
			continue
		}
		ev := OfflineEvent{
			ID: ls.ID, Name: sessionNameLocked(ls.ID),
			OnlineSince: ls.OnlineSince.Unix(), OfflineAt: ls.LastSeen.Unix(),
			SessUp: ls.SessUp, SessDown: ls.SessDown,
		}
		offlineLog = append([]OfflineEvent{ev}, offlineLog...)
		if len(offlineLog) > offlineHistoryMax {
			offlineLog = offlineLog[:offlineHistoryMax]
		}
		offlineDirty = true
		delete(liveSess, id)
	}
}

// sessionNameLocked resolves a client id to its display name ("" if unknown).
// Must be called with onlineMu held — it takes stateMu.RLock itself.
func sessionNameLocked(id string) string {
	stateMu.RLock()
	defer stateMu.RUnlock()
	for _, c := range state.Clients {
		if c.ID == id {
			return c.Name
		}
	}
	return ""
}

// sessionDrop removes every trace of an id (user deleted / regenerated).
func sessionDrop(id string) {
	onlineMu.Lock()
	delete(liveSess, id)
	var keep []OfflineEvent
	for _, ev := range offlineLog {
		if ev.ID != id {
			keep = append(keep, ev)
		}
	}
	if len(keep) != len(offlineLog) {
		offlineDirty = true
	}
	offlineLog = keep
	onlineMu.Unlock()
}

func onlineCount() int {
	onlineMu.Lock()
	n := len(liveSess)
	onlineMu.Unlock()
	return n
}

func userOnlineNow(id string) bool {
	onlineMu.Lock()
	_, ok := liveSess[id]
	onlineMu.Unlock()
	return ok
}

// onlineDurFor returns how long the user's current session has been running
// (seconds); -1 when the user is not online.
func onlineDurFor(id string) int64 {
	onlineMu.Lock()
	defer onlineMu.Unlock()
	ls, ok := liveSess[id]
	if !ok {
		return -1
	}
	return int64(time.Since(ls.OnlineSince).Seconds())
}

// onlinePayload is the /panel/api/online document: who is online now
// (with live speeds and session duration) plus the recent offline history.
func onlinePayload() map[string]any {
	now := time.Now()
	stateMu.RLock()
	names := map[string]string{}
	for _, c := range state.Clients {
		names[c.ID] = c.Name
	}
	stateMu.RUnlock()

	nameOf := func(id, fallback string) string {
		if n, ok := names[id]; ok && n != "" {
			return n
		}
		if fallback != "" {
			return fallback
		}
		return "(کاربر حذف‌شده)"
	}

	onlineMu.Lock()
	onl := make([]map[string]any, 0, len(liveSess))
	for _, ls := range liveSess {
		idle := now.Sub(ls.LastSeen).Seconds()
		st := "active"
		if idle >= onlineIdleAt.Seconds() {
			st = "idle"
		}
		onl = append(onl, map[string]any{
			"id": ls.ID, "name": nameOf(ls.ID, ""),
			"since":  ls.OnlineSince.Unix(),
			"dur_s":  int64(now.Sub(ls.OnlineSince).Seconds()),
			"idle_s": int64(idle),
			"up_bps": ls.UpBps, "down_bps": ls.DownBps,
			"up": ls.SessUp, "down": ls.SessDown,
			"status": st,
		})
	}
	sort.Slice(onl, func(i, j int) bool {
		si, sj := onl[i]["since"].(int64), onl[j]["since"].(int64)
		if si != sj {
			return si < sj
		}
		return onl[i]["name"].(string) < onl[j]["name"].(string)
	})
	evs := make([]map[string]any, 0, len(offlineLog))
	for _, ev := range offlineLog {
		dur := ev.OfflineAt - ev.OnlineSince
		if dur < 0 {
			dur = 0
		}
		evs = append(evs, map[string]any{
			"id": ev.ID, "name": nameOf(ev.ID, ev.Name),
			"since": ev.OnlineSince, "offline_at": ev.OfflineAt,
			"dur_s": dur, "up": ev.SessUp, "down": ev.SessDown,
		})
	}
	onlineMu.Unlock()

	return map[string]any{
		"online": onl, "offline": evs,
		"count": len(onl), "t": now.Unix(),
		"grace_s": int64(onlineGrace.Seconds()),
	}
}

// sessionLoop replaces the old 30s usageLoop: it drains the Xray user
// counters every 2s (feeding totals + live sessions) and every ~30s runs
// the slow housekeeping pass (persist state when dirty, persist offline
// log, sync xray config, traffic snapshot).
func sessionLoop() {
	n := 0
	for {
		time.Sleep(onlineSampleEvery)
		drainUserStats()
		n++
		if n%15 == 0 { // ~30s housekeeping
			if usageDirty.CompareAndSwap(true, false) {
				stateMu.Lock()
				saveStateLocked()
				stateMu.Unlock()
			}
			persistOfflineLog()
			syncXray()
			trafficSnapshot()
		}
	}
}
