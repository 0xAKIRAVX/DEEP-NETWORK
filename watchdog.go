package main

// ─────────── v3.16: نگهبان قفل / lock watchdog ───────────
// One mutex (stateMu) guards the whole panel state. History (live v3.15
// incident): two recursive RLock paths + a network call under the write lock
// froze the running panel — every API and subscription request hung while
// static files kept serving, nobody could even log in, and clients could not
// refresh their configs. Those bugs are fixed at the source (see autoscan.go /
// ircheck.go / api.go v3.16 notes), but "never again" needs a safety net:
//
//   * every 30s the watchdog tries to acquire stateMu;
//   * if it cannot within 30s it dumps EVERY goroutine stack to the deploy
//     log (the exact deadlock site becomes visible in Lucity's logs);
//   * if the lock is still frozen 2 minutes later it panics ON PURPOSE —
//     Lucity restarts the process and the panel self-heals in about a minute
//     instead of staying dead until the next git push.

import (
	"runtime"
	"time"
)

const (
	watchdogEvery  = 30 * time.Second
	watchdogBudget = 30 * time.Second
	watchdogGiveUp = 2 * time.Minute
)

// watchdogProbe tries to take stateMu and reports within the budget.
// dump is non-empty when the budget expired (goroutine stacks).
func watchdogProbe(budget time.Duration) (locked bool, dump string) {
	acquired := make(chan struct{})
	go func() {
		stateMu.Lock()
		close(acquired)
		stateMu.Unlock()
	}()
	select {
	case <-acquired:
		return true, ""
	case <-time.After(budget):
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		return false, string(buf[:n])
	}
}

// watchdogOnce is a single cycle (unit-testable): "ok" when the lock is
// healthy, "recovered" when it was slow but came back, and it calls die()
// when the lock stays frozen past both budgets.
func watchdogOnce(budget, giveUp time.Duration, die func(reason string)) string {
	locked, dump := watchdogProbe(budget)
	if locked {
		return "ok"
	}
	logf("WATCHDOG: stateMu not acquirable for %s — goroutine dump follows:\n%s", budget, dump)
	if locked, _ := watchdogProbe(giveUp); locked {
		logf("WATCHDOG: stateMu recovered after dump")
		return "recovered"
	}
	die("stateMu frozen for over " + (budget + giveUp).String() + " — self-restarting panel")
	return "dead" // unreachable with a real die
}

// lockWatchdog runs the cycle forever in the background.
func lockWatchdog() {
	go func() {
		for {
			time.Sleep(watchdogEvery)
			watchdogOnce(watchdogBudget, watchdogGiveUp, func(reason string) {
				panic(reason)
			})
		}
	}()
}
