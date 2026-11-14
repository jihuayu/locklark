package desktop

import (
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
)

// TestWatchtowerSidebarRunsLocalCheckAndRetiresOnLock drives the visible
// sidebar entry into the actual local Watchtower view, runs the offline scan
// against an owned, encrypted temporary personal session, and proves the
// report is retired by Lock. No HIBP/network path is enabled.
func TestWatchtowerSidebarRunsLocalCheckAndRetiresOnLock(t *testing.T) {
	a := dailyAppFixture(t)
	if _, err := a.session.AddLogin("Watchtower login", "watchtower-user", "weak"); err != nil {
		t.Fatal(err)
	}
	a.EnableV2()
	dispatched := make(chan func(), 8)
	a.dispatch = func(fn func()) { dispatched <- fn }

	tester := newOnevraTestTesterSize(a, 1280, 1000)
	if !tester.HasText("Watchtower 安全体检") {
		t.Fatal("default sidebar does not expose Watchtower")
	}
	if err := tester.Click("Watchtower 安全体检"); err != nil {
		t.Fatal(err)
	}
	if a.v2.nav != navWatchtower {
		t.Fatalf("Watchtower entry selected nav %q", a.v2.nav)
	}
	// The sidebar navigation itself reloads the vault list through the app's
	// normal run path. Drain that one result before starting the local check.
	select {
	case apply := <-dispatched:
		apply()
	case <-time.After(5 * time.Second):
		t.Fatal("sidebar navigation did not dispatch its result")
	}
	if a.busy {
		t.Fatal("sidebar navigation left the app busy")
	}
	tester.Frame()
	if !tester.HasText("运行本地检查") || !tester.HasText("尚未运行安全扫描") {
		t.Fatal("sidebar entry did not navigate to the wired Watchtower view")
	}
	if err := tester.Click("运行本地检查"); err != nil {
		t.Fatal(err)
	}

	var apply func()
	select {
	case apply = <-dispatched:
	case <-time.After(5 * time.Second):
		t.Fatal("local Watchtower check did not dispatch its result")
	}
	apply()
	if a.v2.watchtower == nil {
		t.Fatalf("local Watchtower check produced no report (status=%q busy=%v)", a.status, a.busy)
	}
	report := *a.v2.watchtower
	if report.HIBPChecked || report.HIBPError != "" {
		t.Fatalf("offline default touched HIBP: %+v", report)
	}
	if report.Checked == 0 || len(report.Findings) == 0 {
		t.Fatalf("local Watchtower report has no checked findings: %+v", report)
	}
	if a.busy {
		t.Fatal("local Watchtower check left the app busy")
	}

	a.Lock()
	if a.v2.watchtower != nil || a.v2.nav == navWatchtower {
		t.Fatal("Lock did not retire the Watchtower report and route")
	}
}

// TestWatchtowerStaleGenerationDropsLateReport proves the existing 151
// generation guard drops a local Watchtower result that arrives after the
// generation it started under is no longer current. The work is queued through
// the app's own launch seam, so no sleep or production mock bypass is used.
func TestWatchtowerStaleGenerationDropsLateReport(t *testing.T) {
	a := dailyAppFixture(t)
	if _, err := a.session.AddLogin("Watchtower stale login", "watchtower-user", "weak"); err != nil {
		t.Fatal(err)
	}
	a.EnableV2()
	a.v2.nav = navWatchtower
	launched := make(chan func(), 1)
	dispatched := make(chan func(), 1)
	a.launch = func(fn func()) { launched <- fn }
	a.dispatch = func(fn func()) { dispatched <- fn }

	tester := ui.NewTester(a.v2WatchtowerView, 800, 600)
	if err := tester.Click("运行本地检查"); err != nil {
		t.Fatal(err)
	}
	var work func()
	select {
	case work = <-launched:
	case <-time.After(5 * time.Second):
		t.Fatal("local Watchtower work was not queued")
	}
	a.lockStart()
	work()
	var apply func()
	select {
	case apply = <-dispatched:
	case <-time.After(5 * time.Second):
		t.Fatal("stale local Watchtower result did not dispatch")
	}
	apply()
	if a.v2.watchtower != nil {
		t.Fatal("stale generation applied a late Watchtower report")
	}
	a.Lock()
}
