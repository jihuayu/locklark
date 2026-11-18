//go:build darwin

package desktop

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/egoist/mygo"
	_ "github.com/egoist/mygo/plugins/automation"
	"github.com/oneo-me/onevra/source/shells/plain"
	"golang.org/x/sys/unix"
)

// This checkpoint drives the ordinary Onevra local-vault view through MyGo's
// existing automation event path: pointer and text events are delivered to the
// same surface.Content the native macOS backend delivers OS input to, and the
// rendered widget itself handles them. It never calls the exact-query or
// activation handlers for the claimed input/click.
//
// It is opt-in twice: LOCKLARK_NATIVE_SMOKE=1 selects the existing native
// TestMain, and MYGO_AUTOMATION names a private Unix socket in a private
// temporary directory before the test binary starts. The automation plugin
// then serves only this test process; the test proves that with LOCAL_PEERPID
// before it addresses the one expected content window by exact ID and title.

const (
	nativeQueryAcceptanceTitle = "Locklark native exact query acceptance"
	// LOCAL_PEERPID (sys/un.h) is Darwin's read-only getsockopt for an AF_UNIX peer PID.
	nativeQueryAcceptanceLocalPeerPID = unix.LOCAL_PEERPID
	nativeQueryAcceptanceCallTimeout  = 10 * time.Second
)

var (
	errNativeQueryAcceptanceIO      = errors.New("native query acceptance automation I/O")
	errNativeQueryAcceptanceRefused = errors.New("native query acceptance automation refused")
)

type nativeQueryAcceptanceRect struct {
	X      float64 `json:"x"`
	Y      float64 `json:"y"`
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}

type nativeQueryAcceptanceWindow struct {
	ID            int                       `json:"id"`
	Title         string                    `json:"title"`
	Kind          string                    `json:"kind"`
	Bounds        nativeQueryAcceptanceRect `json:"bounds"`
	ContentBounds nativeQueryAcceptanceRect `json:"contentBounds"`
	Focused       bool                      `json:"focused"`
	Visible       bool                      `json:"visible"`
}

type nativeQueryAcceptanceNode struct {
	ID      string                    `json:"id"`
	Parent  string                    `json:"parent"`
	Role    string                    `json:"role"`
	Key     any                       `json:"key"`
	Label   string                    `json:"label"`
	Value   string                    `json:"value"`
	Bounds  nativeQueryAcceptanceRect `json:"bounds"`
	States  []string                  `json:"states"`
	Actions []string                  `json:"actions"`
}

type nativeQueryAcceptanceTree struct {
	Window int                         `json:"window"`
	Focus  string                      `json:"focus"`
	Nodes  []nativeQueryAcceptanceNode `json:"nodes"`
}

type nativeQueryAcceptanceEvent struct {
	Type string  `json:"type"`
	X    float64 `json:"x,omitempty"`
	Y    float64 `json:"y,omitempty"`
	Key  string  `json:"key,omitempty"`
	Text string  `json:"text,omitempty"`
}

type nativeQueryAcceptanceAutomation struct {
	conn   net.Conn
	reader *bufio.Reader
	next   int64
}

func nativeQueryAcceptanceOpenAutomation(t *testing.T) *nativeQueryAcceptanceAutomation {
	t.Helper()
	path := os.Getenv("MYGO_AUTOMATION")
	if path == "" {
		t.Fatal("NATIVE_QUERY_AUTOMATION_NOT_CONFIGURED")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		t.Fatal("NATIVE_QUERY_AUTOMATION_PATH_INVALID")
	}
	root := filepath.Dir(path)
	resolvedRoot, rootErr := filepath.EvalSymlinks(root)
	if rootErr != nil {
		t.Fatal("NATIVE_QUERY_AUTOMATION_ROOT_NOT_PRIVATE_TEMP")
	}
	privateTemp := false
	for _, base := range []string{filepath.Clean(os.TempDir()), "/tmp", "/private/tmp"} {
		resolvedBase, err := filepath.EvalSymlinks(base)
		if err != nil {
			continue
		}
		if resolvedRoot == resolvedBase ||
			strings.HasPrefix(resolvedRoot, resolvedBase+string(os.PathSeparator)) {
			privateTemp = true
			break
		}
	}
	if !privateTemp {
		t.Fatal("NATIVE_QUERY_AUTOMATION_ROOT_NOT_PRIVATE_TEMP")
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		t.Fatal("NATIVE_QUERY_AUTOMATION_ROOT_NOT_PRIVATE")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Getuid() {
		t.Fatal("NATIVE_QUERY_AUTOMATION_ROOT_OWNER_MISMATCH")
	}
	socket, err := os.Lstat(path)
	if err != nil || socket.Mode()&os.ModeSocket == 0 {
		t.Fatal("NATIVE_QUERY_AUTOMATION_NOT_UNIX")
	}
	conn, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil {
		t.Fatal("NATIVE_QUERY_AUTOMATION_UNAVAILABLE")
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		_ = conn.Close()
		t.Fatal("NATIVE_QUERY_AUTOMATION_NOT_UNIX")
	}
	peer, err := nativeQueryAcceptancePeerPID(unixConn)
	if err != nil || peer != os.Getpid() {
		_ = conn.Close()
		t.Fatal("NATIVE_QUERY_AUTOMATION_PEER_MISMATCH")
	}
	client := &nativeQueryAcceptanceAutomation{conn: conn, reader: bufio.NewReader(conn)}
	t.Cleanup(func() { _ = conn.Close() })
	return client
}

func nativeQueryAcceptancePeerPID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var pid int
	var errno error
	if err := raw.Control(func(fd uintptr) {
		pid, errno = syscall.GetsockoptInt(int(fd), 0, nativeQueryAcceptanceLocalPeerPID)
	}); err != nil {
		return 0, err
	}
	return pid, errno
}

func (c *nativeQueryAcceptanceAutomation) call(method string, params, result any) error {
	c.next++
	request := struct {
		ID     int64  `json:"id"`
		Method string `json:"method"`
		Params any    `json:"params,omitempty"`
	}{ID: c.next, Method: method, Params: params}
	line, err := json.Marshal(request)
	if err != nil {
		return errNativeQueryAcceptanceIO
	}
	if err := c.conn.SetDeadline(time.Now().Add(nativeQueryAcceptanceCallTimeout)); err != nil {
		return errNativeQueryAcceptanceIO
	}
	if _, err := c.conn.Write(append(line, '\n')); err != nil {
		return errNativeQueryAcceptanceIO
	}
	reply, err := c.reader.ReadBytes('\n')
	if err != nil {
		return errNativeQueryAcceptanceIO
	}
	var response struct {
		ID     json.RawMessage `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(reply, &response); err != nil {
		return errNativeQueryAcceptanceIO
	}
	if response.Error != nil {
		return errNativeQueryAcceptanceRefused
	}
	if result == nil {
		return nil
	}
	if len(response.Result) == 0 || json.Unmarshal(response.Result, result) != nil {
		return errNativeQueryAcceptanceIO
	}
	return nil
}

func (c *nativeQueryAcceptanceAutomation) windows() ([]nativeQueryAcceptanceWindow, error) {
	var result struct {
		Windows []nativeQueryAcceptanceWindow `json:"windows"`
	}
	if err := c.call("windows", struct{}{}, &result); err != nil {
		return nil, err
	}
	return result.Windows, nil
}

func (c *nativeQueryAcceptanceAutomation) tree(window int) (nativeQueryAcceptanceTree, error) {
	var result nativeQueryAcceptanceTree
	if err := c.call("tree", struct {
		Window int `json:"window"`
	}{Window: window}, &result); err != nil {
		return nativeQueryAcceptanceTree{}, err
	}
	if result.Window != window {
		return nativeQueryAcceptanceTree{}, errNativeQueryAcceptanceIO
	}
	return result, nil
}

func (c *nativeQueryAcceptanceAutomation) input(window int, events ...nativeQueryAcceptanceEvent) error {
	return c.call("input", struct {
		Window int                          `json:"window"`
		Events []nativeQueryAcceptanceEvent `json:"events"`
	}{Window: window, Events: events}, &struct{}{})
}

func (c *nativeQueryAcceptanceAutomation) isolatedWindow(window int, title string) (nativeQueryAcceptanceWindow, bool, error) {
	windows, err := c.windows()
	if err != nil {
		return nativeQueryAcceptanceWindow{}, false, err
	}
	content, matches := 0, 0
	var target nativeQueryAcceptanceWindow
	for _, candidate := range windows {
		if candidate.Kind != "content" {
			continue
		}
		content++
		if candidate.ID == window && candidate.Title == title {
			matches++
			target = candidate
		}
	}
	ok := content == 1 && matches == 1 && target.Visible &&
		target.Bounds.Width > 0 && target.Bounds.Height > 0 &&
		target.ContentBounds.Width > 0 && target.ContentBounds.Height > 0
	return target, ok, nil
}

func (c *nativeQueryAcceptanceAutomation) requireWindow(t *testing.T, window int, title string) nativeQueryAcceptanceWindow {
	t.Helper()
	target, ok, err := c.isolatedWindow(window, title)
	if err != nil {
		t.Fatal("NATIVE_QUERY_AUTOMATION_WINDOWS_FAILED")
	}
	if !ok {
		t.Fatal("NATIVE_QUERY_TARGET_WINDOW_NOT_ISOLATED")
	}
	return target
}

func nativeQueryAcceptanceClickable(node nativeQueryAcceptanceNode) bool {
	for _, state := range node.States {
		if state == "disabled" {
			return false
		}
	}
	if node.Role == "button" {
		return true
	}
	for _, action := range node.Actions {
		if action == "press" {
			return true
		}
	}
	return false
}

func nativeQueryAcceptanceFindLabel(nodes []nativeQueryAcceptanceNode, label string) (nativeQueryAcceptanceNode, int) {
	var found nativeQueryAcceptanceNode
	count := 0
	for _, node := range nodes {
		if node.Label == label && nativeQueryAcceptanceClickable(node) {
			found = node
			count++
		}
	}
	return found, count
}

func nativeQueryAcceptanceFindText(nodes []nativeQueryAcceptanceNode, label string) (nativeQueryAcceptanceNode, int) {
	var found nativeQueryAcceptanceNode
	count := 0
	for _, node := range nodes {
		if node.Role == "text" && node.Label == label {
			found = node
			count++
		}
	}
	return found, count
}

func nativeQueryAcceptanceFindKey(nodes []nativeQueryAcceptanceNode, key string) (nativeQueryAcceptanceNode, int) {
	var found nativeQueryAcceptanceNode
	count := 0
	for _, node := range nodes {
		value, ok := node.Key.(string)
		if ok && value == key {
			found = node
			count++
		}
	}
	return found, count
}

func nativeQueryAcceptanceLocalVaultKey(path string) string {
	sum := sha256.Sum256([]byte(path))
	return "local-vault-file:" + hex.EncodeToString(sum[:])
}

func nativeQueryAcceptanceCenter(rect nativeQueryAcceptanceRect) (float64, float64) {
	return rect.X + rect.Width/2, rect.Y + rect.Height/2
}

func nativeQueryAcceptanceRequireLabel(t *testing.T, nodes []nativeQueryAcceptanceNode, label string) nativeQueryAcceptanceNode {
	t.Helper()
	node, count := nativeQueryAcceptanceFindLabel(nodes, label)
	if count != 1 {
		t.Fatal("NATIVE_QUERY_CONTROL_NOT_UNIQUE")
	}
	return node
}

func nativeQueryAcceptanceRequireText(t *testing.T, nodes []nativeQueryAcceptanceNode, label string) {
	t.Helper()
	if _, count := nativeQueryAcceptanceFindText(nodes, label); count != 1 {
		t.Fatal("NATIVE_QUERY_RESULT_ID_NOT_UNIQUE")
	}
}

func nativeQueryAcceptanceWait(t *testing.T, app *App, timeout time.Duration, marker string, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if check() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal(marker)
		}
		mygo.RunOnMain(func() {
			if app.win != nil {
				app.win.Invalidate()
			}
		})
		time.Sleep(50 * time.Millisecond)
	}
}

func nativeQueryAcceptanceWaitNode(t *testing.T, app *App, client *nativeQueryAcceptanceAutomation, window int, timeout time.Duration, marker string, match func(nativeQueryAcceptanceTree) (nativeQueryAcceptanceNode, bool)) nativeQueryAcceptanceNode {
	t.Helper()
	var found nativeQueryAcceptanceNode
	nativeQueryAcceptanceWait(t, app, timeout, marker, func() bool {
		tree, err := client.tree(window)
		if err != nil {
			return false
		}
		node, ok := match(tree)
		if ok {
			found = node
		}
		return ok
	})
	return found
}

func nativeQueryAcceptanceClickLabel(t *testing.T, app *App, client *nativeQueryAcceptanceAutomation, window int, title, label string) {
	t.Helper()
	nativeQueryAcceptanceWaitNode(t, app, client, window, 5*time.Second,
		"NATIVE_QUERY_CONTROL_MISSING", func(tree nativeQueryAcceptanceTree) (nativeQueryAcceptanceNode, bool) {
			found, count := nativeQueryAcceptanceFindLabel(tree.Nodes, label)
			return found, count == 1
		})
	client.requireWindow(t, window, title)
	tree, err := client.tree(window)
	if err != nil {
		t.Fatal("NATIVE_QUERY_TARGET_TREE_FAILED")
	}
	fresh, count := nativeQueryAcceptanceFindLabel(tree.Nodes, label)
	if count != 1 || fresh.Bounds.Width <= 0 || fresh.Bounds.Height <= 0 {
		t.Fatal("NATIVE_QUERY_TARGET_CHANGED")
	}
	client.requireWindow(t, window, title)
	x, y := nativeQueryAcceptanceCenter(fresh.Bounds)
	if err := client.input(window, nativeQueryAcceptanceEvent{Type: "click", X: x, Y: y}); err != nil {
		t.Fatal("NATIVE_QUERY_NATIVE_INPUT_FAILED")
	}
}

func nativeQueryAcceptanceClickKey(t *testing.T, app *App, client *nativeQueryAcceptanceAutomation, window int, title, key string) {
	t.Helper()
	nativeQueryAcceptanceWaitNode(t, app, client, window, 5*time.Second,
		"NATIVE_QUERY_CONTROL_MISSING", func(tree nativeQueryAcceptanceTree) (nativeQueryAcceptanceNode, bool) {
			found, count := nativeQueryAcceptanceFindKey(tree.Nodes, key)
			return found, count == 1
		})
	client.requireWindow(t, window, title)
	tree, err := client.tree(window)
	if err != nil {
		t.Fatal("NATIVE_QUERY_TARGET_TREE_FAILED")
	}
	fresh, count := nativeQueryAcceptanceFindKey(tree.Nodes, key)
	if count != 1 || fresh.Bounds.Width <= 0 || fresh.Bounds.Height <= 0 {
		t.Fatal("NATIVE_QUERY_TARGET_CHANGED")
	}
	client.requireWindow(t, window, title)
	x, y := nativeQueryAcceptanceCenter(fresh.Bounds)
	if err := client.input(window, nativeQueryAcceptanceEvent{Type: "click", X: x, Y: y}); err != nil {
		t.Fatal("NATIVE_QUERY_NATIVE_INPUT_FAILED")
	}
}

func nativeQueryAcceptanceType(t *testing.T, client *nativeQueryAcceptanceAutomation, window int, title, text string) {
	t.Helper()
	client.requireWindow(t, window, title)
	tree, err := client.tree(window)
	if err != nil {
		t.Fatal("NATIVE_QUERY_TARGET_TREE_FAILED")
	}
	node, count := nativeQueryAcceptanceFindKey(tree.Nodes, "local-vault-query")
	if count != 1 || tree.Focus != node.ID {
		t.Fatal("NATIVE_QUERY_EDITOR_NOT_FOCUSED")
	}
	client.requireWindow(t, window, title)
	if err := client.input(window,
		nativeQueryAcceptanceEvent{Type: "key", Key: "CmdOrCtrl+A"},
		nativeQueryAcceptanceEvent{Type: "key", Key: "Backspace"},
		nativeQueryAcceptanceEvent{Type: "text", Text: text}); err != nil {
		t.Fatal("NATIVE_QUERY_NATIVE_INPUT_FAILED")
	}
}

type nativeQueryAcceptanceRows struct {
	marker     string
	hitA, hitB *localVaultFileQueryHit
	labelA     string
	labelB     string
	proofA     int
	proofB     int
}

func nativeQueryAcceptanceReadRows(app *App, aPath, bPath, aVaultID, bVaultID string) nativeQueryAcceptanceRows {
	var rows nativeQueryAcceptanceRows
	mygo.RunOnMain(func() {
		state := &app.localVaultFiles
		if state.query.operation != nil || state.query.current == nil ||
			state.query.title != desktopLocalVaultQueryTitle {
			rows.marker = "NATIVE_QUERY_EDITOR_STATE_FAILED"
			return
		}
		hits := app.localVaultFileQueryHits()
		if len(hits) != 2 {
			rows.marker = "NATIVE_QUERY_ROW_COUNT_FAILED"
			return
		}
		byID := make(map[string]*localVaultFileQueryHit, len(hits))
		for _, hit := range hits {
			if hit == nil || hit.result == nil {
				rows.marker = "NATIVE_QUERY_NIL_ROW"
				return
			}
			if _, exists := byID[hit.id]; exists {
				rows.marker = "NATIVE_QUERY_DUPLICATE_ROW"
				return
			}
			byID[hit.id] = hit
		}
		hitA, hitB := byID[desktopLocalVaultQueryIDA], byID[desktopLocalVaultQueryIDB]
		if hitA == nil || hitB == nil {
			rows.marker = "NATIVE_QUERY_IDS_NOT_INDEPENDENT"
			return
		}
		if hitA.title != desktopLocalVaultQueryTitle || hitB.title != desktopLocalVaultQueryTitle {
			rows.marker = "NATIVE_QUERY_TITLE_MISMATCH"
			return
		}
		scopeA, scopeB := hitA.result.scope, hitB.result.scope
		if scopeA == scopeB || scopeA.configPath == scopeB.configPath ||
			scopeA.vaultID == scopeB.vaultID || scopeA.journalPath == scopeB.journalPath ||
			hitA.result.wrapper == hitB.result.wrapper {
			rows.marker = "NATIVE_QUERY_SCOPES_NOT_INDEPENDENT"
			return
		}
		refA, okA := localVaultFileRefByPath(state.refs, aPath)
		refB, okB := localVaultFileRefByPath(state.refs, bPath)
		if !okA || !okB || refA.vaultID != aVaultID || refB.vaultID != bVaultID {
			rows.marker = "NATIVE_QUERY_REFS_NOT_BOUND"
			return
		}
		rows.labelA = app.localVaultFileDisplayLabelFor(refA)
		rows.labelB = app.localVaultFileDisplayLabelFor(refB)
		if rows.labelA == "" || rows.labelB == "" || rows.labelA == rows.labelB {
			rows.marker = "NATIVE_QUERY_DISPLAY_LABELS_NOT_INDEPENDENT"
			return
		}
		rows.hitA, rows.hitB = hitA, hitB
		rows.proofA = len(hitA.result.proof.Hits)
		rows.proofB = len(hitB.result.proof.Hits)
		if rows.proofA != 1 || rows.proofB != 1 {
			rows.marker = "NATIVE_QUERY_PROOFS_NOT_PRESENT"
		}
	})
	return rows
}

func nativeQueryAcceptanceRowIDAfter(nodes []nativeQueryAcceptanceNode, label string) string {
	start := -1
	for index, node := range nodes {
		if node.Label == label && nativeQueryAcceptanceClickable(node) {
			start = index
			break
		}
	}
	if start < 0 {
		return ""
	}
	for _, node := range nodes[start+1:] {
		if node.Role == "text" && strings.HasPrefix(node.Label, "ID：") {
			return strings.TrimPrefix(node.Label, "ID：")
		}
	}
	return ""
}

func nativeQueryAcceptanceRequireRows(t *testing.T, tree nativeQueryAcceptanceTree, rows nativeQueryAcceptanceRows) {
	t.Helper()
	labelA := "激活到 " + rows.labelA + "：" + desktopLocalVaultQueryTitle
	labelB := "激活到 " + rows.labelB + "：" + desktopLocalVaultQueryTitle
	nativeQueryAcceptanceRequireLabel(t, tree.Nodes, labelA)
	nativeQueryAcceptanceRequireLabel(t, tree.Nodes, labelB)
	nativeQueryAcceptanceRequireText(t, tree.Nodes, "ID："+desktopLocalVaultQueryIDA)
	nativeQueryAcceptanceRequireText(t, tree.Nodes, "ID："+desktopLocalVaultQueryIDB)
	if nativeQueryAcceptanceRowIDAfter(tree.Nodes, labelA) != desktopLocalVaultQueryIDA ||
		nativeQueryAcceptanceRowIDAfter(tree.Nodes, labelB) != desktopLocalVaultQueryIDB {
		t.Fatal("NATIVE_QUERY_RESULT_PAIRING_FAILED")
	}
}

func nativeQueryAcceptanceActivation(app *App, path, vaultID, id string) bool {
	matched := false
	mygo.RunOnMain(func() {
		active, current := app.localVaultFileActiveItemCurrent()
		matched = app.localVaultFiles.selected == path && current &&
			active.id == id && active.title == desktopLocalVaultQueryTitle &&
			active.scope.configPath == path && active.scope.vaultID == vaultID
	})
	return matched
}

func nativeQueryAcceptanceActivationLine(t *testing.T, app *App, client *nativeQueryAcceptanceAutomation, window int) {
	t.Helper()
	line := "已激活条目：" + desktopLocalVaultQueryTitle
	nativeQueryAcceptanceWait(t, app, 5*time.Second, "NATIVE_QUERY_ACTIVE_LINE_MISSING", func() bool {
		tree, err := client.tree(window)
		if err != nil {
			return false
		}
		_, count := nativeQueryAcceptanceFindText(tree.Nodes, line)
		return count == 1
	})
}

func nativeQueryAcceptanceHasCleanSweep(app *App) bool {
	clean := false
	mygo.RunOnMain(func() {
		state := &app.localVaultFiles
		current := state.query.current
		clean = current != nil && state.query.sweep == nil && !current.nextSweep.IsZero() &&
			len(app.localVaultFileQueryHits()) == 2
	})
	return clean
}

func nativeQueryAcceptanceDrifted(app *App, rows nativeQueryAcceptanceRows) bool {
	drifted := false
	mygo.RunOnMain(func() {
		hits := app.localVaultFileQueryHits()
		drifted = len(hits) == 1 && hits[0] == rows.hitB &&
			app.localVaultFileQueryHitAuthorized(rows.hitB) &&
			app.localVaultFileQueryResultAuthorized(rows.hitB.result) &&
			app.localVaultFileQueryResultCurrent(rows.hitB.result) &&
			len(rows.hitB.result.proof.Hits) == 1 &&
			len(rows.hitA.result.proof.Hits) == 0
	})
	return drifted
}

func nativeQueryAcceptanceRunQuery(t *testing.T, app *App, client *nativeQueryAcceptanceAutomation, window int, windowTitle, aPath, bPath, aVaultID, bVaultID string) nativeQueryAcceptanceRows {
	t.Helper()
	nativeQueryAcceptanceWaitNode(t, app, client, window, 10*time.Second,
		"NATIVE_QUERY_EDITOR_MISSING", func(tree nativeQueryAcceptanceTree) (nativeQueryAcceptanceNode, bool) {
			node, count := nativeQueryAcceptanceFindKey(tree.Nodes, "local-vault-query")
			return node, count == 1
		})
	nativeQueryAcceptanceClickKey(t, app, client, window, windowTitle, "local-vault-query")
	nativeQueryAcceptanceWait(t, app, 5*time.Second, "NATIVE_QUERY_EDITOR_NOT_FOCUSED", func() bool {
		tree, err := client.tree(window)
		if err != nil {
			return false
		}
		node, count := nativeQueryAcceptanceFindKey(tree.Nodes, "local-vault-query")
		return count == 1 && tree.Focus == node.ID
	})
	nativeQueryAcceptanceType(t, client, window, windowTitle, desktopLocalVaultQueryTitle)
	nativeQueryAcceptanceWait(t, app, 10*time.Second, "NATIVE_QUERY_EDITOR_DID_NOT_ACCEPT_TITLE", func() bool {
		accepted := false
		mygo.RunOnMain(func() {
			accepted = app.localVaultFiles.query.title == desktopLocalVaultQueryTitle
		})
		if !accepted {
			return false
		}
		tree, err := client.tree(window)
		if err != nil {
			return false
		}
		node, count := nativeQueryAcceptanceFindKey(tree.Nodes, "local-vault-query")
		return count == 1 && node.Value == desktopLocalVaultQueryTitle
	})
	nativeQueryAcceptanceClickLabel(t, app, client, window, windowTitle, "精确查询独立文件库")
	nativeQueryAcceptanceWait(t, app, 20*time.Second, "NATIVE_QUERY_RESULTS_MISSING", func() bool {
		rows := nativeQueryAcceptanceReadRows(app, aPath, bPath, aVaultID, bVaultID)
		if rows.marker != "" {
			return false
		}
		tree, err := client.tree(window)
		if err != nil {
			return false
		}
		buttonA, countA := nativeQueryAcceptanceFindLabel(tree.Nodes,
			"激活到 "+rows.labelA+"："+desktopLocalVaultQueryTitle)
		buttonB, countB := nativeQueryAcceptanceFindLabel(tree.Nodes,
			"激活到 "+rows.labelB+"："+desktopLocalVaultQueryTitle)
		_, idA := nativeQueryAcceptanceFindText(tree.Nodes, "ID："+desktopLocalVaultQueryIDA)
		_, idB := nativeQueryAcceptanceFindText(tree.Nodes, "ID："+desktopLocalVaultQueryIDB)
		return countA == 1 && countB == 1 && idA == 1 && idB == 1 &&
			buttonA.ID != buttonB.ID
	})
	rows := nativeQueryAcceptanceReadRows(app, aPath, bPath, aVaultID, bVaultID)
	if rows.marker != "" {
		t.Fatal(rows.marker)
	}
	tree, err := client.tree(window)
	if err != nil {
		t.Fatal("NATIVE_QUERY_TARGET_TREE_FAILED")
	}
	nativeQueryAcceptanceRequireRows(t, tree, rows)
	return rows
}

func nativeQueryAcceptanceV2View(app *App) bool {
	enabled := false
	mygo.RunOnMain(func() {
		enabled = app.v2Mode && app.page == "vault"
	})
	return enabled
}

func TestDesktopLocalVaultExactQueryNativeWindow(t *testing.T) {
	if os.Getenv("LOCKLARK_NATIVE_SMOKE") != "1" {
		t.Skip("requires LOCKLARK_NATIVE_SMOKE=1 in a macOS desktop session")
	}
	if os.Getenv("MYGO_AUTOMATION") == "" {
		t.Fatal("NATIVE_QUERY_AUTOMATION_NOT_CONFIGURED")
	}

	fx := newDesktopLocalVaultQueryFixture(t)
	fx.queue.drain(t)
	app := fx.app
	if fx.f.parent.Unlocked() {
		t.Fatal("NATIVE_QUERY_OLD_SESSION_STILL_UNLOCKED")
	}
	adopted := false
	mygo.RunOnMain(func() {
		adopted = app.session != nil && app.session.Unlocked() &&
			len(app.localVaultFiles.refs) == 2 && len(app.localVaultFiles.sessionSlots) == 2
	})
	if !adopted {
		t.Fatal("NATIVE_QUERY_ADOPTION_FAILED")
	}
	if !nativeQueryAcceptanceV2View(app) {
		t.Fatal("NATIVE_QUERY_NORMAL_VIEW_UNAVAILABLE")
	}
	foreground := os.Getenv("LOCKLARK_NATIVE_FOREGROUND") == "1"

	var shell *plain.Shell
	var windowID int
	var windowTitle string
	mygo.RunOnMain(func() {
		app.onevra.shellActive = true
		shell = plain.NewShell(plain.ShellOptions{
			Title:         nativeQueryAcceptanceTitle,
			Width:         1240,
			Height:        820,
			MinWidth:      980,
			MinHeight:     680,
			Hidden:        true,
			Theme:         app.onevraTheme,
			HeaderLeading: app.onevraHeaderLeading,
			HeaderActions: app.onevraHeaderActions,
			Content:       app.View,
		})
		app.win = shell.Window()
		app.dispatch = app.win.Update
		app.launch = func(fn func()) { go fn() }
		windowID = app.win.ID()
		windowTitle = app.win.Title()
		if !foreground {
			// Present the real window off-screen; it still becomes the key
			// window so the ordinary editor receives native key and text events.
			app.win.SetPosition(-30000, -30000)
		}
		app.win.Show()
		app.win.Focus()
		app.win.Invalidate()
	})
	if shell == nil {
		t.Fatal("NATIVE_QUERY_SHELL_MISSING")
	}
	t.Cleanup(func() {
		mygo.RunOnMain(func() {
			app.cancelLocalVaultFileQuery()
			if app.win != nil {
				app.win.Hide()
				app.win.Destroy()
				app.win = nil
			}
		})
	})

	client := nativeQueryAcceptanceOpenAutomation(t)
	nativeQueryAcceptanceWait(t, app, 10*time.Second, "NATIVE_QUERY_TARGET_WINDOW_NOT_ISOLATED", func() bool {
		_, ok, err := client.isolatedWindow(windowID, windowTitle)
		return err == nil && ok
	})
	client.requireWindow(t, windowID, windowTitle)

	var refA, refB localVaultFileRef
	var labelA, labelB string
	mygo.RunOnMain(func() {
		var okA, okB bool
		refA, okA = localVaultFileRefByPath(app.localVaultFiles.refs, fx.aPath)
		refB, okB = localVaultFileRefByPath(app.localVaultFiles.refs, fx.bPath)
		if !okA || !okB {
			return
		}
		labelA = app.localVaultFileDisplayLabelFor(refA)
		labelB = app.localVaultFileDisplayLabelFor(refB)
	})
	if labelA == "" || labelB == "" || labelA == labelB {
		t.Fatal("NATIVE_QUERY_SIDEBAR_LABELS_MISSING")
	}

	keyA, keyB := nativeQueryAcceptanceLocalVaultKey(fx.aPath), nativeQueryAcceptanceLocalVaultKey(fx.bPath)
	nativeQueryAcceptanceWaitNode(t, app, client, windowID, 15*time.Second,
		"NATIVE_QUERY_SIDEBAR_MISSING", func(tree nativeQueryAcceptanceTree) (nativeQueryAcceptanceNode, bool) {
			node, countA := nativeQueryAcceptanceFindKey(tree.Nodes, keyA)
			_, countB := nativeQueryAcceptanceFindKey(tree.Nodes, keyB)
			return node, countA == 1 && countB == 1
		})
	nativeQueryAcceptanceClickKey(t, app, client, windowID, windowTitle, keyA)
	nativeQueryAcceptanceWait(t, app, 10*time.Second, "NATIVE_QUERY_NAVIGATION_FAILED", func() bool {
		selected := false
		mygo.RunOnMain(func() {
			selected = app.localVaultFiles.selected == fx.aPath
		})
		return selected
	})

	rows1 := nativeQueryAcceptanceRunQuery(t, app, client, windowID, windowTitle,
		fx.aPath, fx.bPath, fx.aManifest.VaultID, fx.bManifest.VaultID)
	nativeQueryAcceptanceClickLabel(t, app, client, windowID, windowTitle,
		"激活到 "+rows1.labelA+"："+desktopLocalVaultQueryTitle)
	nativeQueryAcceptanceWait(t, app, 10*time.Second, "NATIVE_QUERY_ACTIVATE_A_FAILED", func() bool {
		return nativeQueryAcceptanceActivation(app, fx.aPath, fx.aManifest.VaultID, desktopLocalVaultQueryIDA)
	})
	nativeQueryAcceptanceActivationLine(t, app, client, windowID)

	rows := nativeQueryAcceptanceRunQuery(t, app, client, windowID, windowTitle,
		fx.aPath, fx.bPath, fx.aManifest.VaultID, fx.bManifest.VaultID)
	nativeQueryAcceptanceWait(t, app, 15*time.Second, "NATIVE_QUERY_CLEAN_SWEEP_FAILED", func() bool {
		return nativeQueryAcceptanceHasCleanSweep(app)
	})
	desktopLocalVaultQueryDriftA(t, fx.aManifest)

	nativeQueryAcceptanceWait(t, app, 20*time.Second, "NATIVE_QUERY_DRIFT_SWEEP_FAILED", func() bool {
		return nativeQueryAcceptanceDrifted(app, rows)
	})
	nativeQueryAcceptanceWait(t, app, 10*time.Second, "NATIVE_QUERY_DRIFT_DISPLAY_FAILED", func() bool {
		tree, err := client.tree(windowID)
		if err != nil {
			return false
		}
		buttonB, countB := nativeQueryAcceptanceFindLabel(tree.Nodes,
			"激活到 "+rows.labelB+"："+desktopLocalVaultQueryTitle)
		_, idB := nativeQueryAcceptanceFindText(tree.Nodes, "ID："+desktopLocalVaultQueryIDB)
		_, staleA := nativeQueryAcceptanceFindLabel(tree.Nodes,
			"激活到 "+rows.labelA+"："+desktopLocalVaultQueryTitle)
		_, staleIDA := nativeQueryAcceptanceFindText(tree.Nodes, "ID："+desktopLocalVaultQueryIDA)
		return countB == 1 && idB == 1 && staleA == 0 && staleIDA == 0 && buttonB.ID != ""
	})
	nativeQueryAcceptanceClickLabel(t, app, client, windowID, windowTitle,
		"激活到 "+rows.labelB+"："+desktopLocalVaultQueryTitle)
	nativeQueryAcceptanceWait(t, app, 10*time.Second, "NATIVE_QUERY_ORIGINAL_B_ACTIVATION_FAILED", func() bool {
		return nativeQueryAcceptanceActivation(app, fx.bPath, fx.bManifest.VaultID, desktopLocalVaultQueryIDB)
	})
	nativeQueryAcceptanceActivationLine(t, app, client, windowID)

	t.Log("NATIVE_LOCAL_QUERY_ACCEPTANCE_OK rows=2 activated=2 drift=1")
}
