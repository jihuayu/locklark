package browserhost

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
)

func lastNativeResponse(t *testing.T, out *memoryPipe) Response {
	t.Helper()
	all := out.responses(t)
	if len(all) == 0 {
		t.Fatal("missing native response")
	}
	return all[len(all)-1]
}

func expectNativeReply(t *testing.T, out *memoryPipe, id, kind string) Response {
	t.Helper()
	reply := lastNativeResponse(t, out)
	if reply.ID != id || reply.Type != kind {
		t.Fatalf("unexpected response: id=%q type=%q error=%q (want id=%q type=%q)", reply.ID, reply.Type, reply.Error, id, kind)
	}
	return reply
}

func expectRefused(t *testing.T, out *memoryPipe, id string) Response {
	t.Helper()
	reply := expectNativeReply(t, out, id, "error")
	if reply.Error != "refused" || reply.GeneratedPassword != "" || reply.Staged != nil {
		t.Fatalf("unexpected refusal shape: %+v", reply)
	}
	return reply
}

// pairedQuick is paired() with the explicit native quick-fill gesture. Tests
// that exercise V2 mutations use it so the V2 native gate is not the subject of
// the test; dedicated tests cover the non-quick path.
func pairedQuick(t *testing.T) (*Connection, *personal.Session, *memoryPipe, Request) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "quick.ll")
	key := bytes.Repeat([]byte{7}, 16)
	if e := personal.Create(path, "fixture", key); e != nil {
		t.Fatal(e)
	}
	s, e := personal.UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Lock)
	id, e := s.AddLogin("Host login", "fixture-user", "fixture-password")
	if e != nil {
		t.Fatal(e)
	}
	rows, e := s.List("active")
	if e != nil {
		t.Fatal(e)
	}
	rev, e := s.Edit(personal.Edit{ID: id, Revision: rows[0].Revision, Field: "url", Value: "https://example.test/login"})
	if e != nil {
		t.Fatal(e)
	}
	out := &memoryPipe{}
	c := NewConnection(NewWriter(out, time.Second), nil)
	if e = c.Handle(Request{V: 1, ID: reqID(1), Type: "hello"}); e != nil {
		t.Fatal(e)
	}
	if e = c.ApproveQuickPair(s); e != nil {
		t.Fatal(e)
	}
	cap := out.responses(t)[0].Capability
	return c, s, out, Request{V: 1, ID: reqID(2), Type: "match", Capability: cap, Origin: "https://example.test", TabID: 1, DocumentID: "doc-1", ItemID: "", Revision: rev}
}

func cleanupStagedConnection(t *testing.T, c *Connection) {
	t.Helper()
	t.Cleanup(func() {
		c.mu.Lock()
		c.clearStaged()
		c.mu.Unlock()
	})
}

func generateViaHost(t *testing.T, c *Connection, out *memoryPipe, capability, id, options string) Response {
	t.Helper()
	request := Request{V: 1, ID: id, Type: "generate", Capability: capability, Options: options}
	if err := c.Handle(request); err != nil {
		t.Fatalf("generate %q: %v", options, err)
	}
	reply := expectNativeReply(t, out, id, "generated")
	if reply.Profile == nil || reply.GeneratedPassword == "" {
		t.Fatalf("generate %q returned an incomplete response", options)
	}
	if !token.MatchString(reply.HistoryID) {
		t.Fatalf("generate %q returned invalid history id %q", options, reply.HistoryID)
	}
	return reply
}

func inMemorableWords(word string) bool {
	for _, candidate := range memorableWords {
		if candidate == word {
			return true
		}
	}
	return false
}

func validateMemorableWord(t *testing.T, word string, capitalize bool) string {
	t.Helper()
	base := strings.TrimRight(word, digitAlphabet)
	if base == "" || len(base) == len(word) && strings.ContainsAny(word, digitAlphabet) {
		t.Fatalf("malformed memorable word %q", word)
	}
	if capitalize {
		if base[0] < 'A' || base[0] > 'Z' || base[1:] != strings.ToLower(base[1:]) {
			t.Fatalf("word %q is not capitalized", word)
		}
		base = strings.ToLower(base)
	} else if base != strings.ToLower(base) {
		t.Fatalf("word %q unexpectedly capitalized", word)
	}
	if !inMemorableWords(base) {
		t.Fatalf("word %q is not in the local word list", word)
	}
	return base
}

func checkMemorablePassword(t *testing.T, password, separator string, length int, capitalize bool, wantAppended int) {
	t.Helper()
	parts := strings.Split(password, separator)
	if len(parts) != length {
		t.Fatalf("memorable password %q has %d parts, want %d", password, len(parts), length)
	}
	appended := 0
	for _, part := range parts {
		if trimmed := strings.TrimRight(part, digitAlphabet); trimmed != part {
			appended++
			digits := part[len(trimmed):]
			if len(digits) != 2 || digits[0] == '0' {
				t.Fatalf("memorable word %q has malformed numeric suffix", part)
			}
		}
		validateMemorableWord(t, part, capitalize)
	}
	if appended != wantAppended {
		t.Fatalf("memorable password %q appended %d numbers, want %d", password, appended, wantAppended)
	}
}

func checkNumericSeparatorPassword(t *testing.T, password string, length int, capitalize bool) {
	t.Helper()
	var words []string
	separators := 0
	for index := 0; index < len(password); {
		start := index
		for index < len(password) && (password[index] >= 'A' && password[index] <= 'Z' || password[index] >= 'a' && password[index] <= 'z') {
			index++
		}
		if index == start {
			t.Fatalf("numeric memorable password %q has adjacent or leading separators", password)
		}
		words = append(words, password[start:index])
		if index < len(password) {
			if password[index] < '0' || password[index] > '9' {
				t.Fatalf("numeric memorable password %q has a non-digit separator", password)
			}
			separators++
			index++
		}
	}
	if len(words) != length || separators != length-1 {
		t.Fatalf("numeric memorable password %q has %d words and %d separators", password, len(words), separators)
	}
	for _, word := range words {
		validateMemorableWord(t, word, capitalize)
	}
}

func checkRandomPassword(t *testing.T, password string, digits, symbols bool) {
	t.Helper()
	allowed := upperAlphabet + lowerAlphabet
	if digits {
		allowed += digitAlphabet
	}
	if symbols {
		allowed += symbolAlphabet
	}
	for _, r := range password {
		if !strings.ContainsRune(allowed, r) {
			t.Fatalf("random password contains disallowed character %q", r)
		}
	}
	if !strings.ContainsAny(password, upperAlphabet) || !strings.ContainsAny(password, lowerAlphabet) {
		t.Fatalf("random password %q is missing a letter class", password)
	}
	if got := strings.ContainsAny(password, digitAlphabet); got != digits {
		t.Fatalf("random password %q digits=%v, want %v", password, got, digits)
	}
	if got := strings.ContainsAny(password, symbolAlphabet); got != symbols {
		t.Fatalf("random password %q symbols=%v, want %v", password, got, symbols)
	}
}

func memorableLengthBounds(words int) (int, int) {
	shortest, longest := len(memorableWords[0]), len(memorableWords[0])
	for _, word := range memorableWords[1:] {
		if len(word) < shortest {
			shortest = len(word)
		}
		if len(word) > longest {
			longest = len(word)
		}
	}
	// Words are joined by one-character separators and at most one of them may
	// carry a two-digit numeric suffix when the digits option is enabled.
	return words*shortest + words - 1, words*longest + words - 1 + 2
}

func TestGenerateModesBoundsAndEntropy(t *testing.T) {
	c, _, out, r := pairedQuick(t)
	cases := []struct {
		name     string
		options  string
		mode     string
		length   int
		alphabet int
		entropy  int
		check    func(*testing.T, string)
	}{
		{
			name: "random-default", options: `{}`, mode: "random", length: 24, alphabet: 88, entropy: 155,
			check: func(t *testing.T, password string) { checkRandomPassword(t, password, true, true) },
		},
		{
			name: "random-minimum-bounds", options: `{"mode":"random","length":1,"digits":false,"symbols":false}`, mode: "random", length: 8, alphabet: 52, entropy: 45,
			check: func(t *testing.T, password string) { checkRandomPassword(t, password, false, false) },
		},
		{
			name: "random-maximum-bound", options: `{"mode":"random","length":999}`, mode: "random", length: 256, alphabet: 88, entropy: 1653,
			check: func(t *testing.T, password string) { checkRandomPassword(t, password, true, true) },
		},
		{
			name: "random-letters-only", options: `{"mode":"random","length":12,"digits":false,"symbols":false}`, mode: "random", length: 12, alphabet: 52, entropy: 68,
			check: func(t *testing.T, password string) { checkRandomPassword(t, password, false, false) },
		},
		{
			name: "memorable-default", options: `{"mode":"memorable"}`, mode: "memorable", length: 4, alphabet: 256, entropy: 32,
			check: func(t *testing.T, password string) { checkMemorablePassword(t, password, "-", 4, true, 0) },
		},
		{
			name: "memorable-minimum-bound", options: `{"mode":"memorable","length":0}`, mode: "memorable", length: 3, alphabet: 256, entropy: 24,
			check: func(t *testing.T, password string) { checkMemorablePassword(t, password, "-", 3, true, 0) },
		},
		{
			name: "memorable-maximum-bound", options: `{"mode":"memorable","length":11}`, mode: "memorable", length: 10, alphabet: 256, entropy: 80,
			check: func(t *testing.T, password string) { checkMemorablePassword(t, password, "-", 10, true, 0) },
		},
		{
			name: "memorable-spaces-lowercase", options: `{"mode":"memorable","length":5,"separator":"spaces","capitalize":false}`, mode: "memorable", length: 5, alphabet: 256, entropy: 40,
			check: func(t *testing.T, password string) { checkMemorablePassword(t, password, " ", 5, false, 0) },
		},
		{
			name: "memorable-numeric-separators", options: `{"mode":"memorable","length":4,"separator":"numbers"}`, mode: "memorable", length: 4, alphabet: 256, entropy: 32,
			check: func(t *testing.T, password string) { checkNumericSeparatorPassword(t, password, 4, true) },
		},
		{
			name: "memorable-appended-digit", options: `{"mode":"memorable","length":4,"digits":true}`, mode: "memorable", length: 4, alphabet: 256, entropy: 32,
			check: func(t *testing.T, password string) { checkMemorablePassword(t, password, "-", 4, true, 1) },
		},
		{
			name: "pin-default", options: `{"mode":"pin"}`, mode: "pin", length: 6, alphabet: 10, entropy: 19,
		},
		{
			name: "pin-minimum-bound", options: `{"mode":"pin","length":1}`, mode: "pin", length: 4, alphabet: 10, entropy: 13,
		},
		{
			name: "pin-maximum-bound", options: `{"mode":"pin","length":99}`, mode: "pin", length: 12, alphabet: 10, entropy: 39,
		},
	}
	history := map[string]bool{}
	for index, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			reply := generateViaHost(t, c, out, r.Capability, reqID(100+index), test.options)
			profile := reply.Profile
			if profile.Mode != test.mode || profile.Length != test.length || profile.AlphabetSize != test.alphabet || profile.EntropyBitsFloor != test.entropy {
				t.Fatalf("profile = %+v, want mode=%q length=%d alphabet=%d entropy=%d", *profile, test.mode, test.length, test.alphabet, test.entropy)
			}
			if test.mode == "memorable" {
				// Profile.Length is the word count for memorable passwords;
				// the character count also depends on the chosen words,
				// separators and optional numeric suffix.
				minimum, maximum := memorableLengthBounds(test.length)
				if got := len(reply.GeneratedPassword); got < minimum || got > maximum {
					t.Fatalf("generated length = %d, want %d..%d for %d memorable words", got, minimum, maximum, test.length)
				}
			} else if len(reply.GeneratedPassword) != test.length {
				t.Fatalf("generated length = %d, want %d", len(reply.GeneratedPassword), test.length)
			}
			if history[reply.HistoryID] {
				t.Fatalf("history id %q was reused", reply.HistoryID)
			}
			history[reply.HistoryID] = true
			if test.check != nil {
				test.check(t, reply.GeneratedPassword)
			}
			if test.mode == "pin" && strings.Trim(reply.GeneratedPassword, digitAlphabet) != "" {
				t.Fatalf("pin %q contains a non-digit", reply.GeneratedPassword)
			}
		})
	}
}

func TestGenerateInvalidOptionsRefused(t *testing.T) {
	c, _, out, r := pairedQuick(t)
	invalid := []string{
		`not-json`,
		`[]`,
		`null`,
		`{} {}`,
		`{"mode":"bogus"}`,
		`{"mode":"random","length":"24"}`,
		`{"mode":"random","digits":"yes"}`,
		`{"mode":1}`,
		`{"mode":"random","extra":true}`,
		`{"mode":"random","separator":"banana"}`,
		`{"mode":"pin","separator":"banana"}`,
		`{"mode":"memorable","capitalize":"yes"}`,
	}
	for index, raw := range invalid {
		if _, err := parseGenerateOptions(raw); !errors.Is(err, ErrGenerate) {
			t.Fatalf("parseGenerateOptions(%q) = %v, want ErrGenerate", raw, err)
		}
		id := reqID(140 + index)
		request := Request{V: 1, ID: id, Type: "generate", Capability: r.Capability, Options: raw}
		if err := c.Handle(request); err != nil {
			t.Fatalf("generate %q returned transport error %v", raw, err)
		}
		reply := expectRefused(t, out, id)
		if reply.HistoryID != "" || reply.Profile != nil {
			t.Fatalf("invalid generate %q leaked metadata", raw)
		}
	}
	for index, options := range []string{"", strings.Repeat("x", maxGenerateOpts+1), string([]byte{0xff})} {
		id := reqID(170 + index)
		request := Request{V: 1, ID: id, Type: "generate", Capability: r.Capability, Options: options}
		if err := c.Handle(request); !errors.Is(err, ErrProtocol) {
			t.Fatalf("generate options len=%d accepted: %v", len(options), err)
		}
	}
	extra := Request{V: 1, ID: reqID(180), Type: "generate", Capability: r.Capability, Options: `{}`, Origin: "https://example.test"}
	if extra.valid() {
		t.Fatal("generate accepted browser context")
	}
	if err := c.Handle(extra); !errors.Is(err, ErrProtocol) {
		t.Fatalf("generate with origin accepted: %v", err)
	}

	good := fmt.Sprintf(`{"v":1,"id":"%s","type":"generate","capability":"%s","options":"{}"}`, reqID(181), r.Capability)
	if _, err := ReadRequest(bytes.NewReader(frame(good))); err != nil {
		t.Fatalf("valid generate frame refused: %v", err)
	}
	for index, raw := range []string{
		fmt.Sprintf(`{"v":1,"id":"%s","type":"generate","capability":"%s"}`, reqID(182), r.Capability),
		fmt.Sprintf(`{"v":1,"id":"%s","type":"generate","capability":"%s","options":"{}","origin":"https://example.test"}`, reqID(183), r.Capability),
	} {
		if _, err := ReadRequest(bytes.NewReader(frame(raw))); err == nil {
			t.Fatalf("malformed generate frame %d accepted", index)
		}
	}
}

func stageSaveRequest(capability, id, mode, title, itemID, revision string) Request {
	return Request{
		V: 1, ID: id, Type: "stage-save", Capability: capability,
		Origin: "https://example.test", TabID: 1, DocumentID: "doc-1", WindowID: 1,
		Mode: mode, Title: title, ItemID: itemID, Revision: revision,
		payload: &savePayload{[]byte("staged-user"), []byte("staged-password")},
	}
}

func stageSaveViaHost(t *testing.T, c *Connection, out *memoryPipe, capability, id, mode, title, itemID, revision string) StagedSave {
	t.Helper()
	if err := c.Handle(stageSaveRequest(capability, id, mode, title, itemID, revision)); err != nil {
		t.Fatalf("stage-save: %v", err)
	}
	reply := expectNativeReply(t, out, id, "save-staged")
	if reply.Staged == nil {
		t.Fatal("stage-save returned no staged metadata")
	}
	return *reply.Staged
}

func pendingSaveRequest(capability, id, origin string, tabID int64) Request {
	return Request{
		V: 1, ID: id, Type: "pending-save", Capability: capability,
		Origin: origin, TabID: tabID, DocumentID: "doc-1",
	}
}

func pendingSaveViaHost(t *testing.T, c *Connection, out *memoryPipe, capability, id, origin string, tabID int64) Response {
	t.Helper()
	if err := c.Handle(pendingSaveRequest(capability, id, origin, tabID)); err != nil {
		t.Fatalf("pending-save: %v", err)
	}
	return expectNativeReply(t, out, id, "save-pending")
}

func commitStagedRequest(capability, id, stageID, mode, title, itemID, revision string) Request {
	return Request{
		V: 1, ID: id, Type: "commit-staged-save", Capability: capability, StageID: stageID,
		Origin: "https://example.test", TabID: 1, DocumentID: "doc-1", WindowID: 1,
		Mode: mode, Title: title, ItemID: itemID, Revision: revision,
	}
}

func dismissSaveRequest(capability, id, stageID string, never bool) Request {
	return Request{
		V: 1, ID: id, Type: "dismiss-save", Capability: capability,
		StageID: stageID, NeverForOrigin: never,
	}
}

func TestStagedSaveNewFlowPendingCommitAndDismiss(t *testing.T) {
	c, s, out, r := pairedQuick(t)
	cleanupStagedConnection(t, c)
	now := time.Now()
	c.now = func() time.Time { return now }
	const origin = "https://example.test"

	staged := stageSaveViaHost(t, c, out, r.Capability, reqID(200), "new", "Example login", "", "")
	if !token.MatchString(staged.StageID) || staged.Origin != origin || staged.Username != "staged-user" || staged.Title != "Example login" || staged.Mode != "new" || staged.ExistingItemID != "" || staged.ExistingRevision != "" {
		t.Fatalf("unexpected staged metadata: %+v", staged)
	}
	if want := now.Add(stagedSaveTTL).UnixMilli(); staged.ExpiresAt != want {
		t.Fatalf("staged expiry = %d, want %d", staged.ExpiresAt, want)
	}

	pending := pendingSaveViaHost(t, c, out, r.Capability, reqID(201), origin, 1)
	if pending.Staged == nil || pending.Staged.StageID != staged.StageID {
		t.Fatalf("pending-save did not return the staged request: %+v", pending.Staged)
	}

	if err := c.Handle(commitStagedRequest(r.Capability, reqID(202), staged.StageID, "new", "", "", "")); err != nil {
		t.Fatal(err)
	}
	commit := awaitTerminal(t, out, reqID(202))
	if commit.Type != "saved" || !token.MatchString(commit.ItemID) || !revision.MatchString(commit.Revision) {
		t.Fatalf("commit did not return a receipt: type=%q item=%q revision=%q error=%q", commit.Type, commit.ItemID, commit.Revision, commit.Error)
	}
	rows, err := s.List("active")
	if err != nil || len(rows) != 2 {
		t.Fatalf("saved rows = %d, err=%v", len(rows), err)
	}
	found := false
	for _, row := range rows {
		if row.ID == commit.ItemID && row.Revision == commit.Revision && row.Title == "Example login" {
			found = true
		}
	}
	if !found {
		t.Fatal("saved row receipt does not match the vault")
	}
	if len(c.staged) != 0 || c.stagedBusy {
		t.Fatal("commit retained staged private state")
	}
	if reply := pendingSaveViaHost(t, c, out, r.Capability, reqID(203), origin, 1); reply.Staged != nil {
		t.Fatal("pending-save returned committed metadata")
	}

	second := stageSaveViaHost(t, c, out, r.Capability, reqID(204), "new", "Second login", "", "")
	if err := c.Handle(dismissSaveRequest(r.Capability, reqID(205), second.StageID, true)); err != nil {
		t.Fatal(err)
	}
	dismissed := expectNativeReply(t, out, reqID(205), "save-dismissed")
	if len(dismissed.NeverOrigins) != 1 || dismissed.NeverOrigins[0] != origin {
		t.Fatalf("never-for-origin list = %v", dismissed.NeverOrigins)
	}
	if len(c.staged) != 0 {
		t.Fatal("dismiss retained staged private state")
	}
	if err := c.Handle(stageSaveRequest(r.Capability, reqID(206), "new", "Blocked login", "", "")); err != nil {
		t.Fatal(err)
	}
	expectRefused(t, out, reqID(206))
	if len(c.staged) != 0 {
		t.Fatal("never-for-origin did not block staging")
	}
}

func TestDismissWireAcceptsNeverForOriginBoolean(t *testing.T) {
	capability, stageID := reqID(260), reqID(261)
	for index, want := range []bool{false, true} {
		raw := fmt.Sprintf(`{"v":1,"id":"%s","type":"dismiss-save","capability":"%s","stage_id":"%s","never_for_origin":%t}`, reqID(262+index), capability, stageID, want)
		request, err := ReadRequest(bytes.NewReader(frame(raw)))
		if err != nil {
			t.Fatalf("dismiss never_for_origin=%v: %v", want, err)
		}
		if request.NeverForOrigin != want || request.StageID != stageID {
			t.Fatalf("decoded dismiss never_for_origin=%v stage=%q", request.NeverForOrigin, request.StageID)
		}
	}
	bad := fmt.Sprintf(`{"v":1,"id":"%s","type":"dismiss-save","capability":"%s","stage_id":"%s","never_for_origin":1}`, reqID(264), capability, stageID)
	if _, err := ReadRequest(bytes.NewReader(frame(bad))); err == nil {
		t.Fatal("numeric never_for_origin accepted")
	}
}

func TestStagedSaveUpdateCommitPreservesTitle(t *testing.T) {
	c, s, out, r := pairedQuick(t)
	cleanupStagedConnection(t, c)
	rows, err := s.List("active")
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows = %d, err=%v", len(rows), err)
	}
	row := rows[0]
	staged := stageSaveViaHost(t, c, out, r.Capability, reqID(270), "update", row.Title, row.ID, row.Revision)
	if staged.Mode != "update" || staged.ExistingItemID != row.ID || staged.ExistingRevision != row.Revision {
		t.Fatalf("unexpected update staged metadata: %+v", staged)
	}
	// The extension sends its display title on commit too. Update targets must
	// still reach SaveBrowser with an empty title so the existing one survives.
	if err := c.Handle(commitStagedRequest(r.Capability, reqID(271), staged.StageID, "update", "Replacement title", row.ID, row.Revision)); err != nil {
		t.Fatal(err)
	}
	commit := awaitTerminal(t, out, reqID(271))
	if commit.Type != "saved" || commit.ItemID != row.ID || !revision.MatchString(commit.Revision) || commit.Revision == row.Revision {
		t.Fatalf("update commit did not return a receipt: type=%q item=%q revision=%q error=%q", commit.Type, commit.ItemID, commit.Revision, commit.Error)
	}
	after, err := s.List("active")
	if err != nil || len(after) != 1 || after[0].ID != row.ID || after[0].Title != row.Title || after[0].Revision != commit.Revision {
		t.Fatalf("update changed title or rows: %+v, err=%v", after, err)
	}
	if len(c.staged) != 0 || c.stagedBusy {
		t.Fatal("update commit retained staged private state")
	}
}

func TestStagedSaveExpiryAndContextRefusals(t *testing.T) {
	c, _, out, r := pairedQuick(t)
	cleanupStagedConnection(t, c)
	now := time.Now()
	c.now = func() time.Time { return now }
	const origin = "https://example.test"

	staged := stageSaveViaHost(t, c, out, r.Capability, reqID(220), "new", "Expiring login", "", "")
	if reply := pendingSaveViaHost(t, c, out, r.Capability, reqID(221), origin, 2); reply.Staged != nil {
		t.Fatal("pending-save matched the wrong tab")
	}
	if reply := pendingSaveViaHost(t, c, out, r.Capability, reqID(222), origin, 1); reply.Staged == nil || reply.Staged.StageID != staged.StageID {
		t.Fatal("pending-save did not match the staged tab")
	}

	wrongOrigin := commitStagedRequest(r.Capability, reqID(223), staged.StageID, "new", "", "", "")
	wrongOrigin.Origin = "https://other.test"
	if err := c.Handle(wrongOrigin); err != nil {
		t.Fatal(err)
	}
	expectRefused(t, out, reqID(223))

	wrongTab := commitStagedRequest(r.Capability, reqID(224), staged.StageID, "new", "", "", "")
	wrongTab.TabID = 2
	if err := c.Handle(wrongTab); err != nil {
		t.Fatal(err)
	}
	expectRefused(t, out, reqID(224))

	wrongStage := commitStagedRequest(r.Capability, reqID(225), reqID(999), "new", "", "", "")
	if err := c.Handle(wrongStage); err != nil {
		t.Fatal(err)
	}
	expectRefused(t, out, reqID(225))

	if c.staged[staged.StageID] == nil {
		t.Fatal("wrong context refusals consumed the staged save")
	}

	now = now.Add(stagedSaveTTL + time.Second)
	if reply := pendingSaveViaHost(t, c, out, r.Capability, reqID(226), origin, 1); reply.Staged != nil {
		t.Fatal("expired staged save was still pending")
	}
	if len(c.staged) != 0 {
		t.Fatal("expired staged save retained private state")
	}
	if err := c.Handle(commitStagedRequest(r.Capability, reqID(227), staged.StageID, "new", "", "", "")); err != nil {
		t.Fatal(err)
	}
	expectRefused(t, out, reqID(227))
}

func TestStagedSaveUpdateItemRevisionValidation(t *testing.T) {
	c, s, out, r := pairedQuick(t)
	cleanupStagedConnection(t, c)
	rows, err := s.List("active")
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows = %d, err=%v", len(rows), err)
	}
	row := rows[0]
	staleRevision := strings.Repeat("0", 64)
	bad := stageSaveRequest(r.Capability, reqID(240), "update", row.Title, row.ID, staleRevision)
	if err := c.Handle(bad); err != nil {
		t.Fatal(err)
	}
	expectRefused(t, out, reqID(240))
	if len(c.staged) != 0 {
		t.Fatal("stale update revision was staged")
	}

	malformed := stageSaveRequest(r.Capability, reqID(241), "update", row.Title, row.ID, "not-a-revision")
	if err := c.Handle(malformed); !errors.Is(err, ErrProtocol) {
		t.Fatalf("malformed update revision accepted: %v", err)
	}
	if len(c.staged) != 0 {
		t.Fatal("malformed update revision was staged")
	}

	staged := stageSaveViaHost(t, c, out, r.Capability, reqID(242), "update", row.Title, row.ID, row.Revision)
	if staged.Mode != "update" || staged.ExistingItemID != row.ID || staged.ExistingRevision != row.Revision {
		t.Fatalf("unexpected update staged metadata: %+v", staged)
	}

	wrongItem := commitStagedRequest(r.Capability, reqID(243), staged.StageID, "update", "", reqID(998), row.Revision)
	if err := c.Handle(wrongItem); err != nil {
		t.Fatal(err)
	}
	expectRefused(t, out, reqID(243))

	wrongRevision := commitStagedRequest(r.Capability, reqID(244), staged.StageID, "update", "", row.ID, strings.Repeat("f", 64))
	if err := c.Handle(wrongRevision); err != nil {
		t.Fatal(err)
	}
	expectRefused(t, out, reqID(244))

	if c.staged[staged.StageID] == nil {
		t.Fatal("wrong update commit selectors consumed the staged save")
	}
	malformedCommit := commitStagedRequest(r.Capability, reqID(245), staged.StageID, "update", "", row.ID, "short")
	if err := c.Handle(malformedCommit); !errors.Is(err, ErrProtocol) {
		t.Fatalf("malformed commit revision accepted: %v", err)
	}
	if c.staged[staged.StageID] == nil {
		t.Fatal("protocol refusal consumed the staged save")
	}

	if err := c.Handle(dismissSaveRequest(r.Capability, reqID(246), staged.StageID, false)); err != nil {
		t.Fatal(err)
	}
	dismissed := expectNativeReply(t, out, reqID(246), "save-dismissed")
	if len(dismissed.NeverOrigins) != 0 || len(c.staged) != 0 {
		t.Fatal("normal dismiss retained state or never-origin entries")
	}
}
