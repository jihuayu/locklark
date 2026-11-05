package onepux

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func historyItem(id string, entries any) map[string]any {
	return map[string]any{"uuid": id, "categoryUuid": "001", "state": "active", "details": map[string]any{"passwordHistory": entries}}
}

func TestPasswordHistoryShapesOrderScopesAndPrivacy(t *testing.T) {
	entries := []any{
		map[string]any{"value": "private-old", "time": json.Number("9007199254740993")},
		map[string]any{"value": "private-old", "time": json.Number("9007199254740992")},
		map[string]any{"value": "", "time": json.Number("9007199254740992")},
		map[string]any{"value": "", "time": json.Number("9007199254740993")},
		map[string]any{"value": nil, "time": "private-time"},
		map[string]any{"value": []any{"private-array"}, "time": -1},
		map[string]any{"value": map[string]any{"private-key": "private-object"}, "time": 0},
		map[string]any{"value": json.Number("9007199254740993"), "time": json.Number("1e3")},
		map[string]any{"value": true, "time": nil},
		map[string]any{"time": json.Number("9223372036854775808"), "future": "private-extra"},
	}
	raw := pack(t, attributes, fileData(t, historyItem("i1", entries), historyItem("i2", entries)))
	before := append([]byte(nil), raw...)
	report, err := Inspect(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := PasswordHistoryReport{Entries: 20, Values: ShapeReport{Strings: 8, Null: 2, Arrays: 2, Objects: 2, Numbers: 2, Booleans: 2, Missing: 2}, Times: ShapeReport{Numbers: 16, Strings: 2, Null: 2}, IntegerTimes: 12, NegativeIntegerTimes: 2, OtherNumberTimes: 4, RepeatedStringValues: 4, RepeatedNumberTimes: 4, IncreasingAdjacentIntegerTimes: 4, EqualAdjacentIntegerTimes: 2, DecreasingAdjacentIntegerTimes: 2}
	if report.PasswordHistory != want {
		t.Fatal("history was normalized, merged or compared across gaps", report.PasswordHistory)
	}
	encoded, _ := json.Marshal(report)
	if strings.Contains(string(encoded), "private-") || strings.Contains(string(encoded), "9007199254740993") || !bytes.Equal(raw, before) || report.MappingVerified || report.UnmappedItems != 2 {
		t.Fatal("history privacy, immutability or mapping boundary failed")
	}
	for _, reason := range []string{"password-history-unmapped", "history-time-semantics-unverified", "history-value-missing", "history-value-not-string", "history-time-not-number", "history-other-number-time", "history-repeated-string-value", "history-repeated-number-time", "additional-metadata"} {
		if !contains(report.ReviewReasons, reason) {
			t.Fatal("missing history review reason", reason)
		}
	}
}

func TestPasswordHistoryRejectsMalformedAndBounds(t *testing.T) {
	for _, entries := range []any{nil, "private-container", []any{nil}, []any{true}, []any{[]any{}}} {
		refuse(t, pack(t, attributes, fileData(t, historyItem("valid", []any{map[string]any{"value": "private"}}), historyItem("bad", entries))), ErrInvalid)
	}
	entries := make([]any, MaxObjects)
	for i := range entries {
		entries[i] = map[string]any{}
	}
	if _, err := Inspect(pack(t, attributes, fileData(t, historyItem("i", entries)))); err != nil {
		t.Fatal("exact budget rejected", err)
	}
	refuse(t, pack(t, attributes, fileData(t, historyItem("i", append(entries, map[string]any{})))), ErrLimit)
	section := sectionItem("s", []any{map[string]any{"fields": []any{map[string]any{}}}})
	login := loginItem("l", []any{map[string]any{}})
	for _, items := range [][]map[string]any{{historyItem("h", entries[:MaxObjects-2]), section, login}, {section, login, historyItem("h", entries[:MaxObjects-2])}, {login, historyItem("h", entries[:MaxObjects-2]), section}} {
		refuse(t, pack(t, attributes, fileData(t, items...)), ErrLimit)
	}
	for _, items := range [][]map[string]any{{historyItem("h", entries[:MaxObjects-3]), section, login}, {section, login, historyItem("h", entries[:MaxObjects-3])}, {login, historyItem("h", entries[:MaxObjects-3]), section}} {
		if _, err := Inspect(pack(t, attributes, fileData(t, items...))); err != nil {
			t.Fatal("mixed exact budget rejected", err)
		}
		items = append(items, historyItem("extra", []any{map[string]any{}}))
		refuse(t, pack(t, attributes, fileData(t, items...)), ErrLimit)
	}
}

func TestPasswordHistoryEveryNonintegerBreaksAdjacency(t *testing.T) {
	for _, middle := range []map[string]any{{}, {"time": nil}, {"time": "0"}, {"time": false}, {"time": []any{}}, {"time": map[string]any{}}, {"time": json.Number("1.0")}, {"time": json.Number("1e0")}, {"time": json.Number("9223372036854775808")}} {
		entries := []any{map[string]any{"value": "private-case", "time": 1}, middle, map[string]any{"value": "PRIVATE-CASE", "time": 1}}
		report, err := Inspect(pack(t, attributes, fileData(t, historyItem("i", entries))))
		if err != nil {
			t.Fatal(err)
		}
		r := report.PasswordHistory
		if r.IncreasingAdjacentIntegerTimes+r.EqualAdjacentIntegerTimes+r.DecreasingAdjacentIntegerTimes != 0 || r.RepeatedNumberTimes != 1 || r.RepeatedStringValues != 0 {
			t.Fatal("comparison skipped a gap or literal strings were folded", r)
		}
	}
	// Maps and adjacency state reset even when the last and first timestamps
	// of neighboring items would compare as equal.
	entry := []any{map[string]any{"value": "private", "time": 1}}
	report, err := Inspect(pack(t, attributes, fileData(t, historyItem("a", entry), historyItem("b", entry))))
	if err != nil || report.PasswordHistory.RepeatedStringValues != 0 || report.PasswordHistory.RepeatedNumberTimes != 0 || report.PasswordHistory.EqualAdjacentIntegerTimes != 0 {
		t.Fatal("history state escaped item scope", err)
	}
}

func TestPasswordHistoryLiteralTimesAndMissing(t *testing.T) {
	entries := []any{}
	for _, v := range []any{json.Number("-9223372036854775808"), json.Number("9223372036854775807"), json.Number("-0"), json.Number("0"), json.Number("0.0"), json.Number("0e0"), json.Number("0.0"), json.Number("1e9999"), json.Number("-9223372036854775809"), []any{"private"}, map[string]any{"x": "private"}, false} {
		entries = append(entries, map[string]any{"time": v})
	}
	entries = append(entries, map[string]any{})
	report, err := Inspect(pack(t, attributes, fileData(t, historyItem("i", entries))))
	if err != nil {
		t.Fatal(err)
	}
	r := report.PasswordHistory
	if r.Entries != 13 || r.IntegerTimes != 4 || r.NegativeIntegerTimes != 1 || r.OtherNumberTimes != 5 || r.RepeatedNumberTimes != 1 || r.IncreasingAdjacentIntegerTimes != 1 || r.DecreasingAdjacentIntegerTimes != 1 || r.EqualAdjacentIntegerTimes != 1 || r.Times != (ShapeReport{Numbers: 9, Arrays: 1, Objects: 1, Booleans: 1, Missing: 1}) || r.Values.Missing != 13 {
		t.Fatal("time precision/lexical/gap classification changed", r)
	}
	for _, item := range []map[string]any{historyItem("i", []any{}), sectionItem("i", []any{})} {
		report, err := Inspect(pack(t, attributes, fileData(t, item)))
		if err != nil || report.PasswordHistory != (PasswordHistoryReport{}) || contains(report.ReviewReasons, "password-history-unmapped") {
			t.Fatal("empty/missing history invented records", err)
		}
	}
}

func FuzzPasswordHistory(f *testing.F) {
	f.Add([]byte(`[{"value":"private-old","time":9007199254740993},{"time":9007199254740992}]`))
	f.Add([]byte(`[{}, {"time":1e9999,"value":null}]`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 65536 {
			return
		}
		data := `{"accounts":[{"attrs":{"uuid":"a"},"vaults":[{"attrs":{"uuid":"v"},"items":[{"uuid":"i","categoryUuid":"001","state":"active","details":{"passwordHistory":` + string(raw) + `}}]}]}]}`
		report, err := Inspect(pack(t, attributes, data))
		if err != nil {
			if !reflect.DeepEqual(report, Report{}) {
				t.Fatal("partial history report")
			}
			return
		}
		r := report.PasswordHistory
		for _, s := range []ShapeReport{r.Values, r.Times} {
			if s.Missing+s.Null+s.Objects+s.Arrays+s.Strings+s.Numbers+s.Booleans != r.Entries {
				t.Fatal("history shapes lost entries")
			}
		}
		if r.IntegerTimes+r.OtherNumberTimes != r.Times.Numbers || r.NegativeIntegerTimes > r.IntegerTimes || r.RepeatedNumberTimes > r.Times.Numbers || r.RepeatedStringValues > r.Values.Strings || r.IncreasingAdjacentIntegerTimes+r.EqualAdjacentIntegerTimes+r.DecreasingAdjacentIntegerTimes > max(0, r.IntegerTimes-1) || r.Entries > MaxObjects || report.MappingVerified {
			t.Fatal("invalid history invariants")
		}
	})
}
