package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"
)

// Read selected keys exactly once, without encoding/json's struct matching
// (case folding and last-wins merging). Ordinary unselected GitHub fields
// can be arbitrary JSON but never reach the caller.
func fields(raw []byte, names ...string) (map[string]json.RawMessage, bool) {
	d := json.NewDecoder(bytes.NewReader(raw))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return nil, false
	}
	out := make(map[string]json.RawMessage, len(names))
	for d.More() {
		k, err := d.Token()
		key, ok := k.(string)
		if err != nil || !ok {
			return nil, false
		}
		var val json.RawMessage
		if d.Decode(&val) != nil {
			return nil, false
		}
		for _, wanted := range names {
			if !strings.EqualFold(key, wanted) {
				continue
			}
			if key != wanted || out[wanted] != nil {
				return nil, false
			}
			out[wanted] = val
			break
		}
	}
	last, err := d.Token()
	if err != nil || last != json.Delim('}') || len(out) != len(names) {
		return nil, false
	}
	_, err = d.Token()
	return out, err == io.EOF
}

func project(raw []byte, t Target, key []byte) (PullResult, error) {
	var zero PullResult
	top, ok := fields(raw, "number", "state", "merged_at", "base")
	if !ok {
		return zero, errUpstream
	}
	base, ok := fields(top["base"], "repo")
	if !ok {
		return zero, errUpstream
	}
	repo, ok := fields(base["repo"], "id")
	if !ok || string(repo["id"]) != t.Repo || string(top["number"]) != strconv.Itoa(t.Number) {
		return zero, errUpstream
	}
	var result PullResult
	result.Number = t.Number
	if json.Unmarshal(top["state"], &result.State) != nil || (result.State != "open" && result.State != "closed") || json.Unmarshal(top["merged_at"], &result.MergedAt) != nil {
		return zero, errUpstream
	}
	if result.MergedAt != nil {
		tm, err := time.Parse(time.RFC3339, *result.MergedAt)
		if err != nil || tm.UTC().Format("2006-01-02T15:04:05Z") != *result.MergedAt || result.State != "closed" {
			return zero, errUpstream
		}
	}
	// Even a schema-valid value can be a verbatim echo of the actual slot.
	output, err := json.Marshal(result)
	if err != nil || bytes.Contains(output, key) {
		return zero, errUpstream
	}
	return result, nil
}
