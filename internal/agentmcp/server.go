// Package agentmcp serves an operator-launched stdio bridge. It never opens
// the holder's private directory and has no invocation or raw-read tool.
package agentmcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/jihuayu/locklark/internal/preview"
	proposer "github.com/jihuayu/locklark/plugins/github-pull-reader"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Config struct {
	Poll                preview.PollConfig
	Profile, Inbox, Bun string
}

func schema(props map[string]any, required ...string) map[string]any {
	return map[string]any{"type": "object", "properties": props, "required": required, "additionalProperties": false}
}
func args(raw []byte, allowed ...string) (map[string]json.RawMessage, bool) {
	if len(raw) > 4096 {
		return nil, false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	start, e := d.Token()
	if e != nil || start != json.Delim('{') {
		return nil, false
	}
	m := map[string]json.RawMessage{}
	for d.More() {
		tok, e := d.Token()
		k, ok := tok.(string)
		if e != nil || !ok || m[k] != nil {
			return nil, false
		}
		found := false
		for _, a := range allowed {
			if k == a {
				found = true
			}
		}
		if !found {
			return nil, false
		}
		var v json.RawMessage
		if d.Decode(&v) != nil {
			return nil, false
		}
		m[k] = v
	}
	end, e := d.Token()
	if e != nil || end != json.Delim('}') {
		return nil, false
	}
	_, e = d.Token()
	return m, e == io.EOF
}
func str(m map[string]json.RawMessage, key string) string {
	var s string
	_ = json.Unmarshal(m[key], &s)
	return s
}
func result(v any, e error) (*mcp.CallToolResult, error) {
	r := &mcp.CallToolResult{}
	msg := "tool call rejected"
	if e == nil {
		data, err := json.Marshal(v)
		if err == nil {
			msg = string(data)
		} else {
			e = err
		}
	}
	r.IsError = e != nil
	r.Content = []mcp.Content{&mcp.TextContent{Text: msg}}
	return r, nil
}

var rejected = errors.New("bridge unavailable")

func Serve(ctx context.Context, c Config) error {
	p, e := preview.LoadBridgeProfile(c.Profile, c.Poll)
	if !p.Scope.Current() {
		c.Bun = ""
	}
	if e != nil || (p.Scope.Current() && !filepath.IsAbs(c.Bun)) || !isolated(c) {
		return rejected
	}
	for _, dir := range []string{c.Poll.Private, c.Poll.Exchange, c.Inbox} {
		st, e := os.Stat(dir)
		if e != nil || !st.IsDir() {
			return rejected
		}
	}
	c.Poll.Session = p.Session
	ctx, cancel := context.WithDeadline(ctx, p.Expires)
	defer cancel()
	check := func() error {
		cur, e := preview.LoadBridgeProfile(c.Profile, c.Poll)
		if e != nil || cur.Scope != p.Scope || cur.Public != p.Public || cur.Audience != p.Audience || !time.Now().Before(p.Expires) {
			return rejected
		}
		return nil
	}
	s := mcp.NewServer(&mcp.Implementation{Name: "locklark", Version: "0.1-preview"}, nil)
	stringType := map[string]any{"type": "string"}
	repo := map[string]any{"type": "string", "enum": []string{p.Scope.Repo.ID}}
	if p.Scope.Current() {
		s.AddTool(&mcp.Tool{Name: "github_pulls_get", Description: "Request one recorded PR inspection for the enrolled repository. Reuse request_key after a lost response. Does not contact GitHub.", InputSchema: schema(map[string]any{"repo": repo, "number": map[string]any{"type": "integer", "minimum": 1, "maximum": 2147483647}, "reason": stringType, "request_key": map[string]any{"type": "string", "pattern": "^[0-9a-f]{32}$"}}, "repo", "number", "reason", "request_key")}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			m, ok := args(req.Params.Arguments, "repo", "number", "reason", "request_key")
			var n int
			if !ok || len(m) != 4 || str(m, "repo") != p.Scope.Repo.ID || json.Unmarshal(m["number"], &n) != nil || n < 1 || int64(n) > 2147483647 || check() != nil {
				return result(nil, rejected)
			}
			plan, e := proposer.Propose(ctx, c.Bun, p.Scope.Repo.ID, n)
			if e != nil {
				return result(nil, e)
			}
			return result(preview.SubmitBridgeAction(c.Poll, c.Inbox, p, str(m, "request_key"), str(m, "reason"), n, plan))
		})
	}
	s.AddTool(&mcp.Tool{Name: "locklark_resume", Description: "Start a read-only status challenge or read its dated, signed snapshot. A new challenge requests a fresh observation.", InputSchema: schema(map[string]any{"request_id": stringType, "review": stringType, "poll_id": stringType}, "request_id", "review")}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		m, ok := args(req.Params.Arguments, "request_id", "review", "poll_id")
		if !ok || check() != nil {
			return result(nil, rejected)
		}
		id, review, poll := str(m, "request_id"), str(m, "review"), str(m, "poll_id")
		if _, exists := m["poll_id"]; !exists {
			var e error
			poll, e = c.Poll.Start(id, review)
			if e != nil {
				return result(nil, e)
			}
		} else {
			status, e := c.Poll.Read(id, review, poll)
			if e != nil {
				return result(nil, e)
			}
			if status != nil {
				return result(status, nil)
			}
		}
		return result(map[string]string{"state": "awaiting-holder", "request_id": id, "poll_id": poll}, nil)
	})
	s.AddTool(&mcp.Tool{Name: "locklark_collect", Description: "Read the signed result already delivered to this session. Never executes an action.", InputSchema: schema(map[string]any{"request_id": stringType, "review": stringType}, "request_id", "review")}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		m, ok := args(req.Params.Arguments, "request_id", "review")
		if !ok || len(m) != 2 || check() != nil {
			return result(nil, rejected)
		}
		return result(preview.CollectBridgeResult(c.Poll, p, str(m, "request_id"), str(m, "review")))
	})
	return s.Run(ctx, &mcp.StdioTransport{MaxLineLength: 16 << 10})
}
