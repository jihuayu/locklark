// Package management exposes an authenticated, read-only projection of an
// already verified team directory. It never holds a vault decryption key.
package management

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jihuayu/locklark/internal/directory"
)

var ErrUnavailable = errors.New("verified management state unavailable")

type Member struct {
	ID      string   `json:"id"`
	Role    string   `json:"role"`
	Devices []string `json:"devices"`
}
type Summary struct {
	Version    int                  `json:"version"`
	Mode       string               `json:"mode"`
	Checkpoint directory.Checkpoint `json:"checkpoint"`
	ObservedAt string               `json:"observedAt"`
	Freshness  string               `json:"freshness"`
	Members    []Member             `json:"members"`
}

// DirectoryReader captures trusted startup parameters. Request input never
// selects a filesystem path, pin, checkpoint, policy or output field.
func DirectoryReader(path string, cfg *directory.Config, anchor directory.Checkpoint) func() (Summary, error) {
	return func() (Summary, error) {
		view, e := directory.Read(path, cfg, anchor)
		if e != nil {
			return Summary{}, ErrUnavailable
		}
		out := Summary{Version: 1, Mode: view.Receipt.Proposal.Mode, Checkpoint: view.Receipt.Checkpoint(), ObservedAt: time.Now().UTC().Format(time.RFC3339), Freshness: "local-verified", Members: []Member{}}
		for _, member := range view.Receipt.Proposal.Members {
			row := Member{ID: member.ID, Role: member.Role, Devices: []string{}}
			for _, device := range member.Devices {
				row.Devices = append(row.Devices, device.ID)
			}
			out.Members = append(out.Members, row)
		}
		return out, nil
	}
}
func validToken(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func NewHandler(host, token string, read func() (Summary, error)) (http.Handler, error) {
	ip, port, e := net.SplitHostPort(host)
	if e != nil || ip != "127.0.0.1" || port == "" || !validToken(token) || read == nil {
		return nil, ErrUnavailable
	}
	active := make(chan struct{}, 1)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Referrer-Policy", "no-referrer")
		remote, _, e := net.SplitHostPort(r.RemoteAddr)
		_, hasOrigin := r.Header["Origin"]
		if e != nil || net.ParseIP(remote) == nil || !net.ParseIP(remote).IsLoopback() || r.Host != host || hasOrigin {
			http.Error(w, "forbidden", 403)
			return
		}
		auth := r.Header.Values("Authorization")
		if len(auth) != 1 || subtle.ConstantTimeCompare([]byte(auth[0]), []byte("Bearer "+token)) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		if r.Method != "GET" {
			http.Error(w, "method not allowed", 405)
			return
		}
		if r.URL.Path != "/v1/summary" || r.URL.RawQuery != "" || r.URL.RawPath != "" {
			http.NotFound(w, r)
			return
		}
		if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			http.Error(w, "body not allowed", 400)
			return
		}
		for _, name := range []string{"Forwarded", "X-Forwarded-Host", "X-Forwarded-For", "X-Forwarded-Proto"} {
			if strings.TrimSpace(r.Header.Get(name)) != "" {
				http.Error(w, "forbidden", 403)
				return
			}
		}
		select {
		case active <- struct{}{}:
			defer func() { <-active }()
		default:
			http.Error(w, "unavailable", 503)
			return
		}
		summary, e := read()
		if e != nil {
			http.Error(w, "verified state unavailable", 503)
			return
		}
		encoded, e := json.Marshal(summary)
		if e != nil || len(encoded) > 64<<10 {
			http.Error(w, "verified state unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(encoded)
	}), nil
}
