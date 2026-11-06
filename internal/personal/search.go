package personal

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jihuayu/locklark/internal/vault"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

const searchAction = "item.search"
const searchProfile = "title-nfc-fold-substring-u17-v2"

var ErrSearchQuery = errors.New("invalid title search query or state scope")

type searchRequest struct{ query, state string }
type SearchReceipt struct {
	Status      string `json:"status"`
	Profile     string `json:"profile"`
	Scope       string `json:"scope"`
	Session     string `json:"session"`
	Event       string `json:"event"`
	QueryDigest string `json:"query_digest"`
	Rows        []Row  `json:"rows"`
}

// MarshalJSON preserves titles for JSON consumers while making Cc/Cf characters
// visible escapes in terminal output. Matching titles may contain the query;
// no separate raw query field is returned.
func (s SearchReceipt) MarshalJSON() ([]byte, error) {
	type plain SearchReceipt
	raw, e := json.Marshal(plain(s))
	if e != nil {
		return nil, e
	}
	return escapeJSONControls(raw), nil
}
func ValidSearchQuery(query string) bool {
	return len(query) > 0 && len(query) <= 256 && utf8.ValidString(query) && strings.TrimSpace(query) != "" && !strings.ContainsFunc(query, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) })
}
func (r *searchRequest) valid() bool {
	return r != nil && ValidSearchQuery(r.query) && ValidStateFilter(r.state)
}
func normalizedTitle(s string) string {
	return norm.NFC.String(cases.Fold().String(norm.NFC.String(s)))
}
func searchRows(items []vault.Item, revisions map[string]string, r searchRequest) ([]Row, error) {
	if !r.valid() {
		return nil, ErrSearchQuery
	}
	want := normalizedTitle(r.query)
	rows := []Row{}
	for _, it := range items {
		if it.Kind != "login" {
			continue
		}
		state := it.State
		if state == "" {
			state = "active"
		}
		if r.state != "all" && state != r.state {
			continue
		}
		if !strings.Contains(normalizedTitle(it.Title), want) {
			continue
		}
		if !idOK(it.ID) || !digestOK(revisions[it.ID]) {
			return nil, invalid
		}
		restore := ""
		if state == "trashed" {
			restore = "active"
			if it.PreviousState == "archived" {
				restore = "archived"
			}
		}
		rows = append(rows, Row{Kind: it.Kind, ID: it.ID, Title: it.Title, Revision: revisions[it.ID], State: state, RestoreState: restore})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	return rows, nil
}
func (r searchRequest) binding(secret []byte) (string, error) {
	key, e := hkdf.Key(sha256.New, secret, nil, "locklark/personal/search/key/v1", 32)
	if e != nil {
		return "", invalid
	}
	defer clear(key)
	raw, e := json.Marshal(struct{ Profile, Query, State string }{searchProfile, r.query, r.state})
	if e != nil {
		return "", invalid
	}
	defer clear(raw)
	mac := hmac.New(sha256.New, key)
	mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil)), nil
}
func Search(path, pw string, key []byte, query, state string) (SearchReceipt, error) {
	request := &searchRequest{query, state}
	if !request.valid() {
		return SearchReceipt{}, ErrSearchQuery
	}
	r, e := command(path, pw, key, searchAction, vault.Item{}, nil, commandOption{search: request})
	if e != nil {
		return SearchReceipt{}, e
	}
	return SearchReceipt{Status: "searched-titles", Profile: searchProfile, Scope: state, Session: r.session, Event: r.intent, QueryDigest: r.destinationDigest, Rows: r.rows}, nil
}
