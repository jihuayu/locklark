package management

import (
	"encoding/json"
	"github.com/jihuayu/locklark/internal/directory"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
)

type Configuration struct {
	Pins   directory.Pins       `json:"pins"`
	Anchor directory.Checkpoint `json:"anchor"`
	Policy string               `json:"policy"`
}
type Connection struct {
	Version int    `json:"version"`
	URL     string `json:"url"`
	Token   string `json:"token"`
}

func LoadConfiguration(path string) (*directory.Config, directory.Checkpoint, error) {
	f, e := openTrustedConfiguration(path)
	if e != nil {
		return nil, directory.Checkpoint{}, ErrUnavailable
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(f, 64<<10+1))
	if e != nil || len(raw) > 64<<10 {
		return nil, directory.Checkpoint{}, ErrUnavailable
	}
	var c Configuration
	if json.Unmarshal(raw, &c) != nil {
		return nil, directory.Checkpoint{}, ErrUnavailable
	}
	var cfg *directory.Config
	switch c.Policy {
	case "writer-acl-v1":
		cfg, e = directory.NewConfigWithWriterACL(c.Pins)
	case "possession-v1":
		cfg, e = directory.NewConfigWithPossession(c.Pins)
	case "owner-v1":
		cfg, e = directory.NewConfig(c.Pins)
	default:
		return nil, directory.Checkpoint{}, ErrUnavailable
	}
	if e != nil || c.Anchor.Scope != cfg.Genesis().Scope {
		return nil, directory.Checkpoint{}, ErrUnavailable
	}
	return cfg, c.Anchor, nil
}
func WriteConnection(path string, c Connection) error {
	if !validToken(c.Token) || c.Version != 1 || trustedConnectionParent(path) != nil {
		return ErrUnavailable
	}
	raw, e := json.Marshal(c)
	if e != nil {
		return ErrUnavailable
	}
	defer clear(raw)
	f, e := createConnection(path)
	if e != nil {
		return ErrUnavailable
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(path)
		}
	}()
	if n, e := f.Write(raw); e != nil || n != len(raw) {
		return ErrUnavailable
	}
	if f.Sync() != nil {
		return ErrUnavailable
	}
	if f.Close() != nil {
		return ErrUnavailable
	}
	ok = true
	return nil
}

// ReadConnection is used by the Node launcher through a private child stdout
// pipe, so Windows owner/DACL validation is shared with the native publisher.
func ReadConnection(path string) (Connection, error) {
	f, e := openTrustedConfiguration(path)
	if e != nil {
		return Connection{}, ErrUnavailable
	}
	defer f.Close()
	if privateConnectionFile(f) != nil {
		return Connection{}, ErrUnavailable
	}
	raw, e := io.ReadAll(io.LimitReader(f, 4097))
	defer clear(raw)
	var c Connection
	if e != nil || len(raw) > 4096 || json.Unmarshal(raw, &c) != nil || c.Version != 1 || !validToken(c.Token) {
		return Connection{}, ErrUnavailable
	}
	u, e := url.Parse(c.URL)
	if e != nil || u.Scheme != "http" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return Connection{}, ErrUnavailable
	}
	host, port, e := net.SplitHostPort(u.Host)
	number, numberErr := strconv.Atoi(port)
	if e != nil || numberErr != nil || host != "127.0.0.1" || number < 1 || number > 65535 || strconv.Itoa(number) != port {
		return Connection{}, ErrUnavailable
	}
	return c, nil
}
