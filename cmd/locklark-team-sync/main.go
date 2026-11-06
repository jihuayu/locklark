// locklark-team-sync runs a single fixed trusted sequencer over TLS. Device,
// owner and publisher private keys and plaintext items never enter this process.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/jihuayu/locklark/internal/directory"
	"github.com/jihuayu/locklark/internal/teamsync"
	"golang.org/x/term"
)

var errCommand = errors.New("team sync server refused; check trusted configuration, checkpoint, TLS files and hidden terminal input")

const usage = "usage: locklark-team-sync init-anchor|serve --config ABSOLUTE_CONFIG_FILE\nSequencer seed is accepted only in a hidden controlling-terminal prompt. No secret argv, environment, stdin or key-file fallback.\n"

type serverConfig struct {
	Pins        directory.Pins       `json:"pins"`
	Minimum     directory.Checkpoint `json:"minimum"`
	Directory   string               `json:"directory"`
	Anchor      string               `json:"anchor"`
	Listen      string               `json:"listen"`
	Certificate string               `json:"certificate"`
	TLSKey      string               `json:"tls_key"`
}

func main() {
	if e := run(os.Args[1:], os.Stdout); e != nil {
		fmt.Fprintln(os.Stderr, errCommand)
		os.Exit(1)
	}
}
func readConfig(path string) (serverConfig, *directory.Config, error) {
	var value serverConfig
	raw, e := readLocalFile(path, 16<<10, true)
	if e != nil || !utf8.Valid(raw) {
		return value, nil, errCommand
	}
	// Reject duplicate selectors and trailing values while allowing an operator
	// to format this independently trusted public configuration for readability.
	d := json.NewDecoder(bytes.NewReader(raw))
	nodes := 0
	var walk func(int) error
	walk = func(depth int) error {
		nodes++
		if nodes > 1024 || depth > 8 {
			return errCommand
		}
		token, e := d.Token()
		if e != nil {
			return errCommand
		}
		switch token {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				key, e := d.Token()
				s, ok := key.(string)
				if e != nil || !ok || seen[s] || len(seen) > 32 {
					return errCommand
				}
				seen[s] = true
				if walk(depth+1) != nil {
					return errCommand
				}
			}
			if token, e = d.Token(); e != nil || token != json.Delim('}') {
				return errCommand
			}
		case json.Delim('['):
			n := 0
			for d.More() {
				n++
				if n > 64 || walk(depth+1) != nil {
					return errCommand
				}
			}
			if token, e = d.Token(); e != nil || token != json.Delim(']') {
				return errCommand
			}
		}
		return nil
	}
	if walk(0) != nil {
		return value, nil, errCommand
	}
	if _, e = d.Token(); e != io.EOF {
		return value, nil, errCommand
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&value) != nil {
		return value, nil, errCommand
	}
	c, e := directory.NewConfigWithWriterACL(value.Pins)
	if e != nil || !c.ValidCheckpoint(value.Minimum) {
		return serverConfig{}, nil, errCommand
	}
	for _, p := range []string{value.Directory, value.Anchor, value.Certificate, value.TLSKey} {
		if !filepath.IsAbs(p) {
			return serverConfig{}, nil, errCommand
		}
	}
	if filepath.Clean(value.Directory) == filepath.Clean(value.Anchor) {
		return serverConfig{}, nil, errCommand
	}
	if _, _, e = net.SplitHostPort(value.Listen); e != nil {
		return serverConfig{}, nil, errCommand
	}
	return value, c, nil
}
func readSequencer() (ed25519.PrivateKey, error) {
	name := "/dev/tty"
	if runtime.GOOS == "windows" {
		name = "CONIN$"
	}
	console, e := os.OpenFile(name, os.O_RDWR, 0)
	if e != nil {
		return nil, errCommand
	}
	defer console.Close()
	output := io.Writer(console)
	if runtime.GOOS == "windows" {
		output = os.Stderr
	}
	return readSequencerTerminal(console, output)
}

func readSequencerTerminal(console *os.File, output io.Writer) (key ed25519.PrivateKey, err error) {
	if !term.IsTerminal(int(console.Fd())) {
		return nil, errCommand
	}
	ctx, stop := signal.NotifyContext(context.Background(), terminalSignals()...)
	defer stop()
	// Hide input before emitting any visible readiness/prompt signal. ReadPassword
	// would disable echo only after the prompt, exposing an immediate paste.
	state, e := term.MakeRaw(int(console.Fd()))
	if e != nil {
		return nil, errCommand
	}
	var restoreInput func() error
	defer func() {
		failed := false
		if restoreInput != nil && restoreInput() != nil {
			failed = true
		}
		if term.Restore(int(console.Fd()), state) != nil {
			failed = true
			// A failed restore never permits startup. Retry on the original FD,
			// then the same controlling terminal, without reading another secret.
			_ = term.Restore(int(console.Fd()), state)
			name := "/dev/tty"
			if runtime.GOOS == "windows" {
				name = "CONIN$"
			}
			if f, e := os.OpenFile(name, os.O_RDWR, 0); e == nil {
				_ = term.Restore(int(f.Fd()), state)
				_ = f.Close()
			}
		}
		if failed {
			clear(key)
			key = nil
			err = errCommand
		}
	}()
	read, restore, e := prepareTerminalInput(console)
	if e != nil {
		return nil, errCommand
	}
	restoreInput = restore
	if _, e = fmt.Fprint(output, "Sequencer signing seed (64 lowercase hex; hidden): "); e != nil {
		return nil, errCommand
	}
	defer fmt.Fprint(output, "\r\n")
	raw := make([]byte, 0, 64)
	defer clear(raw)
	for {
		ch, e := read(ctx)
		if e != nil {
			return nil, errCommand
		}
		switch ch {
		case '\r', '\n':
			if len(raw) != 64 {
				return nil, errCommand
			}
			seed := make([]byte, 32)
			defer clear(seed)
			if _, e = hex.Decode(seed, raw); e != nil {
				return nil, errCommand
			}
			return ed25519.NewKeyFromSeed(seed), nil
		case 3, 4, 27:
			return nil, errCommand
		case 8, 127:
			if len(raw) > 0 {
				raw[len(raw)-1] = 0
				raw = raw[:len(raw)-1]
			}
		default:
			if len(raw) >= 64 || !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
				return nil, errCommand
			}
			raw = append(raw, ch)
		}
	}
}
func run(args []string, out io.Writer) error {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "help") {
		_, e := io.WriteString(out, usage)
		return e
	}
	if len(args) < 1 || args[0] != "serve" && args[0] != "init-anchor" {
		return errCommand
	}
	f := flag.NewFlagSet("team-sync", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	configPath := f.String("config", "", "trusted public configuration")
	if f.Parse(args[1:]) != nil || f.NArg() != 0 || *configPath == "" {
		return errCommand
	}
	conf, c, e := readConfig(*configPath)
	if e != nil {
		return errCommand
	}
	if args[0] == "init-anchor" {
		if _, e := teamsync.CreateFileAnchorStore(conf.Anchor, conf.Minimum); e != nil {
			return errCommand
		}
		_, e = fmt.Fprintln(out, "Team sync server checkpoint initialized from the explicit trusted minimum.")
		return e
	}
	anchors, e := teamsync.OpenFileAnchorStore(conf.Anchor)
	if e != nil {
		return errCommand
	}
	cert, e := readLocalFile(conf.Certificate, 1<<20, false)
	if e != nil {
		return errCommand
	}
	key, e := readLocalFile(conf.TLSKey, 1<<20, true)
	if e != nil {
		return errCommand
	}
	defer clear(key)
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil {
		return errCommand
	}
	sequencer, e := readSequencer()
	if e != nil {
		return errCommand
	}
	defer clear(sequencer)
	h, e := teamsync.NewHandler(conf.Directory, c, sequencer, conf.Minimum, anchors)
	if e != nil {
		return errCommand
	}
	listener, e := net.Listen("tcp", conf.Listen)
	if e != nil {
		return errCommand
	}
	defer listener.Close()
	server := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10, ErrorLog: log.New(io.Discard, "", 0), TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, NextProtos: []string{"http/1.1"}}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- server.Serve(tls.NewListener(listener, tlsConfig)) }()
	if _, e = fmt.Fprintln(out, "Team sync HTTPS server ready."); e != nil {
		server.Close()
		return errCommand
	}
	select {
	case e = <-done:
		if !errors.Is(e, http.ErrServerClosed) {
			return errCommand
		}
		return nil
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
		_ = server.Close()
		return nil
	}
}
