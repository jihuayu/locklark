package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/jihuayu/locklark/internal/directory"
	"github.com/jihuayu/locklark/internal/teamsync"
)

type clientPublic struct {
	Pins               directory.Pins
	URL, Roots, Anchor string
}
type clientIdentity struct {
	Signing ed25519.PrivateKey
	Device  directory.Device
}
type faultControl struct{ Mode, Replay string }
type captureWriter struct {
	*httptest.ResponseRecorder
	underlying http.ResponseWriter
}

func (w captureWriter) Unwrap() http.ResponseWriter { return w.underlying }

type failingAnchor struct{ teamsync.AnchorStore }
type controlledAnchor struct {
	teamsync.AnchorStore
	control string
}

func (a failingAnchor) Advance(_, _ directory.Checkpoint) error {
	return errors.New("injected anchor persistence failure")
}
func (a controlledAnchor) Advance(expected, next directory.Checkpoint) error {
	var fault faultControl
	jsonRead(a.control, &fault)
	if fault.Mode == "server-anchor-fail" && next.Version > expected.Version {
		return errors.New("injected server anchor persistence failure")
	}
	return a.AnchorStore.Advance(expected, next)
}

func classification(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, teamsync.ErrInvalid):
		return "invalid"
	case errors.Is(err, teamsync.ErrDenied):
		return "denied"
	case errors.Is(err, teamsync.ErrConflict):
		return "conflict"
	case errors.Is(err, teamsync.ErrCapacity):
		return "capacity"
	case errors.Is(err, teamsync.ErrFreshness):
		return "freshness"
	case errors.Is(err, teamsync.ErrAnchor):
		return "anchor"
	case errors.Is(err, teamsync.ErrUnknown):
		return "unknown"
	case errors.Is(err, teamsync.ErrClosed):
		return "closed"
	case errors.Is(err, teamsync.ErrTransport):
		return "transport"
	default:
		return "unclassified"
	}
}

func serveFixture(publicPath, captures, control, ready string) {
	var config serverPublic
	jsonRead(publicPath, &config)
	c := configuration(config.Pins)
	var identity clientIdentity
	must(json.NewDecoder(io.LimitReader(os.Stdin, 4096)).Decode(&identity))
	anchors, e := teamsync.OpenFileAnchorStore(config.Anchor)
	must(e)
	h, e := teamsync.NewHandler(config.Database, c, identity.Signing, c.Genesis(), controlledAnchor{anchors, control})
	must(e)
	clear(identity.Signing)
	pair, e := tls.LoadX509KeyPair(config.Certificate, config.TLSKey)
	must(e)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	must(e)
	var mu sync.Mutex
	sequence := 0
	wrapper := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sequence++
		index := sequence
		mu.Unlock()
		prefix := filepath.Join(captures, fmt.Sprintf("%06d", index))
		body, err := io.ReadAll(io.LimitReader(r.Body, 17<<20))
		must(err)
		must(r.Body.Close())
		r.Body = io.NopCloser(bytes.NewReader(body))
		must(os.WriteFile(prefix+".request", body, 0600))
		var fault faultControl
		jsonRead(control, &fault)
		isRead := r.URL.Path == "/v1/team-sync/read"
		isPublish := r.URL.Path == "/v1/team-sync/publish"
		drop := func() {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
		}
		if fault.Mode == "drop-before" && isPublish {
			jsonWrite(prefix+".meta", map[string]any{"path": r.URL.Path, "status": 0, "dropped": true})
			drop()
			return
		}
		recorder := httptest.NewRecorder()
		if fault.Mode == "replay" && isRead {
			raw, err := os.ReadFile(fault.Replay)
			must(err)
			recorder.Header().Set("Content-Type", "application/json")
			recorder.WriteHeader(http.StatusOK)
			_, err = recorder.Write(raw)
			must(err)
		} else {
			h.ServeHTTP(captureWriter{recorder, w}, r)
		}
		response := recorder.Body.Bytes()
		if fault.Mode == "tamper" && isRead {
			response = bytes.Clone(response)
			for i := len(response) - 1; i >= 0; i-- {
				if response[i] != '\n' && response[i] != ' ' {
					response[i] ^= 1
					break
				}
			}
		}
		must(os.WriteFile(prefix+".response", response, 0600))
		jsonWrite(prefix+".meta", map[string]any{"path": r.URL.Path, "status": recorder.Code, "dropped": fault.Mode == "drop-after" && isPublish})
		if fault.Mode == "drop-after" && isPublish {
			drop()
			return
		}
		for name, values := range recorder.Header() {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(recorder.Code)
		if fault.Mode == "delay" && isRead {
			w.(http.Flusher).Flush()
			time.Sleep(16 * time.Second)
		}
		_, _ = w.Write(response)
	})
	server := &http.Server{Handler: wrapper, ErrorLog: log.New(io.Discard, "", 0), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8192, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, NextProtos: []string{"http/1.1"}}}
	port := listener.Addr().(*net.TCPAddr).Port
	jsonWrite(ready, map[string]any{"URL": fmt.Sprintf("https://localhost:%d", port), "tls13": true, "pid": os.Getpid()})
	emit(map[string]any{"serving": true, "tls13": true})
	err := server.Serve(tls.NewListener(listener, server.TLSConfig))
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		panic("fixture server failed")
	}
}

func clientFixture(configPath, identityPath, operation, candidatePath, viewOut string, failAnchor, pretendOwner bool) {
	var config clientPublic
	jsonRead(configPath, &config)
	c := configuration(config.Pins)
	var identity clientIdentity
	jsonRead(identityPath, &identity)
	defer clear(identity.Signing)
	roots := x509.NewCertPool()
	cert, e := os.ReadFile(config.Roots)
	must(e)
	if !roots.AppendCertsFromPEM(cert) {
		panic("certificate root unavailable")
	}
	anchor, e := teamsync.OpenFileAnchorStore(config.Anchor)
	must(e)
	var store teamsync.AnchorStore = anchor
	if failAnchor {
		store = failingAnchor{anchor}
	}
	endpoint := teamsync.Endpoint{URL: config.URL, Roots: roots}
	var client *teamsync.Client
	if identity.Device.ID == "" || pretendOwner {
		client, e = teamsync.NewOwnerClient(c, endpoint, identity.Signing, store)
	} else {
		client, e = teamsync.NewDeviceClient(c, endpoint, identity.Device, identity.Signing, store)
	}
	if e != nil {
		emit(map[string]any{"status": classification(e), "success": false})
		return
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result := map[string]any{}
	switch operation {
	case "read":
		state, err := client.Fetch(ctx)
		e = err
		if e == nil {
			view := state.View()
			jsonWrite(viewOut, view)
			result["version"] = state.Checkpoint().Version
			result["history_length"] = len(state.History().Receipts)
		} else if !reflect.DeepEqual(state.View(), directory.View{}) || !reflect.DeepEqual(state.Checkpoint(), directory.Checkpoint{}) || len(state.History().Receipts) != 0 {
			panic("failed fetch returned success state")
		}
	case "publish":
		var candidate publication
		jsonRead(candidatePath, &candidate)
		receipt, err := client.Publish(ctx, candidate.Proposal, candidate.Snapshot)
		e = err
		if e == nil {
			result["version"] = receipt.Checkpoint().Version
		} else if !reflect.DeepEqual(receipt, directory.Receipt{}) {
			panic("failed publish returned receipt")
		}
	case "reconcile":
		var candidate publication
		jsonRead(candidatePath, &candidate)
		outcome, err := client.Reconcile(ctx, candidate.Proposal)
		e = err
		if e == nil {
			switch outcome.State {
			case teamsync.PublishCommitted:
				result["outcome"] = "committed"
			case teamsync.PublishConflicted:
				result["outcome"] = "conflicted"
			case teamsync.PublishUnknown:
				result["outcome"] = "unknown"
			default:
				panic("unknown reconciliation state")
			}
			result["version"] = outcome.Current.Version
		}
	default:
		panic("unknown client operation")
	}
	result["status"] = classification(e)
	result["success"] = e == nil
	emit(result)
}

func init() {
	transportCommand = func(command string, args []string) bool {
		if command != "serve" && command != "client" && command != "anchor-init" && command != "anchor-read" {
			return false
		}
		f := flag.NewFlagSet(command, flag.ContinueOnError)
		f.SetOutput(io.Discard)
		publicPath := f.String("public", "", "public server configuration")
		captures := f.String("captures", "", "private capture directory")
		control := f.String("control", "", "private fault file")
		ready := f.String("ready", "", "private readiness file")
		config := f.String("config", "", "public client configuration")
		identity := f.String("identity", "", "private synthetic identity")
		operation := f.String("operation", "read", "read, publish or reconcile")
		candidate := f.String("candidate", "", "private candidate file")
		view := f.String("view-out", "", "verified ciphertext view")
		anchorPath := f.String("anchor", "", "new anchor path")
		initial := f.String("initial", "", "independently trusted checkpoint")
		pinsPath := f.String("pins", "", "independently supplied bootstrap pins for Genesis")
		fail := f.Bool("anchor-fail", false, "inject durable advance failure")
		pretendOwner := f.Bool("pretend-owner", false, "attempt device as owner")
		must(f.Parse(args))
		if f.NArg() != 0 {
			panic("unexpected fixture argument")
		}
		switch command {
		case "serve":
			serveFixture(*publicPath, *captures, *control, *ready)
		case "client":
			clientFixture(*config, *identity, *operation, *candidate, *view, *fail, *pretendOwner)
		case "anchor-init":
			var cp directory.Checkpoint
			if *pinsPath != "" {
				var pins directory.Pins
				jsonRead(*pinsPath, &pins)
				cp = configuration(pins).Genesis()
			} else {
				jsonRead(*initial, &cp)
			}
			_, e := teamsync.CreateFileAnchorStore(*anchorPath, cp)
			must(e)
			emit(map[string]any{"initialized": true})
		case "anchor-read":
			store, e := teamsync.OpenFileAnchorStore(*anchorPath)
			must(e)
			cp, e := store.Load()
			must(e)
			emit(map[string]any{"version": cp.Version})
		}
		return true
	}
}
