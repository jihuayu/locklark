package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/jihuayu/locklark/internal/management"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const managementUsage = `Locklark Management — Verified read-only directory broker for the web console

USAGE
  locklark-management --directory FILE --config TRUSTED_JSON --connection NEW_JSON
  locklark-management --read-connection PRIVATE_JSON
  locklark-management --help | -h | help

MODES
  Serve Broker     Verify the pinned directory checkpoint, bind a loopback HTTP
                   listener (127.0.0.1:0), and write a new owner-only connection
                   record for the Next.js web launcher.
  Read Connection  Validate an existing owner-only connection record and emit it
                   as JSON on stdout (--read-connection).

FLAGS
  --directory FILE          Path to the encrypted team directory file
  --config TRUSTED_JSON     Trusted public pins, policy, and checkpoint JSON
  --connection NEW_JSON     New owner-only output path for the loopback broker token
  --read-connection FILE    Validate a private connection JSON file (standalone mode)

NOTES
  - Listens strictly on 127.0.0.1 with an ephemeral bearer token; never exposes
    private keys or plaintext vault items.
`

func run(args []string, out io.Writer) error {
	if len(args) == 1 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h") {
		_, e := io.WriteString(out, managementUsage)
		return e
	}
	var path, config, connectionOut, readConnection string
	f := flag.NewFlagSet("locklark-management", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&path, "directory", "", "fixed team directory file")
	f.StringVar(&config, "config", "", "trusted public pins, policy, and checkpoint JSON")
	f.StringVar(&connectionOut, "connection", "", "new private broker connection JSON")
	f.StringVar(&readConnection, "read-connection", "", "validate private connection for the Node launcher")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, e := io.WriteString(out, managementUsage)
			return e
		}
		return management.ErrUnavailable
	}
	if readConnection != "" {
		if path != "" || config != "" || connectionOut != "" || f.NArg() != 0 {
			return management.ErrUnavailable
		}
		c, e := management.ReadConnection(readConnection)
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(c)
	}
	if path == "" || config == "" || connectionOut == "" || f.NArg() != 0 {
		return management.ErrUnavailable
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cfg, anchor, e := management.LoadConfiguration(config)
	if e != nil {
		return e
	}
	read := management.DirectoryReader(path, cfg, anchor)
	if _, e = read(); e != nil {
		return e
	}
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		return e
	}
	defer listener.Close()
	raw := make([]byte, 32)
	if _, e = rand.Read(raw); e != nil {
		return e
	}
	token := hex.EncodeToString(raw)
	clear(raw)
	h, e := management.NewHandler(listener.Addr().String(), token, read)
	if e != nil {
		return e
	}
	connection := management.Connection{Version: 1, URL: "http://" + listener.Addr().String(), Token: token}
	if management.WriteConnection(connectionOut, connection) != nil {
		return management.ErrUnavailable
	}
	// Remove only the exact record created by this process, not a replacement.
	defer func() {
		file, e := os.Open(connectionOut)
		if e != nil {
			return
		}
		b, e := io.ReadAll(io.LimitReader(file, 4097))
		file.Close()
		if e == nil && len(b) <= 4096 {
			defer clear(b)
			var current management.Connection
			if json.Unmarshal(b, &current) == nil && current == connection {
				os.Remove(connectionOut)
			}
		}
	}()
	server := &http.Server{Handler: h, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 4096}
	go func() {
		<-ctx.Done()
		closeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		server.Shutdown(closeCtx)
	}()
	fmt.Fprintln(out, "Verified read-only management service started. Pass the private connection file to the Next.js console.")
	if e = server.Serve(listener); e != nil && e != http.ErrServerClosed {
		return e
	}
	return nil
}

func main() {
	if run(os.Args[1:], os.Stdout) != nil {
		fmt.Fprintln(os.Stderr, "locklark-management: service refused; verify --directory, --config, and --connection paths (see --help).")
		os.Exit(1)
	}
}
