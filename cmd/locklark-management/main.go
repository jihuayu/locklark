package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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

func run() error {
	var path, config, out, readConnection string
	flag.StringVar(&path, "directory", "", "fixed team directory file")
	flag.StringVar(&config, "config", "", "trusted public pins, policy and checkpoint JSON")
	flag.StringVar(&out, "connection", "", "new private broker connection JSON")
	flag.StringVar(&readConnection, "read-connection", "", "validate private connection for the Node launcher")
	flag.Parse()
	if readConnection != "" {
		if path != "" || config != "" || out != "" || flag.NArg() != 0 {
			return management.ErrUnavailable
		}
		c, e := management.ReadConnection(readConnection)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(c)
	}
	if path == "" || config == "" || out == "" || flag.NArg() != 0 {
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
	if management.WriteConnection(out, connection) != nil {
		return management.ErrUnavailable
	}
	// Remove only the exact record created by this process, not a replacement.
	defer func() {
		f, e := os.Open(out)
		if e != nil {
			return
		}
		b, e := io.ReadAll(io.LimitReader(f, 4097))
		f.Close()
		if e == nil && len(b) <= 4096 {
			defer clear(b)
			var current management.Connection
			if json.Unmarshal(b, &current) == nil && current == connection {
				os.Remove(out)
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
	fmt.Println("Verified read-only management service started. Use the private connection file with the Next.js application.")
	if e = server.Serve(listener); e != nil && e != http.ErrServerClosed {
		return e
	}
	return nil
}
func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "Management service could not start or verify its fixed configuration.")
		os.Exit(1)
	}
}
