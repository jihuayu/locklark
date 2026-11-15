package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"golang.org/x/term"
)

const maxVaultFileBaselineOutput = 1 << 20

type vaultFileBaselineOutput struct {
	Status          string                           `json:"status"`
	RemoteFreshness string                           `json:"remote_freshness"`
	Items           []personal.VaultFileBaselineItem `json:"items"`
}

// openBaselineVaultFile reads both factors only from the controlling terminal.
// No factor or item value is accepted from argv, environment or configuration.
func openBaselineVaultFile(out io.Writer, cfg vaultFileResumeConfig, pin vaultfile.PolicyCheckpoint) (retErr error) {
	controlInput, controlOutput, err := openRunCLIConsole()
	if err != nil {
		return errVaultFileCancelled
	}
	defer controlInput.Close()
	if controlOutput != controlInput {
		defer controlOutput.Close()
	}
	fd := int(controlInput.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		return errVaultFileCancelled
	}
	var once sync.Once
	var resetErr error
	restore := func() { once.Do(func() { resetErr = term.Restore(fd, state) }) }
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)
	done := make(chan struct{})
	defer func() {
		close(done)
		restore()
		if retErr == nil && resetErr != nil {
			retErr = errVaultFileLocalUnknown
		}
	}()
	go func() {
		select {
		case <-signals:
			restore()
			os.Exit(130)
		case <-done:
		}
	}()
	c := console{reader: consoleByteReader{controlInput}, writer: controlOutput}
	password, err := c.field("主密码")
	if err != nil {
		return errVaultFileCancelled
	}
	defer clear(password)
	secretInput, err := c.field("Secret Key")
	if err != nil {
		return errVaultFileCancelled
	}
	key, err := personal.ParseSecret(string(secretInput))
	clear(secretInput)
	if err != nil {
		return errVaultFileVerification
	}
	defer clear(key)
	session, err := personal.UnlockSession(cfg.PersonalFile, password, key, time.Minute)
	if err != nil {
		return errVaultFileVerification
	}
	defer session.Lock()
	items, err := session.OpenVaultFileBaseline(cfg.Journal, &pin)
	if err != nil {
		if errors.Is(err, personal.ErrVaultFileBaselineJournal) {
			return errVaultFileJournal
		}
		return errVaultFileVerification
	}
	// The returned projection contains no key or item secret, and the active
	// session is locked before it is serialized to the output channel.
	session.Lock()
	restore()
	if resetErr != nil {
		return errVaultFileLocalUnknown
	}
	encoded, err := json.Marshal(vaultFileBaselineOutput{
		Status: "LOCAL_BASELINE", RemoteFreshness: "UNVERIFIED", Items: items,
	})
	if err != nil || len(encoded)+1 > maxVaultFileBaselineOutput {
		clear(encoded)
		return errVaultFileVerification
	}
	encoded = append(encoded, '\n')
	defer clear(encoded)
	n, err := out.Write(encoded)
	if err != nil || n != len(encoded) {
		return errVaultFileLocalUnknown
	}
	return nil
}
