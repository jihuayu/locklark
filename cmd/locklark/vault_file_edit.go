package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/teamfiles"
	"github.com/jihuayu/locklark/internal/vaultfilesync"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	"golang.org/x/term"
)

// editPreparedVaultFile never puts item selectors or title values in output.
// The input is a bounded private file; both unlock factors use only the TTY.
func editPreparedVaultFile(out io.Writer, cfg vaultFileResumeConfig, pin vaultfile.PolicyCheckpoint, input []byte) (retErr error) {
	var request personal.VaultFileTitleRename
	if teamfiles.JSON(input, &request) != nil || request.ItemID == "" || request.ExpectedOldTitle == "" ||
		request.NewTitle == "" || request.NewTitle == request.ExpectedOldTitle {
		return errVaultFileInput
	}
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
	sealed, err := session.SealVaultFileTitleRename(cfg.Journal, &pin, request)
	if err != nil {
		switch {
		case errors.Is(err, personal.ErrVaultFileBaselineJournal):
			return errVaultFileJournal
		case errors.Is(err, personal.ErrVaultFileEditReview):
			return errVaultFileLocalReview
		default:
			return errVaultFileVerification
		}
	}
	defer clear(sealed.Sealed)
	defer clear(sealed.State.BaseBytes)
	defer clear(sealed.State.WorkingBytes)
	session.Lock()
	file, err := vaultfile.ParseFile(sealed.Sealed)
	if err != nil {
		return errVaultFileVerification
	}
	proposal := vaultfilejournal.Proposal{Generation: sealed.State.Generation, OperationID: file.Header.OpID,
		ExpectedRevision: sealed.State.RemoteRevision, Bytes: sealed.Sealed}
	if len(sealed.State.BaseBytes) == 0 || len(sealed.State.WorkingBytes) == 0 {
		return errVaultFileLocalReview
	}
	if bytes.Equal(sealed.State.BaseBytes, sealed.State.WorkingBytes) {
		proposal.Generation++
	}
	ctx := context.Background()
	verifier, err := vaultfilesync.NewContentProposalVerifier(&pin)
	if err != nil || verifier(ctx, sealed.State.BaseBytes, sealed.State.RemoteRevision, proposal) != nil {
		return errVaultFileVerification
	}
	j, err := vaultfilejournal.OpenExisting(cfg.Journal)
	if err != nil {
		return errVaultFileJournal
	}
	writeErr := j.PrepareWorkingIfState(sealed.State, proposal)
	closeErr := j.Close()
	if writeErr != nil {
		return vaultFileEditWriteError(writeErr)
	}
	if closeErr != nil {
		return errVaultFileLocalUnknown
	}
	restore()
	if resetErr != nil {
		return errVaultFileLocalUnknown
	}
	const receipt = "{\"status\":\"PREPARED\"}\n"
	if n, err := io.WriteString(out, receipt); err != nil || n != len(receipt) {
		return errVaultFileLocalUnknown
	}
	return nil
}

func vaultFileEditWriteError(err error) error {
	if errors.Is(err, vaultfilejournal.ErrStateMismatch) || errors.Is(err, vaultfilejournal.ErrPendingRecords) {
		return errVaultFileLocalReview
	}
	return vaultFileImportWriteError(err)
}
