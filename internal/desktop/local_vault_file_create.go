package desktop

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"path/filepath"
	"sync"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/teamfiles"
	"github.com/jihuayu/locklark/internal/vaultfileclient"
	oneui "github.com/oneo-me/onevra/source/components"
)

// A recovery code exists here only while its native confirmation is visible.
// Strings in Go are not physically erasable; no factor or kit is persisted in
// settings, a catalog, arguments or a background context.
type localVaultFileCreateState struct {
	open, busy bool
	phase      string
	configPath string
	// scope is the validated public create scope captured by Prepare. Complete
	// freezes it before launch; it never contains a factor or key.
	scope localVaultFileSessionScope
	// child is the exact reserved C1 operation owned by this creation attempt.
	// It holds no factors; cancellation of creation cancels this exact op only.
	child    *localVaultFileSessionOperation
	password string
	secret   string
	kit      string
	confirm  string
	issued   string
	backup   *personal.BackupPreparation
	publish  *localVaultFilePublishGate
	status   string
	sequence uint64
	cancel   context.CancelFunc
}

// localVaultFilePublishGate is the one-shot start/cancel boundary for a queued
// backup publish. Cancel before start closes the unpublished preparation and
// no Publish call follows. Once start wins, cancel never closes or rolls back
// the preparation; the worker completes Publish and only late result delivery
// is rejected.
type localVaultFilePublishGate struct {
	mu       sync.Mutex
	backup   *personal.BackupPreparation
	started  bool
	canceled bool
}

func (g *localVaultFilePublishGate) start() (*personal.BackupPreparation, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.started || g.canceled || g.backup == nil {
		return nil, false
	}
	g.started = true
	return g.backup, true
}

func (g *localVaultFilePublishGate) cancel() {
	g.mu.Lock()
	g.canceled = true
	backup, started := g.backup, g.started
	if !started {
		g.backup = nil
	}
	g.mu.Unlock()
	if !started && backup != nil {
		backup.Close()
	}
}

func (a *App) openLocalVaultFileCreate(configPath string) {
	if a.session == nil || !a.session.Unlocked() {
		return
	}
	a.cancelLocalVaultFileCreate()
	a.localCreate.open = true
	a.localCreate.phase = "prepare"
	a.localCreate.configPath = configPath
	a.localCreate.status = "请完整验证本机身份"
}

func (a *App) cancelLocalVaultFileCreate() {
	state := &a.localCreate
	state.sequence++
	if state.publish != nil {
		state.publish.cancel()
	}
	if state.cancel != nil {
		state.cancel()
	}
	child := state.child
	state.child = nil
	if child != nil {
		a.cancelLocalVaultFileSessionOperationExact(child)
	}
	if state.backup != nil {
		state.backup.Close()
	}
	sequence := state.sequence
	*state = localVaultFileCreateState{sequence: sequence}
}

func ensureLocalVaultFileWorkspace(settingsPath, personalPath string) (profileDir, backendRoot string, err error) {
	if settingsPath == "" || !filepath.IsAbs(settingsPath) || filepath.Clean(settingsPath) != settingsPath {
		return "", "", vaultfileclient.ErrLocalReview
	}
	profileDir, backendRoot = localVaultFilePaths(settingsPath, personalPath)
	settingsDir := filepath.Dir(settingsPath)
	base := filepath.Dir(filepath.Dir(profileDir))
	for _, path := range []string{settingsDir, base, filepath.Join(base, "profiles"), profileDir, backendRoot} {
		if teamfiles.EnsurePrivateWorkspace(path) != nil {
			return "", "", vaultfileclient.ErrLocalReview
		}
	}
	return profileDir, backendRoot, nil
}

// boundLocalVaultFileManifest is the strict resume/completion entry binding.
// It reads and authenticates the existing manifest before any CreationContext,
// ownership write or publish, and accepts it only for this session's personal
// file and unified workspace backend. The returned empty-VaultID template is
// passed to OpenCreation so EnsureCreateManifest re-checks the exact fields.
func boundLocalVaultFileManifest(configPath, personalPath, backendRoot string) (vaultfileclient.Manifest, error) {
	manifest, exists, err := vaultfileclient.ReadManifest(configPath)
	if err != nil || !exists || manifest.PersonalFile != personalPath || manifest.BackendRoot != backendRoot {
		return vaultfileclient.Manifest{}, vaultfileclient.ErrLocalReview
	}
	manifest.VaultID = ""
	if !vaultfileclient.ValidManifestPhase(configPath, manifest, false, false) {
		return vaultfileclient.Manifest{}, vaultfileclient.ErrLocalReview
	}
	return manifest, nil
}

func newLocalVaultFileProposal(profileDir, backendRoot, personalPath string) (string, vaultfileclient.Manifest, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", vaultfileclient.Manifest{}, vaultfileclient.ErrLocalUnknown
	}
	selector := hex.EncodeToString(random[:])
	return filepath.Join(profileDir, selector+".json"), vaultfileclient.Manifest{
		Version: 1, Kind: vaultfileclient.CreateKind, PersonalFile: personalPath,
		BackendRoot: backendRoot, Name: selector + ".llv",
		Journal: filepath.Join(profileDir, selector+".journal"),
		Archive: filepath.Join(profileDir, selector+".llb"),
	}, nil
}

func (a *App) localCreatePrepare() {
	state := &a.localCreate
	if !state.open || state.busy || state.phase != "prepare" || a.session == nil {
		return
	}
	password, secret := []byte(state.password), []byte(state.secret)
	state.password, state.secret = "", ""
	state.busy = true
	state.status = "正在准备独立文件库"
	state.sequence++
	sequence, generation, session := state.sequence, a.generation, a.session
	configPath := state.configPath
	settingsPath := a.settingsPath
	ctx, cancel := context.WithCancel(context.Background())
	state.cancel = cancel
	a.launch(func() {
		defer clear(password)
		defer clear(secret)
		profileDir, backendRoot, err := ensureLocalVaultFileWorkspace(settingsPath, session.VaultPath())
		var proposal *vaultfileclient.Manifest
		if err == nil && configPath == "" {
			var initial vaultfileclient.Manifest
			configPath, initial, err = newLocalVaultFileProposal(profileDir, backendRoot, session.VaultPath())
			proposal = &initial
		} else if err == nil {
			var expected vaultfileclient.Manifest
			expected, err = boundLocalVaultFileManifest(configPath, session.VaultPath(), backendRoot)
			if err == nil {
				proposal = &expected
			}
		}
		var backup *personal.BackupPreparation
		var needsBackup bool
		if err == nil && ctx.Err() == nil {
			var creation *vaultfileclient.CreationContext
			creation, err = vaultfileclient.OpenCreation(configPath, proposal, password, secret)
			if creation != nil {
				if ctx.Err() == nil {
					needsBackup, err = creation.Prepare(ctx)
				} else {
					creation.Cancel()
				}
				creation.Close()
			}
		}
		if err == nil && needsBackup && ctx.Err() == nil {
			var key []byte
			key, err = personal.ParseSecret(string(secret))
			if err == nil {
				manifest, exists, readErr := vaultfileclient.ReadManifest(configPath)
				if readErr != nil || !exists || manifest.PersonalFile != session.VaultPath() || manifest.BackendRoot != backendRoot {
					err = vaultfileclient.ErrLocalReview
				} else {
					backup, err = personal.PrepareBackup(manifest.PersonalFile, manifest.Archive, string(password), key)
				}
				clear(key)
			}
		}
		var scope localVaultFileSessionScope
		if err == nil && ctx.Err() == nil {
			manifest, exists, readErr := vaultfileclient.ReadManifest(configPath)
			if readErr != nil || !exists || manifest.VaultID == "" ||
				manifest.PersonalFile != session.VaultPath() || manifest.BackendRoot != backendRoot {
				err = vaultfileclient.ErrLocalReview
			} else {
				scope = localVaultFileSessionScope{configPath: configPath, vaultID: manifest.VaultID, backendRoot: backendRoot}
			}
		}
		if ctx.Err() != nil && err == nil {
			err = vaultfileclient.ErrCreateCancelled
		}
		a.dispatch(func() {
			defer cancel()
			if a.generation != generation || a.session != session || !a.localCreate.open || a.localCreate.sequence != sequence || ctx.Err() != nil {
				if backup != nil {
					backup.Close()
				}
				return
			}
			state := &a.localCreate
			state.cancel, state.busy, state.configPath = nil, false, configPath
			state.scope = scope
			if err != nil {
				if backup != nil {
					backup.Close()
				}
				state.status = "准备失败；请核查本地状态"
			} else if needsBackup {
				state.backup = backup
				state.issued = backup.Material()
				state.phase = "confirm"
				state.status = "请离线保存恢复码，再逐字输入确认"
			} else {
				state.phase = "complete"
				state.status = "备份已存在；请再次完整验证并输入恢复码"
			}
			a.refreshLocalVaultFiles()
			if a.win != nil {
				a.win.Invalidate()
			}
		})
	})
}

func (a *App) localCreatePublishBackup() {
	state := &a.localCreate
	if !state.open || state.busy || state.phase != "confirm" || state.backup == nil ||
		state.confirm == "" || subtle.ConstantTimeCompare([]byte(state.confirm), []byte(state.issued)) != 1 {
		state.status = "恢复码未逐字匹配"
		return
	}
	gate := &localVaultFilePublishGate{backup: state.backup}
	state.backup, state.confirm, state.issued = nil, "", ""
	state.publish = gate
	state.busy = true
	state.sequence++
	sequence, generation, session := state.sequence, a.generation, a.session
	ctx, cancel := context.WithCancel(context.Background())
	state.cancel = cancel
	a.launch(func() {
		backup, ok := gate.start()
		if !ok {
			return
		}
		err := backup.Publish()
		backup.Close()
		a.dispatch(func() {
			defer cancel()
			if ctx.Err() != nil || a.generation != generation || a.session != session ||
				!a.localCreate.open || a.localCreate.sequence != sequence {
				return
			}
			state := &a.localCreate
			state.cancel, state.busy, state.publish = nil, false, nil
			if err != nil {
				state.phase, state.status = "unknown", "备份结果待核查；不会自动重试"
			} else {
				state.phase, state.status = "complete", "备份已发布；请再次完整验证并输入恢复码"
			}
			if a.win != nil {
				a.win.Invalidate()
			}
		})
	})
}

func (a *App) localCreateComplete() {
	state := &a.localCreate
	if !state.open || state.busy || state.phase != "complete" || a.session == nil ||
		state.scope.configPath == "" || state.scope.vaultID == "" || state.scope.backendRoot == "" {
		return
	}
	password, secret, kit := []byte(state.password), []byte(state.secret), []byte(state.kit)
	state.password, state.secret, state.kit = "", "", ""
	state.confirm, state.issued = "", ""
	state.busy = true
	state.sequence++
	sequence, generation, session := state.sequence, a.generation, a.session
	scope := state.scope
	ctx, cancel := context.WithCancel(context.Background())
	state.cancel = cancel
	// Reserve the exact C1 operation on the UI path, before the single
	// Complete/Verify worker starts. The worker never calls begin again, so no
	// second factor-open launch can race this creation attempt.
	childOp := a.reserveLocalVaultFileSessionOperation(scope)
	state.child = childOp
	dispatch := a.dispatch
	hook := a.localVaultFiles.sessionCandidateForTest
	closePause := a.localVaultFiles.sessionCandidateClosePauseForTest
	a.launch(func() {
		defer clear(password)
		defer clear(secret)
		defer clear(kit)
		var err error
		verified := false
		if ctx.Err() == nil {
			var expected vaultfileclient.Manifest
			expected, err = boundLocalVaultFileManifest(scope.configPath, session.VaultPath(), scope.backendRoot)
			if err == nil {
				var creation *vaultfileclient.CreationContext
				creation, err = vaultfileclient.OpenCreationForVault(scope.configPath, &expected, scope.vaultID, password, secret)
				if creation != nil {
					if ctx.Err() == nil {
						var backupRequired bool
						backupRequired, err = creation.Prepare(ctx)
						if err == nil && backupRequired {
							err = vaultfileclient.ErrLocalReview
						}
						if err == nil {
							err = creation.Complete(ctx, password, secret, kit)
						}
						if err == nil {
							err = creation.Verify(ctx, password, secret, kit)
							if err == nil {
								verified = true
							}
						}
					} else {
						creation.Cancel()
					}
					creation.Close()
				}
			}
		}
		if !verified {
			// The producer is done with every factor and kit buffer. Clear
			// before marking and before the UI dispatch so neither can retain
			// material or block settlement.
			clear(password)
			clear(secret)
			clear(kit)
			if childOp != nil {
				childOp.markProcessingFinished()
			}
			dispatch(func() {
				defer cancel()
				a.finishLocalVaultFileCreateFailure(childOp, generation, session, sequence, ctx, err)
			})
			return
		}
		// Creation is verified. Child-open is a separate finite outcome: a
		// failure here is "created but not opened", never a Complete retry.
		opened := false
		if ctx.Err() == nil && childOp != nil {
			manifest, exists, readErr := vaultfileclient.ReadManifest(scope.configPath)
			if readErr == nil && exists && manifest.VaultID == scope.vaultID &&
				manifest.PersonalFile == session.VaultPath() && manifest.BackendRoot == scope.backendRoot {
				key, keyErr := personal.ParseSecret(string(secret))
				if keyErr == nil {
					candidate, summary, openErr := a.openLocalVaultFileSessionCandidate(childOp, password, key)
					clear(key)
					if openErr == nil {
						result := localVaultFileSessionResult{candidate: candidate, summary: summary, outcome: localVaultFileSessionOutcomeOpened}
						opened = a.stageLocalVaultFileSessionResult(childOp, result, hook, closePause)
					} else if candidate != nil {
						clearLocalVaultFileSessionSummary(&summary)
						closeLocalVaultFileSessionCandidate(childOp, candidate, closePause)
					}
				}
			}
			if !opened {
				a.stageLocalVaultFileSessionResult(childOp, localVaultFileSessionResult{outcome: localVaultFileSessionOutcomeFailed}, hook, closePause)
			}
		}
		// No path above may run after this point with live factor or kit
		// material. Staging, if it happened, already registered the exact
		// candidate, so marking cannot open a premature no-candidate window.
		clear(password)
		clear(secret)
		clear(kit)
		if childOp != nil {
			childOp.markProcessingFinished()
		}
		dispatch(func() {
			defer cancel()
			if ctx.Err() != nil || a.generation != generation || a.session != session ||
				!a.localCreate.open || a.localCreate.sequence != sequence {
				if childOp != nil {
					a.cancelLocalVaultFileSessionOperationExact(childOp)
				}
				return
			}
			if childOp != nil {
				if !a.takeAndCompleteLocalVaultFileSessionResult(childOp) {
					a.cancelLocalVaultFileSessionOperationExact(childOp)
				}
			}
			state := &a.localCreate
			state.cancel, state.busy, state.child = nil, false, nil
			childOpened := childOp != nil && childOp.finiteOutcome() == localVaultFileSessionOutcomeOpened
			switch {
			case childOpened && a.presentAdoptedLocalVaultFileSession(childOp):
				state.phase, state.status = "done", "已验证本地初始版本 · 远端状态未核实"
				state.open = false
			case childOpened:
				// The child was really opened but the current cache authority
				// cannot deliver its projection. Keep the finite message in the
				// creation dialog; do not select or copy withheld metadata.
				state.phase, state.status = "done", "已创建；本地视图暂不可用，请稍后核查"
			default:
				state.phase, state.status = "done", "已创建，尚未打开；请核查本地状态"
				state.open = false
				a.presentUnopenedLocalVaultFile(scope)
			}
			if a.win != nil {
				a.win.Invalidate()
			}
		})
	})
}

func (a *App) finishLocalVaultFileCreateFailure(childOp *localVaultFileSessionOperation, generation uint64, session *personal.Session, sequence uint64, ctx context.Context, err error) {
	if ctx.Err() != nil || a.generation != generation || a.session != session ||
		!a.localCreate.open || a.localCreate.sequence != sequence {
		if childOp != nil {
			a.cancelLocalVaultFileSessionOperationExact(childOp)
		}
		return
	}
	if childOp != nil {
		if !a.takeAndCompleteLocalVaultFileSessionResult(childOp) {
			a.cancelLocalVaultFileSessionOperationExact(childOp)
		}
	}
	state := &a.localCreate
	state.cancel, state.busy, state.child = nil, false, nil
	if errors.Is(err, vaultfileclient.ErrCreateUnknown) || errors.Is(err, vaultfileclient.ErrLocalUnknown) {
		state.phase, state.status = "unknown", "创建结果待核查；不会自动重试"
	} else {
		state.status = "创建未完成；请核查本地状态"
	}
	if a.win != nil {
		a.win.Invalidate()
	}
}

// presentAdoptedLocalVaultFileSession shows an adopted child only while the
// exact operation still owns the exact current slot and the existing C1 cache
// getter authorizes delivery. It never clones the slot summary directly, calls
// the legacy global-proof opener, unwraps the wrapper or copies withheld
// metadata into the UI. Failure leaves the current local projection untouched.
func (a *App) presentAdoptedLocalVaultFileSession(op *localVaultFileSessionOperation) bool {
	if op == nil || op.slot == nil ||
		op.finiteOutcome() != localVaultFileSessionOutcomeOpened {
		return false
	}
	slot := op.slot
	if op.scope.configPath == "" || op.scope.vaultID == "" || op.scope.backendRoot == "" ||
		slot.scope != op.scope || slot.sequence != op.sequence ||
		slot.operation != nil || slot.parent != op.parent ||
		slot.appGeneration != op.generation || slot.session == nil ||
		a.session != op.parent || a.generation != op.generation ||
		a.localVaultFiles.sessionSlots[op.scope] != slot {
		return false
	}
	summary, ok := a.readLocalVaultFileSession(op.scope)
	if !ok || summary.VaultID != op.scope.vaultID {
		clearLocalVaultFileSessionSummary(&summary)
		return false
	}
	// The getter can synchronize a parent/cache boundary. Recheck the exact
	// operation ownership before copying the local projection into the UI.
	if op.slot != slot || a.localVaultFiles.sessionSlots[op.scope] != slot ||
		slot.scope != op.scope || slot.sequence != op.sequence ||
		slot.operation != nil || slot.parent != op.parent ||
		slot.appGeneration != op.generation || slot.session == nil ||
		a.session != op.parent || a.generation != op.generation {
		clearLocalVaultFileSessionSummary(&summary)
		return false
	}
	a.closeLocalVaultFileView()
	state := &a.localVaultFiles
	state.selected = op.scope.configPath
	state.status = "已验证本地初始版本 · 远端状态未核实"
	state.items = summary.Items
	a.refreshLocalVaultFiles()
	return true
}

// presentUnopenedLocalVaultFile reports the finite created-but-unopened outcome
// without selecting or opening a wrapper.
func (a *App) presentUnopenedLocalVaultFile(scope localVaultFileSessionScope) {
	a.closeLocalVaultFileView()
	state := &a.localVaultFiles
	state.selected = scope.configPath
	state.status = "已创建，尚未打开；请核查本地状态"
	a.refreshLocalVaultFiles()
}

func (a *App) onevraLocalVaultFileCreateDialog(c *ui.Context) {
	state := &a.localCreate
	oneui.Dialog(c, &state.open, oneui.DialogOptions{
		Label:                "创建独立文件库",
		DisableBackdropClose: true,
		DisableEscapeClose:   true,
	}, func(panel ui.Element) {
		t := c.Theme()
		panel.Width(460).Background(t.Surface).Border(1, t.Border).Radius(t.Radius).Padding(t.Space(4))
		panel.Children(func() {
			ui.Column(c).FillWidth().Gap(t.Space(2)).Children(func() {
				oneui.Text(c, "创建独立文件库").Bold()
				oneui.Text(c, state.status).Wrap()
				switch state.phase {
				case "prepare", "complete":
					oneui.TextBox(c, &state.password, oneui.TextBoxOptions{}).Label("主密码").Password().Disabled(state.busy)
					oneui.TextBox(c, &state.secret, oneui.TextBoxOptions{}).Label("Secret Key").Password().Disabled(state.busy)
					if state.phase == "complete" {
						oneui.TextBox(c, &state.kit, oneui.TextBoxOptions{}).Label("备份恢复码").Password().Disabled(state.busy)
					}
				case "confirm":
					oneui.Text(c, state.issued).Wrap()
					oneui.TextBox(c, &state.confirm, oneui.TextBoxOptions{}).Label("重新输入恢复码").Password().Disabled(state.busy)
				}
				ui.Row(c).FillWidth().Justify(ui.End).Gap(t.Space(2)).Children(func() {
					if oneui.Button(c, "取消", oneui.ButtonGhost).Clicked() {
						a.cancelLocalVaultFileCreate()
					}
					if state.phase == "prepare" && oneui.Button(c, "准备创建", oneui.ButtonPrimary).
						Disabled(state.busy || state.password == "" || state.secret == "").Clicked() {
						a.localCreatePrepare()
					}
					if state.phase == "confirm" && oneui.Button(c, "确认并发布备份", oneui.ButtonPrimary).
						Disabled(state.busy || state.confirm == "").Clicked() {
						a.localCreatePublishBackup()
					}
					if state.phase == "complete" && oneui.Button(c, "完成创建", oneui.ButtonPrimary).
						Disabled(state.busy || state.password == "" || state.secret == "" || state.kit == "").Clicked() {
						a.localCreateComplete()
					}
				})
			})
		})
	})
}
