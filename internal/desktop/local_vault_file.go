package desktop

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/teamfiles"
	"github.com/jihuayu/locklark/internal/vaultfileclient"
	oneui "github.com/oneo-me/onevra/source/components"
	"github.com/oneo-me/onevra/source/icons/lucide"
)

// Local refs are navigation hints only. They never supply a policy checkpoint.
// journalPath is a captured scheduling hint from the strict manifest read; it is
// not a routing identity, grant or authority.
type localVaultFileRef struct {
	path, vaultID, name, journalPath string
}

type localVaultFileState struct {
	refs         []localVaultFileRef
	selected     string
	items        []personal.VaultFileBaselineItem
	status       string
	loading      bool
	sequence     uint64
	listSequence uint64
	cancel       context.CancelFunc

	// Owned-session lifecycle state. It is reset on lock and never survives a
	// parent or App generation boundary. The wrapper itself is opaque here.
	sessionSlots      map[localVaultFileSessionScope]*localVaultFileSessionSlot
	sessionParent     *personal.Session
	sessionGeneration uint64
	// sessionCandidateForTest observes the staged operation after the
	// production factory result has been handed off and before dispatch. The
	// worker captures it before launch; production leaves it nil.
	sessionCandidateForTest func(*localVaultFileSessionOperation)
	// sessionCandidateOpenPauseForTest and sessionCandidateClosePauseForTest
	// are parameterless private seams, nil in production. The open pause runs
	// at generic worker entry after the cancel check and before the real
	// factory; the close pause runs immediately before the real cleanup Close
	// of a candidate that never became an adopted slot. Both are captured
	// before launch so the worker never reads mutable App state, and neither
	// receives a factor, key, identity, VUK, handle or capability.
	sessionCandidateOpenPauseForTest  func()
	sessionCandidateClosePauseForTest func()
}

func localVaultFilePaths(settingsPath, personalPath string) (profileDir, backendRoot string) {
	base := filepath.Join(filepath.Dir(settingsPath), "vaultfile-workspace")
	sum := sha256.Sum256([]byte(personalPath))
	return filepath.Join(base, "profiles", hex.EncodeToString(sum[:])), filepath.Join(base, "backend")
}

func listLocalVaultFileRefs(profileDir, backendRoot, personalPath string) ([]localVaultFileRef, error) {
	if _, err := os.Lstat(profileDir); os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, vaultfileclient.ErrLocalReview
	}
	if teamfiles.ValidatePrivateParent(profileDir) != nil {
		return nil, vaultfileclient.ErrLocalReview
	}
	entries, err := os.ReadDir(profileDir)
	if err != nil || len(entries) > 128 {
		return nil, vaultfileclient.ErrLocalReview
	}
	refs := make([]localVaultFileRef, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(profileDir, entry.Name())
		ref := localVaultFileRef{path: path, name: "待核查文件"}
		manifest, exists, e := vaultfileclient.ReadManifest(path)
		if e == nil && exists && manifest.PersonalFile == personalPath && manifest.BackendRoot == backendRoot {
			ref.vaultID, ref.name, ref.journalPath = manifest.VaultID, manifest.Name, manifest.Journal
		}
		refs = append(refs, ref)
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].path < refs[j].path })
	return refs, nil
}

func (a *App) refreshLocalVaultFiles() {
	if a.session == nil {
		return
	}
	session, generation := a.session, a.generation
	a.localVaultFiles.listSequence++
	listSequence := a.localVaultFiles.listSequence
	profileDir, backendRoot := localVaultFilePaths(a.settingsPath, session.VaultPath())
	a.launch(func() {
		refs, err := listLocalVaultFileRefs(profileDir, backendRoot, session.VaultPath())
		a.dispatch(func() {
			if a.session != session || a.generation != generation || a.localVaultFiles.listSequence != listSequence {
				return
			}
			if err != nil {
				a.localVaultFiles.refs = nil
				a.localVaultFiles.status = "本地文件库目录待核查"
			} else {
				a.localVaultFiles.refs = refs
			}
			if a.win != nil {
				a.win.Invalidate()
			}
		})
	})
}

func (a *App) closeLocalVaultFileView() {
	state := &a.localVaultFiles
	state.sequence++
	if state.cancel != nil {
		state.cancel()
		state.cancel = nil
	}
	state.selected, state.items, state.loading, state.status = "", nil, false, ""
}

func (a *App) selectLocalVaultFile(ref localVaultFileRef) {
	if a.session == nil || !a.session.Unlocked() {
		return
	}
	a.closeLocalVaultFileView()
	state := &a.localVaultFiles
	if ref.vaultID == "" {
		state.selected, state.status = ref.path, "本地文件库待核查"
		return
	}
	state.selected, state.loading = ref.path, true
	state.status = "正在验证本地初始版本"
	state.sequence++
	sequence, generation, session := state.sequence, a.generation, a.session
	_, backendRoot := localVaultFilePaths(a.settingsPath, session.VaultPath())
	ctx, cancel := context.WithCancel(context.Background())
	state.cancel = cancel
	a.launch(func() {
		result, err := vaultfileclient.OpenLocalGenesisBaseline(session, ref.path, backendRoot, ref.vaultID)
		a.dispatch(func() {
			defer cancel()
			if ctx.Err() != nil || a.generation != generation || a.session != session ||
				a.localVaultFiles.sequence != sequence || a.localVaultFiles.selected != ref.path {
				return
			}
			state := &a.localVaultFiles
			state.cancel, state.loading = nil, false
			if err != nil || result.VaultID != ref.vaultID {
				state.items = nil
				if errors.Is(err, personal.ErrVaultFileFullFactorRequired) {
					state.status = "需要完整解锁账户后打开此库"
				} else {
					state.status = "本地文件库待核查"
				}
			} else {
				state.items = result.Items
				state.status = "已验证本地初始版本 · 远端状态未核实"
			}
			if a.win != nil {
				a.win.Invalidate()
			}
		})
	})
}

func (a *App) onevraLocalVaultFileSidebar(c *ui.Context) {
	oneui.SidebarSection(c, "独立文件库", func() {
		for _, ref := range a.localVaultFiles.refs {
			ref := ref
			item := oneui.SidebarItemWithSlots(c, ref.name, a.localVaultFiles.selected == ref.path,
				func(c *ui.Context, size float32) { oneui.Icon(c, lucide.Vault()).Size(size, size) }, nil)
			pathHash := sha256.Sum256([]byte(ref.path))
			item.Key("local-vault-file:" + hex.EncodeToString(pathHash[:]))
			if item.Clicked() {
				a.selectLocalVaultFile(ref)
			}
		}
		if oneui.Button(c, "刷新独立文件库", oneui.ButtonGhost).Clicked() {
			a.refreshLocalVaultFiles()
		}
		if oneui.Button(c, "新建独立文件库", oneui.ButtonGhost).Clicked() {
			a.openLocalVaultFileCreate("")
		}
	})
}

func (a *App) localVaultFileLabel() string {
	for _, ref := range a.localVaultFiles.refs {
		if ref.path == a.localVaultFiles.selected {
			return "独立文件库：" + ref.name
		}
	}
	return "独立文件库"
}

func (a *App) onevraLocalVaultFileView(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).Fill().Padding(t.Space(3)).Gap(t.Space(2)).Children(func() {
		oneui.Text(c, a.localVaultFiles.status).Bold()
		if oneui.Button(c, "关闭本地基线视图", oneui.ButtonOutline).Clicked() {
			a.closeLocalVaultFileView()
		}
		if !a.localVaultFiles.loading {
			if a.localVaultFiles.status == "本地文件库待核查" && !a.localCreate.open {
				if oneui.Button(c, "核查或继续创建", oneui.ButtonOutline).Clicked() {
					a.openLocalVaultFileCreate(a.localVaultFiles.selected)
				}
			}
			for _, item := range a.localVaultFiles.items {
				oneui.Text(c, item.Title).SingleLine()
			}
		}
	})
}
