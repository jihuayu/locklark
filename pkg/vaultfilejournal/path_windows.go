//go:build windows

package vaultfilejournal

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"unsafe"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/sys/windows"
)

// Access masks. Right groups are UNIX-style bundles; a grant of any bundled
// right counts as a request for every right in it. MAXIMUM_ALLOWED (0x02000000)
// is deliberately absent: it is a desired-access flag for an access *request*,
// not a right an ACE can grant (see AccessCheck in MS-DTYP), so it can never
// appear in a DACL mask and naming it in a forbidden mask would be dead.
const (
	genericRead     = 0x80000000
	genericWrite    = 0x40000000
	genericExecute  = 0x20000000
	genericAll      = 0x10000000
	deleteChildMask = 0x0040
	// aceFlagsInheritOnly marks an ACE that applies only to children.
	aceFlagsInheritOnly = 0x8

	// ACE types. x/sys exports only access-allowed and access-denied; the
	// rest are named here so every ACE type is classified, never guessed.
	aceSystemAuditType          = 0x2
	aceSystemAlarmType          = 0x3
	aceSystemMandatoryLabelType = 0x11

	// fileWriteRights let a holder replace the journal content or metadata.
	fileWriteRights = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA |
		windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES |
		genericWrite | genericAll | windows.DELETE
	// fileDestructiveRights additionally let a holder re-permission or
	// re-own the journal.
	fileDestructiveRights = fileWriteRights | windows.WRITE_DAC | windows.WRITE_OWNER
	// fileRelevantRights is everything a holder of the file DACL may not use.
	fileRelevantRights = fileDestructiveRights | windows.FILE_READ_DATA |
		windows.FILE_READ_EA | windows.FILE_EXECUTE | genericRead | genericExecute |
		windows.READ_CONTROL | windows.SYNCHRONIZE

	// dirChildRights let a holder add, rename or delete the journal inside the
	// directory (DELETE on a child is DELETE_CHILD on the directory), or make
	// it readable or writable.
	dirChildRights = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA |
		windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES | deleteChildMask |
		genericWrite | genericAll
	// dirDestructiveRights additionally let a holder replace, re-permission or
	// re-own the directory entry itself.
	dirDestructiveRights = dirChildRights | windows.DELETE | windows.WRITE_DAC |
		windows.WRITE_OWNER | genericRead | genericExecute
	// dirImmediateForbidden is what the journal's own parent must not grant an
	// untrusted principal: list or traverse it, write or delete inside it,
	// replace it, or rewrite its ACL.
	dirImmediateForbidden = dirDestructiveRights | windows.FILE_READ_DATA |
		windows.FILE_READ_EA | windows.FILE_EXECUTE | windows.READ_CONTROL
	// dirAncestorForbidden is what an ancestor must not grant an untrusted
	// principal: delete or replace a child entry, re-permission or re-own the
	// ancestor, or hold write, metadata or generic-write powers on it.
	// Ordinary read, list, traverse (FILE_READ_DATA/FILE_EXECUTE) and
	// add-new-child (FILE_WRITE_DATA/FILE_APPEND_DATA) are allowed: a
	// relative open resolves the next component from the ancestor and is
	// then gated by that component and the strict immediate parent, so these
	// rights cannot redirect or replace the journal's own path.
	dirAncestorForbidden = windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES |
		windows.DELETE | deleteChildMask | windows.WRITE_DAC | windows.WRITE_OWNER |
		genericWrite | genericAll

	// journalTempPrefix names this package's uniquely named publication files.
	journalTempPrefix = ".locklark-vaultfilejournal-"

	// symlinkFlagAllowUnprivilegedCreate lets a Developer Mode process create
	// links without SeCreateSymbolicLinkPrivilege.
	symlinkFlagAllowUnprivilegedCreate = 0x2
)

// sidScope is the set of principals trusted to own or administer the local
// journal: this process user, LocalSystem, Administrators and
// TrustedInstaller. Other built-in groups (for example Protected Users) are
// not administrators of this user's files and stay untrusted.
type sidScope struct {
	user, system, admins, trustedInstaller *windows.SID
}

func currentSIDs() (*sidScope, error) {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || tu == nil || tu.User.Sid == nil {
		return nil, fmt.Errorf("current user identity: %v", err)
	}
	// String form keeps well-known SIDs that the package may not name.
	text := func(s string) *windows.SID {
		sid, err := windows.StringToSid(s)
		if err != nil {
			return nil
		}
		return sid
	}
	return &sidScope{
		user:             tu.User.Sid,
		system:           text("S-1-5-18"),
		admins:           text("S-1-5-32-544"),
		trustedInstaller: text("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"),
	}, nil
}

func (s *sidScope) trusted(sid *windows.SID) bool {
	if sid == nil {
		return false
	}
	for _, t := range []*windows.SID{s.user, s.system, s.admins, s.trustedInstaller} {
		if t != nil && t.Equals(sid) {
			return true
		}
	}
	return false
}

func describeSID(sid *windows.SID) string {
	if sid == nil {
		return "<nil>"
	}
	return sid.String()
}

// walkDACL applies allowed to every access-allowed rule that is not
// inherit-only. Deny, audit and integrity-policy rules grant nothing; unknown
// or access-denied callback and object-specific rules fail closed because they
// may grant conditional access this package does not evaluate.
func walkDACL(sd *windows.SECURITY_DESCRIPTOR, allowed func(sid *windows.SID, mask uint32) error) error {
	acl, defaulted, err := sd.DACL()
	if err != nil || defaulted || acl == nil {
		// A nil DACL allows everyone; an absent or defaulted one cannot be
		// trusted either.
		return errors.New("DACL is absent, defaulted or unreadable")
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return fmt.Errorf("unreadable ACE %d: %w", i, err)
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE,
			aceSystemAuditType, aceSystemAlarmType, aceSystemMandatoryLabelType:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			if ace.Header.AceFlags&aceFlagsInheritOnly != 0 {
				continue
			}
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if err := allowed(sid, uint32(ace.Mask)); err != nil {
				return err
			}
		default:
			// Callback, object-specific, audit-callback and alarm-callback
			// ACEs cannot be evaluated here.
			return fmt.Errorf("unsupported ACE type %d", ace.Header.AceType)
		}
	}
	return nil
}

func (s *sidScope) requireOwner(path string, sd *windows.SECURITY_DESCRIPTOR) error {
	owner, _, err := sd.Owner()
	if err != nil || !s.trusted(owner) {
		return fmt.Errorf("%w: %s is not owned by a trusted principal", ErrInvalid, path)
	}
	return nil
}

// checkDirACL enforces the directory rules: a trusted owner and no allowed
// ACE to an untrusted principal using any of forbidden.
func (s *sidScope) checkDirACL(path string, sd *windows.SECURITY_DESCRIPTOR, forbidden uint32) error {
	if err := s.requireOwner(path, sd); err != nil {
		return err
	}
	err := walkDACL(sd, func(sid *windows.SID, mask uint32) error {
		if s.trusted(sid) {
			return nil
		}
		if grant := mask & forbidden; grant != 0 {
			return fmt.Errorf("grants %s rights 0x%x", describeSID(sid), grant)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("%w: directory %s %v", ErrInvalid, path, err)
	}
	return nil
}

// checkFileACL requires a trusted owner and a DACL that grants no untrusted
// principal any file right.
func (s *sidScope) checkFileACL(path string, sd *windows.SECURITY_DESCRIPTOR) error {
	if err := s.requireOwner(path, sd); err != nil {
		return err
	}
	err := walkDACL(sd, func(sid *windows.SID, mask uint32) error {
		if s.trusted(sid) {
			return nil
		}
		if grant := mask & fileRelevantRights; grant != 0 {
			return fmt.Errorf("grants %s rights 0x%x", describeSID(sid), grant)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("%w: database file %s %v", ErrInvalid, path, err)
	}
	return nil
}

// checkPrivateDir validates the whole local-drive path chain of dir: every
// component must be a real directory (no reparse point) with a trusted owner
// and a DACL that lets no untrusted principal traverse it, replace it or
// rewrite its ACL. The immediate parent additionally must not let untrusted
// principals list it, write inside it or delete the journal from it. Open
// never creates or tightens any of these directories.
func checkPrivateDir(dir string) error {
	if err := checkLocalDrive(dir); err != nil {
		return err
	}
	scope, err := currentSIDs()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	chain := directoryChain(dir)
	for i, current := range chain {
		attrs, err := lstatNoFollow(current)
		if err != nil {
			return fmt.Errorf("%w: directory %s: %v", ErrInvalid, current, err)
		}
		if attrs&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			return fmt.Errorf("%w: %s is not a directory", ErrInvalid, current)
		}
		if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return fmt.Errorf("%w: %s is a reparse point", ErrInvalid, current)
		}
		sd, err := windows.GetNamedSecurityInfo(current, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			return fmt.Errorf("%w: cannot read the security of directory %s: %v", ErrInvalid, current, err)
		}
		forbidden := uint32(dirAncestorForbidden)
		if i == len(chain)-1 {
			forbidden = dirImmediateForbidden
		}
		if err := scope.checkDirACL(current, sd, forbidden); err != nil {
			return err
		}
	}
	return nil
}

// directoryChain lists dir and every ancestor down to the volume root, root
// first, without following any component.
func directoryChain(dir string) []string {
	var chain []string
	for current := filepath.Clean(dir); ; current = filepath.Dir(current) {
		chain = append(chain, current)
		if parent := filepath.Dir(current); parent == current {
			break
		}
	}
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain
}

// localDriveRejection reports why path is not an absolute local-drive path,
// or "" when it is. Any absolute drive-letter path is valid here; the drive's
// type (fixed, RAM disk, network, removable) is checked separately.
func localDriveRejection(path string) string {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return "path is not absolute"
	}
	switch {
	case strings.HasPrefix(clean, `\\?\`) || strings.HasPrefix(clean, `\\.\`):
		return "path uses a device or extended-length prefix"
	case strings.HasPrefix(clean, `\`) || strings.HasPrefix(clean, `//`):
		return "path has a UNC or network root"
	}
	volume := filepath.VolumeName(clean)
	if len(volume) != 2 || volume[1] != ':' || !isDriveLetter(volume[0]) ||
		len(clean) < 3 || clean[2] != '\\' {
		return "path does not start with a local drive letter"
	}
	return ""
}

func checkLocalDrive(path string) error {
	if why := localDriveRejection(path); why != "" {
		return fmt.Errorf("%w: %s: %s", ErrInvalid, path, why)
	}
	root, err := windows.UTF16PtrFromString(filepath.VolumeName(filepath.Clean(path)) + `\`)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrInvalid, path, err)
	}
	switch kind := windows.GetDriveType(root); kind {
	case windows.DRIVE_FIXED, windows.DRIVE_RAMDISK:
		return nil
	default:
		return fmt.Errorf("%w: %s is on drive type %d, not a local fixed drive", ErrInvalid, path, kind)
	}
}

func isDriveLetter(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

// lstatNoFollow returns path's attributes without following a reparse point.
func lstatNoFollow(path string) (uint32, error) {
	wide, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	attrs, err := windows.GetFileAttributes(wide)
	if err != nil {
		return 0, err
	}
	return attrs, nil
}

// checkDBPath requires path to name a regular, non-reparse file with a private
// DACL, or no file at all. Only a genuinely absent name is reported
// missing=true; nothing is created here. An existing file must pass the same
// handle validation that openExistingDatabase applies, so a symlinked
// database name is rejected before publication or bbolt.
func checkDBPath(path string) (missing bool, err error) {
	file, _, missing, err := openValidatedDB(path)
	if file != nil {
		_ = file.Close()
	}
	return missing, err
}

// openDBHandle opens path for bbolt. It must not follow a file reparse point:
// FILE_FLAG_OPEN_REPARSE_POINT plus OPEN_EXISTING makes the handle name the
// link itself, never its target, so a symlinked database cannot be validated
// in place of, or initialized or locked through, another file. OPEN_EXISTING
// is sufficient because Open has already published or located the file.
// The share mode keeps bbolt's read/write and mapping compatibility
// (FILE_SHARE_READ|FILE_SHARE_WRITE, so no conflicting open is refused) but
// withholds FILE_SHARE_DELETE, so the name cannot be deleted or renamed away
// while this handle is open: no replacement can appear at the path, and a
// delete-pending name (which a fresh open would resolve to the same file)
// surfaces as an access error here instead of being followed.
func openDBHandle(path string) (windows.Handle, error) {
	wide, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, fmt.Errorf("%w: %s: %v", ErrInvalid, path, err)
	}
	handle, err := windows.CreateFile(wide, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return 0, fmt.Errorf("%w: database file %s: %w", ErrInvalid, path, err)
	}
	return handle, nil
}

// openValidatedDB opens the existing file at path through one handle, without
// following a final-component reparse point, and requires a regular,
// non-reparse, singly linked file with a trusted owner and a private DACL.
// It returns the opened file for bbolt to use directly, the handle identity,
// and whether the name was absent. Only a genuinely absent final name is
// missing=true with no error. With FILE_FLAG_OPEN_REPARSE_POINT and
// OPEN_EXISTING, a final-component reparse point that already exists (even a
// dangling link) is opened as the reparse point itself, never followed, and
// validateDBHandle rejects it as not a regular file.
func openValidatedDB(path string) (file *os.File, info windows.ByHandleFileInformation, missing bool, err error) {
	handle, err := openDBHandle(path)
	if err != nil {
		if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) || errors.Is(err, syscall.ERROR_PATH_NOT_FOUND) {
			return nil, info, true, nil
		}
		return nil, info, false, err
	}
	defer func() {
		if file == nil {
			_ = syscall.CloseHandle(syscall.Handle(handle))
		}
	}()
	if err := validateDBHandle(path, handle, &info); err != nil {
		return nil, info, false, err
	}
	// Wrap the validated descriptor rather than reopening by name: bbolt
	// receives exactly the handle inspected above.
	return os.NewFile(uintptr(handle), path), info, false, nil
}

// validateDBHandle applies the database file rules to one open handle: a
// regular, non-reparse, singly linked file whose owner and DACL are trusted.
func validateDBHandle(path string, handle windows.Handle, info *windows.ByHandleFileInformation) error {
	if err := windows.GetFileInformationByHandle(handle, info); err != nil {
		return fmt.Errorf("%w: database file %s: %v", ErrInvalid, path, err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return fmt.Errorf("%w: database path %s is not a regular file", ErrInvalid, path)
	}
	if info.NumberOfLinks > 1 {
		return fmt.Errorf("%w: database file %s has multiple hard links", ErrInvalid, path)
	}
	scope, err := currentSIDs()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%w: cannot read the security of %s: %v", ErrInvalid, path, err)
	}
	if err := scope.checkFileACL(path, sd); err != nil {
		return err
	}
	return nil
}

// verifyDBPathIdentity requires path, opened once more without following a
// reparse point, to still name exactly the file identified by info. The name
// cannot have been deleted or renamed while the bbolt handle is open (it
// withholds FILE_SHARE_DELETE) and the handle above is where the data lives;
// this check catches a swap of the name before that handle was taken.
func verifyDBPathIdentity(path string, info windows.ByHandleFileInformation) error {
	handle, err := openDBHandle(path)
	if err != nil {
		return fmt.Errorf("%w: database file %s changed during open: %v", ErrInvalid, path, err)
	}
	defer func() { _ = syscall.CloseHandle(syscall.Handle(handle)) }()
	var after windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &after); err != nil {
		return fmt.Errorf("%w: database file %s: %v", ErrInvalid, path, err)
	}
	if info.VolumeSerialNumber != after.VolumeSerialNumber ||
		info.FileIndexHigh != after.FileIndexHigh || info.FileIndexLow != after.FileIndexLow {
		return fmt.Errorf("%w: database file %s changed during open", ErrInvalid, path)
	}
	return nil
}

var tempCounter atomic.Uint64

// openDatabase opens the journal database after the path checks. A missing
// database is published as a fully initialized, privately secured file; any
// other path is opened in place. A missingHint merely records what Open saw:
// the name is looked up afresh here, because openValidatedDB never creates it.
// Windows has no supported user-mode directory flush, so a new name becomes
// durable through the file sync inside publishNewDatabase followed by
// MoveFileEx(MOVEFILE_WRITE_THROUGH). That is the supported initial-file
// publication mechanism; it is not a general directory-flush or power-loss
// guarantee.
func openDatabase(path, parent string, missingHint bool) (*Journal, error) {
	if missingHint {
		// Publish only when the name is genuinely absent; when another opener
		// won the publication race, publishNewDatabase reports that and its
		// uniquely named temporary file was removed, nothing else.
		if _, err := publishNewDatabase(path, parent); err != nil {
			return nil, err
		}
	}
	return openExistingDatabase(path)
}

// openExistingDatabase opens an existing database with bbolt through the one
// handle that was validated as a regular, singly linked, privately secured,
// non-reparse file. There is no window between validation and bbolt in which
// the path could be redirected: bbolt receives the validated descriptor via
// Options.OpenFile and never resolves the name itself. After bbolt has locked
// the file, the name is checked once more to still identify that same file.
func openExistingDatabase(path string) (*Journal, error) {
	file, info, missing, err := openValidatedDB(path)
	if err != nil {
		return nil, err
	}
	if missing {
		return nil, fmt.Errorf("%w: database file %s does not exist", ErrInvalid, path)
	}
	handedOff := false
	defer func() {
		if !handedOff {
			_ = file.Close()
		}
	}()
	db, err := bolt.Open(path, 0o600, &bolt.Options{
		NoSync:  false,
		Timeout: lockTimeout,
		OpenFile: func(name string, flag int, perm os.FileMode) (*os.File, error) {
			// bbolt opens the located database once, read-write. The
			// validated handle already names that file, so any other name is
			// a bug, never a fallback to a fresh name lookup. bbolt in write
			// mode always adds O_CREATE to O_RDWR; here it is declarative
			// only, because the file exists and this returns it unchanged
			// rather than creating or resolving a second handle. A truncate
			// request is rejected.
			if name != path || flag&os.O_TRUNC != 0 || flag&(os.O_WRONLY|os.O_RDWR) != os.O_RDWR {
				return nil, fmt.Errorf("%w: database file %s: unexpected reopen %q with flags 0x%x",
					ErrInvalid, path, name, flag)
			}
			handedOff = true
			return file, nil
		},
	})
	if err != nil {
		// A handing-off OpenFile has already given ownership to bbolt, which
		// closes the file itself when it gives up.
		if errors.Is(err, bolt.ErrTimeout) {
			return nil, fmt.Errorf("%w: %w", ErrLocked, err)
		}
		return nil, fmt.Errorf("vault file journal: open: %w", err)
	}
	if err := verifyDBPathIdentity(path, info); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Journal{db: db}, nil
}

// publishNewDatabase initializes a new database as a collision-resistant
// temporary file in parent with a protected, trusted-only DACL and publishes
// it to name with a non-replacing, write-through move. Only when another
// opener wins the name does this call remove its own uniquely named temporary
// file; it never removes the final path.
func publishNewDatabase(name, parent string) (published bool, err error) {
	sd, err := privateFileSecurity()
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	handle, temp, err := createSecureTemp(parent, sd)
	if err != nil {
		return false, err
	}
	// The creation handle was opened without sharing, so it is the only way
	// to reach the file until it is closed. temp is removed unless published.
	defer func() {
		if !published {
			_ = removeOwnFile(temp)
		}
	}()

	// Verify the DACL actually applied at creation through that handle, then
	// close it before anything else opens the path by name.
	if err := verifyTempSecurity(temp, handle); err != nil {
		_ = syscall.CloseHandle(syscall.Handle(handle))
		return false, err
	}
	if err := syscall.CloseHandle(syscall.Handle(handle)); err != nil {
		return false, fmt.Errorf("vault file journal: close creation handle: %w", err)
	}

	// Only this call reaches this unique name, so a lock timeout here is an
	// error, not a competing writer. NoSync stays false, and the file is
	// synced again after bbolt's own close.
	db, err := bolt.Open(temp, 0o600, &bolt.Options{NoSync: false, Timeout: lockTimeout})
	if err != nil {
		return false, fmt.Errorf("vault file journal: initialize database: %w", err)
	}
	if err := db.Close(); err != nil {
		return false, fmt.Errorf("vault file journal: close database: %w", err)
	}
	if err := syncFile(temp); err != nil {
		return false, fmt.Errorf("vault file journal: sync database: %w", err)
	}

	from, err := windows.UTF16PtrFromString(temp)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	to, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH); err != nil {
		switch {
		case errors.Is(err, syscall.ERROR_ALREADY_EXISTS), errors.Is(err, syscall.ERROR_FILE_EXISTS),
			errors.Is(err, syscall.ERROR_ACCESS_DENIED):
			// The final name now exists (another opener or a non-writable
			// name); leave it in place and let the caller open it.
			return false, nil
		}
		return false, fmt.Errorf("vault file journal: publish database: %w", err)
	}
	published = true
	return true, nil
}

// verifyTempSecurity requires the freshly created temporary to have a
// protected DACL that grants no untrusted principal read, write, delete or
// ACL access. It fails closed if the DACL cannot be read through handle.
func verifyTempSecurity(temp string, handle windows.Handle) error {
	scope, err := currentSIDs()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%w: cannot read the security of new database %s: %v", ErrInvalid, temp, err)
	}
	if err := scope.checkFileACL(temp, sd); err != nil {
		return err
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("%w: new database %s has no protected DACL", ErrInvalid, temp)
	}
	return nil
}

// privateFileSecurity returns a descriptor owned by the current user with a
// protected DACL granting full control only to the current user, LocalSystem
// and Administrators.
func privateFileSecurity() (*windows.SECURITY_DESCRIPTOR, error) {
	scope, err := currentSIDs()
	if err != nil {
		return nil, err
	}
	rule := func(sid *windows.SID) string {
		if sid == nil {
			return ""
		}
		return "(A;;FA;;;" + sid.String() + ")"
	}
	return windows.SecurityDescriptorFromString("D:P" + rule(scope.user) + rule(scope.system) + rule(scope.admins))
}

// createSecureTemp creates a uniquely named file in parent with sd applied at
// creation (CREATE_NEW never reuses an existing name).
func createSecureTemp(parent string, sd *windows.SECURITY_DESCRIPTOR) (windows.Handle, string, error) {
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	for attempt := 0; attempt < 16; attempt++ {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return 0, "", fmt.Errorf("vault file journal: create database: %w", err)
		}
		var counter [8]byte
		binary.BigEndian.PutUint64(counter[:], tempCounter.Add(1))
		digest := sha256.Sum256(append(random[:], counter[:]...))
		temp := filepath.Join(parent, journalTempPrefix+fmt.Sprintf("%x.db", digest[:16]))
		wide, err := windows.UTF16PtrFromString(temp)
		if err != nil {
			return 0, "", fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		handle, err := windows.CreateFile(wide, windows.GENERIC_READ|windows.GENERIC_WRITE,
			0, &attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if errors.Is(err, syscall.ERROR_FILE_EXISTS) || errors.Is(err, syscall.ERROR_ALREADY_EXISTS) {
			continue
		}
		if err != nil {
			return 0, "", fmt.Errorf("vault file journal: create database: %w", err)
		}
		return handle, temp, nil
	}
	return 0, "", fmt.Errorf("vault file journal: cannot allocate a unique database name")
}

func syncFile(path string) error {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

// createDirSymlink and createFileSymlink create symbolic links (reparse
// points) used by the hostile-path tests. They are unprivileged when the
// process has Developer Mode; otherwise they only require the target's
// delete-child right.
func createDirSymlink(link, target string) error {
	l, err := windows.UTF16PtrFromString(link)
	if err != nil {
		return err
	}
	t, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	return windows.CreateSymbolicLink(l, t, windows.SYMBOLIC_LINK_FLAG_DIRECTORY|symlinkFlagAllowUnprivilegedCreate)
}

func createFileSymlink(link, target string) error {
	l, err := windows.UTF16PtrFromString(link)
	if err != nil {
		return err
	}
	t, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	return windows.CreateSymbolicLink(l, t, symlinkFlagAllowUnprivilegedCreate)
}
