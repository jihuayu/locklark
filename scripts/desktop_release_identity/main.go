// Command desktop_release_identity verifies the signed content identity of a
// Locklark desktop update archive.
//
// It reads the archive in place, never extracts or executes an entry, and
// checks the paths and bounded sizes of the tar stream. The Windows archive
// must hold a real windows/amd64 Go PE; the macOS archive must hold a
// darwin/universal fat Mach-O with both arm64 and amd64 slices. Each slice
// must carry the requested MyGo package version and the Locklark identifier,
// and the macOS Info.plist must name the same bundle and version.
//
// In plan mode it also checks each signed "mygo delta 1" index: the raw
// DEFLATE JSON index must name the exact from/to versions and its entry tree
// must match the already-read full archive of the same platform. Delta data
// is bounded by offsets but is not decompressed or applied.
//
// The helper is built once by scripts/verify_desktop_release.py and handles
// both platform archives and all deltas in one invocation.
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/sha256"
	"debug/buildinfo"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"unicode/utf16"
)

const (
	appIdentifier = "app.locklark.desktop"
	windowsTarget = "windows-amd64"
	darwinTarget  = "darwin-universal"

	windowsExecutable = "Locklark.exe"
	darwinBundle      = "Locklark.app"
	darwinExecutable  = darwinBundle + "/Contents/MacOS/Locklark"
	darwinInfoPlist   = darwinBundle + "/Contents/Info.plist"

	maxArchiveSize    = int64(1 << 30)
	maxTotalSize      = int64(2 << 30)
	maxEntrySize      = int64(512 << 20)
	maxExecutableSize = int64(512 << 20)
	maxInfoPlistSize  = int64(4 << 20)
	maxEntries        = 200000
	maxPathLength     = 4096
	maxLinkLength     = 4096

	deltaMagic              = "mygo delta 1\n"
	maxDeltaSize            = int64(1 << 30)
	maxDeltaIndex           = 16 << 20
	maxDeltaIndexCompressed = 16 << 20
	maxDeltaEntries         = 200000
	maxPlanSize             = 1 << 20
)

type archiveEntry struct {
	kind   byte
	mode   uint32
	size   int64
	sha256 string
	link   string
}

type archiveContents struct {
	files map[string][]byte
	tree  map[string]archiveEntry
}

type plan struct {
	Version string            `json:"version"`
	Full    map[string]string `json:"full"`
	Deltas  []planDelta       `json:"deltas"`
}

type planDelta struct {
	Platform string `json:"platform"`
	From     string `json:"from"`
	Path     string `json:"path"`
}

type deltaIndex struct {
	From    string       `json:"from"`
	Version string       `json:"version"`
	Entries []deltaEntry `json:"entries"`
}

type deltaEntry struct {
	Path   string `json:"path"`
	Dir    bool   `json:"dir,omitempty"`
	Link   string `json:"link,omitempty"`
	Mode   uint32 `json:"mode,omitempty"`
	Size   int64  `json:"size,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	From   string `json:"from,omitempty"`
	Data   int64  `json:"data,omitempty"`
}

func main() {
	planMode := flag.Bool("plan", false, "read a JSON verification plan from stdin")
	platform := flag.String("platform", "", "archive target: windows-amd64 or darwin-universal")
	version := flag.String("version", "", "expected MyGo package version")
	flag.Parse()
	var err error
	if *planMode {
		if len(flag.Args()) != 0 {
			err = errors.New("plan mode takes no positional arguments")
		} else {
			err = runPlan()
		}
	} else {
		err = run(*platform, *version, flag.Args())
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "release archive identity failed:", err)
		os.Exit(1)
	}
	fmt.Println("archive identity ok")
}

func run(platform, version string, args []string) error {
	if version == "" {
		return errors.New("missing expected version")
	}
	if len(args) != 1 {
		return errors.New("want exactly one archive path")
	}
	_, err := loadFull(platform, version, args[0])
	return err
}

func loadFull(platform, version, filename string) (*archiveContents, error) {
	if version == "" {
		return nil, errors.New("missing expected version")
	}
	switch platform {
	case windowsTarget, darwinTarget:
	default:
		return nil, fmt.Errorf("unsupported platform %q", platform)
	}
	contents, err := readArchive(platform, filename)
	if err != nil {
		return nil, fmt.Errorf("%s archive: %w", platform, err)
	}
	switch platform {
	case windowsTarget:
		err = verifyWindows(contents.files[windowsExecutable], version)
	case darwinTarget:
		err = verifyDarwin(contents.files[darwinExecutable], contents.files[darwinInfoPlist], version)
	}
	if err != nil {
		return nil, fmt.Errorf("%s archive: %w", platform, err)
	}
	return contents, nil
}

func readPlan() (*plan, error) {
	data, err := io.ReadAll(io.LimitReader(os.Stdin, maxPlanSize+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read the plan: %w", err)
	}
	if len(data) > maxPlanSize {
		return nil, errors.New("plan is too large")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p plan
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("invalid plan: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("invalid plan: trailing data")
	}
	if p.Version == "" {
		return nil, errors.New("plan has no version")
	}
	if len(p.Full) != 2 {
		return nil, errors.New("plan must name both platform archives")
	}
	for _, platform := range []string{windowsTarget, darwinTarget} {
		if p.Full[platform] == "" {
			return nil, fmt.Errorf("plan has no %s archive", platform)
		}
	}
	for platform := range p.Full {
		if platform != windowsTarget && platform != darwinTarget {
			return nil, fmt.Errorf("plan has unsupported platform %q", platform)
		}
	}
	for index, delta := range p.Deltas {
		if delta.Platform != windowsTarget && delta.Platform != darwinTarget {
			return nil, fmt.Errorf("plan delta %d has unsupported platform %q", index, delta.Platform)
		}
		if delta.From == "" || delta.Path == "" {
			return nil, fmt.Errorf("plan delta %d is incomplete", index)
		}
	}
	return &p, nil
}

func runPlan() error {
	p, err := readPlan()
	if err != nil {
		return err
	}
	trees := map[string]map[string]archiveEntry{}
	for _, platform := range []string{windowsTarget, darwinTarget} {
		contents, err := loadFull(platform, p.Version, p.Full[platform])
		if err != nil {
			return err
		}
		tree, err := deltaTargetTree(platform, contents.tree)
		if err != nil {
			return fmt.Errorf("%s archive: %w", platform, err)
		}
		trees[platform] = tree
	}
	for index, delta := range p.Deltas {
		tree, ok := trees[delta.Platform]
		if !ok {
			return fmt.Errorf("plan delta %d has no %s archive", index, delta.Platform)
		}
		if err := verifyDelta(delta.Path, delta.Platform, delta.From, p.Version, tree); err != nil {
			return fmt.Errorf("%s delta from %s: %w", delta.Platform, delta.From, err)
		}
	}
	return nil
}

func deltaTargetTree(platform string, tree map[string]archiveEntry) (map[string]archiveEntry, error) {
	if platform == windowsTarget {
		return tree, nil
	}
	if platform != darwinTarget {
		return nil, fmt.Errorf("unsupported platform %q", platform)
	}
	prefix := darwinBundle + "/"
	out := map[string]archiveEntry{}
	for name, entry := range tree {
		if name == darwinBundle {
			if entry.kind != 'd' {
				return nil, fmt.Errorf("%s is not a directory", darwinBundle)
			}
			continue
		}
		if !strings.HasPrefix(name, prefix) {
			return nil, fmt.Errorf("entry %q is outside %s", name, darwinBundle)
		}
		rel := strings.TrimPrefix(name, prefix)
		if rel == "" || rel == "." || !fs.ValidPath(rel) {
			return nil, fmt.Errorf("entry %q has an invalid bundle-relative path", name)
		}
		out[rel] = entry
	}
	return out, nil
}

func verifyDelta(filename, platform, from, to string, target map[string]archiveEntry) error {
	info, err := os.Lstat(filename)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("delta is not a regular file")
	}
	size := info.Size()
	if size <= 0 || size > maxDeltaSize {
		return fmt.Errorf("delta size %d is outside the allowed range", size)
	}
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	headLen := len(deltaMagic) + binary.MaxVarintLen64
	head := make([]byte, headLen)
	n, err := f.ReadAt(head, 0)
	if err != nil && err != io.EOF {
		return err
	}
	if n < len(deltaMagic) || !bytes.HasPrefix(head[:n], []byte(deltaMagic)) {
		return errors.New("not a mygo delta 1 file")
	}
	varint := head[len(deltaMagic):n]
	indexLen, k := binary.Uvarint(varint)
	if k <= 0 {
		return errors.New("invalid delta index length")
	}
	if !canonicalUvarint(indexLen, varint[:k]) {
		return errors.New("non-canonical delta index length")
	}
	if indexLen == 0 || indexLen > maxDeltaIndexCompressed {
		return fmt.Errorf("delta index length %d is outside the allowed range", indexLen)
	}
	start := int64(len(deltaMagic) + k)
	if start > size || indexLen > uint64(size-start) {
		return errors.New("truncated delta index")
	}
	compressed := make([]byte, int(indexLen))
	if n, err := f.ReadAt(compressed, start); err != nil || n != len(compressed) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return fmt.Errorf("cannot read the delta index: %w", err)
	}
	indexBytes, err := inflateDeltaIndex(compressed)
	if err != nil {
		return err
	}
	index, err := parseDeltaIndex(indexBytes)
	if err != nil {
		return err
	}
	if index.From != from || index.Version != to {
		return fmt.Errorf(
			"index updates %q to %q, want %q to %q",
			index.From, index.Version, from, to,
		)
	}
	tree, err := deltaTree(index, start+int64(indexLen), size)
	if err != nil {
		return err
	}
	return compareDeltaTree(tree, target)
}

func canonicalUvarint(value uint64, encoded []byte) bool {
	canonical := binary.AppendUvarint(nil, value)
	return bytes.Equal(canonical, encoded)
}

type oneByteReader struct {
	reader *bytes.Reader
}

func (r oneByteReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return r.reader.Read(p[:1])
}

func (r oneByteReader) ReadByte() (byte, error) {
	return r.reader.ReadByte()
}

func inflateDeltaIndex(compressed []byte) ([]byte, error) {
	reader := &bytes.Reader{}
	reader.Reset(compressed)
	source := oneByteReader{reader: reader}
	flateReader := flate.NewReader(source)
	defer flateReader.Close()
	data, err := io.ReadAll(io.LimitReader(flateReader, maxDeltaIndex+1))
	if err != nil {
		return nil, fmt.Errorf("cannot inflate delta index: %w", err)
	}
	if len(data) > maxDeltaIndex {
		return nil, fmt.Errorf("delta index expands beyond %d bytes", maxDeltaIndex)
	}
	if reader.Len() != 0 {
		return nil, errors.New("trailing data after the delta index")
	}
	return data, nil
}

func parseDeltaIndex(data []byte) (*deltaIndex, error) {
	if err := checkJSONNoDuplicates(data); err != nil {
		return nil, fmt.Errorf("invalid delta index: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var index deltaIndex
	if err := dec.Decode(&index); err != nil {
		return nil, fmt.Errorf("invalid delta index: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("invalid delta index: trailing data")
	}
	return &index, nil
}

func checkJSONNoDuplicates(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := checkJSONValue(dec, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func checkJSONValue(dec *json.Decoder, depth int) error {
	if depth > 100 {
		return errors.New("JSON nested too deeply")
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if seen[key] {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = true
			if err := checkJSONValue(dec, depth+1); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
	case '[':
		for dec.More() {
			if err := checkJSONValue(dec, depth+1); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return errors.New("unterminated JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func isHexSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if c < '0' || (c > '9' && c < 'a') || c > 'f' {
			return false
		}
	}
	return true
}

func deltaTree(index *deltaIndex, dataStart, size int64) (map[string]archiveEntry, error) {
	if len(index.Entries) > maxDeltaEntries {
		return nil, fmt.Errorf("delta has more than %d entries", maxDeltaEntries)
	}
	tree := map[string]archiveEntry{}
	seen := map[string]bool{}
	offset := dataStart
	if offset < 0 || offset > size {
		return nil, errors.New("delta data offset is outside the file")
	}
	for entryIndex, entry := range index.Entries {
		name, err := deltaPath(entry.Path)
		if err != nil {
			return nil, fmt.Errorf("delta entry %d: %w", entryIndex, err)
		}
		key := strings.ToLower(name)
		if seen[key] {
			return nil, fmt.Errorf("duplicate delta entry %q", name)
		}
		seen[key] = true
		if entry.Dir {
			if entry.Link != "" || entry.Mode != 0 || entry.Size != 0 ||
				entry.SHA256 != "" || entry.From != "" || entry.Data != 0 {
				return nil, fmt.Errorf("delta directory %q has file or link fields", name)
			}
			tree[name] = archiveEntry{kind: 'd'}
			continue
		}
		if entry.Link != "" {
			if entry.Mode != 0 || entry.Size != 0 || entry.SHA256 != "" ||
				entry.From != "" || entry.Data != 0 {
				return nil, fmt.Errorf("delta link %q has file fields", name)
			}
			if err := checkLink(name, entry.Link); err != nil {
				return nil, err
			}
			tree[name] = archiveEntry{kind: 'l', link: entry.Link}
			continue
		}
		if entry.Mode > 0o777 || !isHexSHA256(entry.SHA256) || entry.Size < 0 || entry.Data < 0 {
			return nil, fmt.Errorf("delta file %q has invalid metadata", name)
		}
		if entry.From == "" && entry.Data == 0 {
			return nil, fmt.Errorf("delta file %q has neither data nor a source", name)
		}
		if entry.From != "" {
			if _, err := deltaPath(entry.From); err != nil {
				return nil, fmt.Errorf("delta file %q has an invalid source: %w", name, err)
			}
		}
		if entry.Data > size-offset {
			return nil, fmt.Errorf("delta file %q has data beyond the file", name)
		}
		offset += entry.Data
		tree[name] = archiveEntry{
			kind:   'f',
			mode:   entry.Mode,
			size:   entry.Size,
			sha256: entry.SHA256,
		}
	}
	if offset != size {
		return nil, fmt.Errorf("delta data ends at %d bytes, want %d", offset, size)
	}
	return tree, nil
}

func compareDeltaTree(got, want map[string]archiveEntry) error {
	for name, entry := range got {
		target, ok := want[name]
		if !ok {
			return fmt.Errorf("delta entry %q is not in the full archive", name)
		}
		if entry.kind != target.kind {
			return fmt.Errorf("delta entry %q has the wrong kind", name)
		}
		switch entry.kind {
		case 'l':
			if entry.link != target.link {
				return fmt.Errorf("delta link %q has target %q, want %q", name, entry.link, target.link)
			}
		case 'f':
			if entry.mode != target.mode || entry.size != target.size || entry.sha256 != target.sha256 {
				return fmt.Errorf("delta file %q does not match the full archive", name)
			}
		}
	}
	for name := range want {
		if _, ok := got[name]; !ok {
			return fmt.Errorf("delta is missing full archive entry %q", name)
		}
	}
	return nil
}

// readArchive reads the required files of a tar.gz archive in place. Every
// entry is checked for canonical paths, duplicates, link targets and bounds;
// no entry is extracted.
func readArchive(platform, filename string) (*archiveContents, error) {
	targets := map[string]int64{}
	switch platform {
	case windowsTarget:
		targets[windowsExecutable] = maxExecutableSize
	case darwinTarget:
		targets[darwinExecutable] = maxExecutableSize
		targets[darwinInfoPlist] = maxInfoPlistSize
	default:
		return nil, fmt.Errorf("unsupported platform %q", platform)
	}

	info, err := os.Lstat(filename)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("archive is not a regular file")
	}
	if info.Size() <= 0 || info.Size() > maxArchiveSize {
		return nil, fmt.Errorf("archive size %d is outside the allowed range", info.Size())
	}
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	gz, err := gzip.NewReader(bufio.NewReader(f))
	if err != nil {
		return nil, fmt.Errorf("not a gzip archive: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	files := map[string][]byte{}
	tree := map[string]archiveEntry{}
	kinds := map[string]byte{}    // canonical lower-case path -> 'd', 'f' or 'l'
	children := map[string]bool{} // lower-case paths that have at least one entry below them
	var total int64
	for entries := 0; ; entries++ {
		if entries >= maxEntries {
			return nil, fmt.Errorf("archive has more than %d entries", maxEntries)
		}
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("invalid tar entry: %w", err)
		}
		name, err := archivePath(hdr.Name)
		if err != nil {
			return nil, err
		}
		key := strings.ToLower(name)
		if _, exists := kinds[key]; exists {
			return nil, fmt.Errorf("duplicate archive entry %q", name)
		}
		if hdr.Size < 0 || hdr.Size > maxEntrySize {
			return nil, fmt.Errorf("archive entry %q has an invalid size", name)
		}
		if total > maxTotalSize-hdr.Size {
			return nil, fmt.Errorf("archive expands beyond %d bytes", maxTotalSize)
		}
		total += hdr.Size

		kind := byte('f')
		switch hdr.Typeflag {
		case tar.TypeReg, tar.TypeRegA:
		case tar.TypeDir:
			if hdr.Size != 0 {
				return nil, fmt.Errorf("directory %q has a non-zero size", name)
			}
			kind = 'd'
		case tar.TypeSymlink:
			if hdr.Size != 0 {
				return nil, fmt.Errorf("link %q has a non-zero size", name)
			}
			if err := checkLink(name, hdr.Linkname); err != nil {
				return nil, err
			}
			kind = 'l'
		default:
			return nil, fmt.Errorf("archive entry %q has unsupported type %d", name, hdr.Typeflag)
		}

		if kind != 'd' {
			if children[key] {
				return nil, fmt.Errorf("entry %q is not a directory but has children", name)
			}
		}
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			parentKey := strings.ToLower(parent)
			if existing, ok := kinds[parentKey]; ok && existing != 'd' {
				return nil, fmt.Errorf("entry %q is below non-directory %q", name, parent)
			}
			children[parentKey] = true
		}
		kinds[key] = kind

		entry := archiveEntry{kind: kind}
		switch kind {
		case 'd':
			// The delta index carries no directory mode.
		case 'l':
			entry.link = hdr.Linkname
		case 'f':
			entry.mode = uint32(fs.FileMode(hdr.Mode).Perm())
			entry.size = hdr.Size
			hash := sha256.New()
			if limit, wanted := targets[name]; wanted {
				if hdr.Size > limit {
					return nil, fmt.Errorf("required file %q exceeds %d bytes", name, limit)
				}
				data := make([]byte, hdr.Size)
				if _, err := io.ReadFull(tr, data); err != nil {
					return nil, fmt.Errorf("cannot read %q: %w", name, err)
				}
				hash.Write(data)
				files[name] = data
			} else {
				n, err := io.Copy(hash, tr)
				if err != nil {
					return nil, fmt.Errorf("cannot read %q: %w", name, err)
				}
				if n != hdr.Size {
					return nil, fmt.Errorf("short read of %q", name)
				}
			}
			entry.sha256 = hex.EncodeToString(hash.Sum(nil))
		}
		if _, wanted := targets[name]; wanted && kind != 'f' {
			return nil, fmt.Errorf("required file %q is not a regular file", name)
		}
		tree[name] = entry
	}

	// archive/tar stops at its end-of-archive blocks, while tar writers pad
	// the gzip stream to a block boundary. The only bytes left must be that
	// bounded zero padding; anything else is trailing content.
	rest, err := io.ReadAll(io.LimitReader(gz, 1<<20+1))
	if err != nil {
		return nil, fmt.Errorf("invalid gzip trailer: %w", err)
	}
	if len(rest) > 1<<20 {
		return nil, errors.New("trailing data after the tar stream")
	}
	for _, b := range rest {
		if b != 0 {
			return nil, errors.New("trailing data after the tar stream")
		}
	}
	for name := range targets {
		if _, ok := files[name]; !ok {
			return nil, fmt.Errorf("archive is missing %q", name)
		}
	}
	return &archiveContents{files: files, tree: tree}, nil
}

func archivePath(raw string) (string, error) {
	if raw == "" || len(raw) > maxPathLength {
		return "", fmt.Errorf("archive entry has an invalid path")
	}
	if strings.ContainsAny(raw, "\\\x00") {
		return "", fmt.Errorf("archive entry %q has an unsafe path", raw)
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("archive entry %q has a control character", raw)
		}
	}
	trimmed := strings.TrimSuffix(raw, "/")
	if trimmed == "" || strings.Contains(trimmed, ":") {
		return "", fmt.Errorf("archive entry %q has an unsafe path", raw)
	}
	clean := path.Clean(trimmed)
	if clean == "." || clean != trimmed || !fs.ValidPath(clean) {
		return "", fmt.Errorf("archive entry %q is not a canonical relative path", raw)
	}
	return clean, nil
}

func deltaPath(raw string) (string, error) {
	if strings.HasSuffix(raw, "/") {
		return "", fmt.Errorf("delta entry %q has a trailing slash", raw)
	}
	return archivePath(raw)
}

func checkLink(name, target string) error {
	if target == "" || len(target) > maxLinkLength || strings.ContainsAny(target, "\\\x00") {
		return fmt.Errorf("link %q has an invalid target", name)
	}
	for _, r := range target {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("link %q has a control character in its target", name)
		}
	}
	if path.IsAbs(target) {
		return fmt.Errorf("link %q has an absolute target", name)
	}
	clean := path.Clean(target)
	if clean == "." {
		return fmt.Errorf("link %q has an invalid target", name)
	}
	resolved := path.Clean(path.Join(path.Dir(name), clean))
	if resolved == "." || !fs.ValidPath(resolved) {
		return fmt.Errorf("link %q points outside the archive", name)
	}
	return nil
}

func verifyWindows(exe []byte, version string) error {
	f, err := pe.NewFile(bytes.NewReader(exe))
	if err != nil {
		return fmt.Errorf("Locklark.exe is not a PE file: %w", err)
	}
	defer f.Close()
	if f.Machine != pe.IMAGE_FILE_MACHINE_AMD64 {
		return fmt.Errorf("Locklark.exe has PE machine %#x, want amd64", f.Machine)
	}
	optional, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		return errors.New("Locklark.exe is not a 64-bit PE file")
	}
	sections, err := peStringSections(f, optional.ImageBase)
	if err != nil {
		return fmt.Errorf("cannot read Locklark.exe sections: %w", err)
	}
	if err := checkBuildInfo(exe, "windows", "amd64"); err != nil {
		return fmt.Errorf("Locklark.exe: %w", err)
	}
	if !hasEmbeddedString(sections, version) {
		return fmt.Errorf("Locklark.exe does not embed an exact Go string for version %q", version)
	}
	if !hasEmbeddedString(sections, appIdentifier) {
		return fmt.Errorf("Locklark.exe does not embed an exact Go string for identifier %q", appIdentifier)
	}
	// mygo build writes a VS_VERSIONINFO resource with these keys. Minimal
	// Go fixtures may omit resources; when they exist, their values must
	// agree with the Go metadata and the release version.
	if rsrc := f.Section(".rsrc"); rsrc != nil {
		data, err := rsrc.Data()
		if err != nil {
			return fmt.Errorf("cannot read the PE resources: %w", err)
		}
		if bytes.Contains(data, utf16LE("MyGoIdentifier")) {
			for _, pair := range [][2]string{
				{"FileVersion", version},
				{"ProductVersion", version},
				{"MyGoIdentifier", appIdentifier},
			} {
				if !bytes.Contains(data, utf16LE(pair[0])) || !bytes.Contains(data, utf16LE(pair[1])) {
					return fmt.Errorf("Locklark.exe resource %s does not match %q", pair[0], pair[1])
				}
			}
		}
	}
	return nil
}

func verifyDarwin(fat, plist []byte, version string) error {
	if err := verifyInfoPlist(plist, version); err != nil {
		return err
	}
	ff, err := macho.NewFatFile(bytes.NewReader(fat))
	if err != nil {
		return fmt.Errorf("macOS executable is not a universal Mach-O: %w", err)
	}
	defer ff.Close()
	if len(ff.Arches) != 2 {
		return fmt.Errorf("macOS executable has %d Mach-O slices, want arm64 and amd64", len(ff.Arches))
	}
	want := map[macho.Cpu]string{
		macho.CpuArm64: "arm64",
		macho.CpuAmd64: "amd64",
	}
	seen := map[macho.Cpu]bool{}
	for _, arch := range ff.Arches {
		if arch.File == nil {
			return errors.New("macOS executable has an unreadable Mach-O slice")
		}
		goarch, ok := want[arch.Cpu]
		if !ok {
			return fmt.Errorf("macOS executable has unexpected slice %s", arch.Cpu)
		}
		if seen[arch.Cpu] {
			return fmt.Errorf("macOS executable repeats slice %s", arch.Cpu)
		}
		seen[arch.Cpu] = true
		if arch.File.Magic != macho.Magic64 {
			return fmt.Errorf("macOS %s slice is not a 64-bit Mach-O", goarch)
		}
		offset, size := int64(arch.Offset), int64(arch.Size)
		if size <= 0 || offset < 0 || offset > int64(len(fat)) || size > int64(len(fat))-offset {
			return fmt.Errorf("macOS %s slice is outside the file", goarch)
		}
		slice := fat[offset : offset+size]
		if err := checkBuildInfo(slice, "darwin", goarch); err != nil {
			return fmt.Errorf("macOS %s slice: %w", goarch, err)
		}
		sections, err := machoStringSections(arch.File)
		if err != nil {
			return fmt.Errorf("macOS %s slice sections: %w", goarch, err)
		}
		if !hasEmbeddedString(sections, version) {
			return fmt.Errorf("macOS %s slice does not embed an exact Go string for version %q", goarch, version)
		}
		if !hasEmbeddedString(sections, appIdentifier) {
			return fmt.Errorf("macOS %s slice does not embed an exact Go string for identifier %q", goarch, appIdentifier)
		}
	}
	if !seen[macho.CpuArm64] || !seen[macho.CpuAmd64] {
		return errors.New("macOS executable does not have both arm64 and amd64 slices")
	}
	return nil
}

type stringSection struct {
	name string
	addr uint64
	data []byte
}

func peStringSections(f *pe.File, imageBase uint64) ([]stringSection, error) {
	sections := make([]stringSection, 0, len(f.Sections))
	for _, section := range f.Sections {
		data, err := section.Data()
		if err != nil {
			return nil, err
		}
		sections = append(sections, stringSection{
			name: section.Name,
			addr: imageBase + uint64(section.VirtualAddress),
			data: data,
		})
	}
	return sections, nil
}

func machoStringSections(f *macho.File) ([]stringSection, error) {
	sections := make([]stringSection, 0, len(f.Sections))
	for _, section := range f.Sections {
		data, err := section.Data()
		if err != nil {
			return nil, err
		}
		sections = append(sections, stringSection{
			name: section.Name,
			addr: uint64(section.Addr),
			data: data,
		})
	}
	return sections, nil
}

// hasExactGoString reports whether value is stored as an exact Go string.
// A Go string variable is a 16-byte header: the address of its bytes and
// their length. Merely finding value as a substring would accept another
// version such as 1.2.3-rc1 when 1.2.3 is expected.
func hasExactGoString(sections []stringSection, value string) bool {
	needle := []byte(value)
	if len(needle) == 0 {
		return false
	}
	var header [16]byte
	binary.LittleEndian.PutUint64(header[8:], uint64(len(needle)))
	for _, source := range sections {
		for offset := 0; ; {
			index := bytes.Index(source.data[offset:], needle)
			if index < 0 {
				break
			}
			offset += index
			binary.LittleEndian.PutUint64(header[:8], source.addr+uint64(offset))
			for _, holder := range sections {
				if bytes.Contains(holder.data, header[:]) {
					return true
				}
			}
			offset++
		}
	}
	return false
}

// hasEmbeddedString accepts either an exact Go string header or, as the
// external linker used by cgo emits them, a NUL-delimited string. The latter
// still rejects a longer version such as 1.2.3-rc1 when 1.2.3 is expected,
// and a longer identifier.
func hasEmbeddedString(sections []stringSection, value string) bool {
	if hasExactGoString(sections, value) {
		return true
	}
	needle := []byte(value)
	if len(needle) == 0 {
		return false
	}
	for _, source := range sections {
		for offset := 0; ; {
			index := bytes.Index(source.data[offset:], needle)
			if index < 0 {
				break
			}
			index += offset
			before := index == 0 || source.data[index-1] == 0
			afterIndex := index + len(needle)
			after := afterIndex == len(source.data) || source.data[afterIndex] == 0
			if before && after {
				return true
			}
			offset = index + 1
		}
	}
	return false
}

func checkBuildInfo(executable []byte, goos, goarch string) error {
	bi, err := buildinfo.Read(bytes.NewReader(executable))
	if err != nil {
		return fmt.Errorf("not a Go binary: %w", err)
	}
	if got := buildSetting(bi, "GOOS"); got != goos {
		return fmt.Errorf("Go GOOS is %q, want %q", got, goos)
	}
	if got := buildSetting(bi, "GOARCH"); got != goarch {
		return fmt.Errorf("Go GOARCH is %q, want %q", got, goarch)
	}
	return nil
}

func buildSetting(bi *buildinfo.BuildInfo, key string) string {
	for _, setting := range bi.Settings {
		if setting.Key == key {
			return setting.Value
		}
	}
	return ""
}

func utf16LE(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 2*len(units))
	for i, unit := range units {
		binary.LittleEndian.PutUint16(out[2*i:], unit)
	}
	return out
}

func verifyInfoPlist(data []byte, version string) error {
	values, err := parsePlist(data)
	if err != nil {
		return fmt.Errorf("Info.plist: %w", err)
	}
	if got := values["CFBundleIdentifier"]; got != appIdentifier {
		return fmt.Errorf("Info.plist CFBundleIdentifier is %q, want %q", got, appIdentifier)
	}
	short, shortOK := values["CFBundleShortVersionString"]
	bundle, bundleOK := values["CFBundleVersion"]
	if !shortOK && !bundleOK {
		return errors.New("Info.plist has no bundle version")
	}
	if shortOK && short != version {
		return fmt.Errorf("Info.plist CFBundleShortVersionString is %q, want %q", short, version)
	}
	if bundleOK && bundle != version {
		return fmt.Errorf("Info.plist CFBundleVersion is %q, want %q", bundle, version)
	}
	return nil
}

// parsePlist reads the top-level string values of an XML property list. It
// ignores nested values, which Info.plist does not use for these keys.
func parsePlist(data []byte) (map[string]string, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil, errors.New("no plist dictionary")
		}
		if err != nil {
			return nil, err
		}
		if start, ok := tok.(xml.StartElement); ok && start.Name.Local == "dict" {
			return parsePlistDict(dec)
		}
	}
}

func parsePlistDict(dec *xml.Decoder) (map[string]string, error) {
	values := map[string]string{}
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch node := tok.(type) {
		case xml.StartElement:
			if node.Name.Local != "key" {
				return nil, fmt.Errorf("unexpected plist element %q", node.Name.Local)
			}
			var key string
			if err := dec.DecodeElement(&key, &node); err != nil {
				return nil, err
			}
			value, err := readPlistValue(dec)
			if err != nil {
				return nil, err
			}
			if _, exists := values[key]; exists {
				return nil, fmt.Errorf("duplicate plist key %q", key)
			}
			values[key] = value
		case xml.EndElement:
			if node.Name.Local == "dict" {
				return values, nil
			}
		}
	}
}

func readPlistValue(dec *xml.Decoder) (string, error) {
	tok, err := dec.Token()
	if err != nil {
		return "", err
	}
	start, ok := tok.(xml.StartElement)
	if !ok {
		return "", errors.New("plist key has no value")
	}
	switch start.Name.Local {
	case "string":
		var value string
		if err := dec.DecodeElement(&value, &start); err != nil {
			return "", err
		}
		return value, nil
	default:
		if err := dec.Skip(); err != nil {
			return "", err
		}
		return "", nil
	}
}
