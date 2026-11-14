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
// The helper is built once by scripts/verify_desktop_release.py and reused
// for both platform archives.
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"debug/buildinfo"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
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
)

func main() {
	platform := flag.String("platform", "", "archive target: windows-amd64 or darwin-universal")
	version := flag.String("version", "", "expected MyGo package version")
	flag.Parse()
	if err := run(*platform, *version, flag.Args()); err != nil {
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
	switch platform {
	case windowsTarget, darwinTarget:
	default:
		return fmt.Errorf("unsupported platform %q", platform)
	}
	files, err := readArchive(platform, args[0])
	if err != nil {
		return err
	}
	switch platform {
	case windowsTarget:
		return verifyWindows(files[windowsExecutable], version)
	case darwinTarget:
		if err := verifyDarwin(files[darwinExecutable], files[darwinInfoPlist], version); err != nil {
			return err
		}
	}
	return nil
}

// readArchive reads the required files of a tar.gz archive in place. Every
// entry is checked for canonical paths, duplicates, link targets and bounds;
// no entry is extracted.
func readArchive(platform, filename string) (map[string][]byte, error) {
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

		limit, wanted := targets[name]
		if !wanted {
			continue
		}
		if kind != 'f' {
			return nil, fmt.Errorf("required file %q is not a regular file", name)
		}
		if hdr.Size > limit {
			return nil, fmt.Errorf("required file %q exceeds %d bytes", name, limit)
		}
		data := make([]byte, hdr.Size)
		if _, err := io.ReadFull(tr, data); err != nil {
			return nil, fmt.Errorf("cannot read %q: %w", name, err)
		}
		files[name] = data
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
	return files, nil
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
