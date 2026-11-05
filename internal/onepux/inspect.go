// Package onepux inventories a bounded plaintext 1PUX v3 archive in memory.
// It never extracts files, authenticates an origin or authorizes migration.
package onepux

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	MaxArchive  = 8 << 20
	MaxExpanded = 16 << 20
	MaxEntry    = 8 << 20
	MaxJSON     = 4 << 20
	MaxEntries  = 1024
	MaxObjects  = 4096
	MaxNodes    = 100000
	MaxDepth    = 32
)

var ErrInvalid = errors.New("invalid 1PUX archive")
var ErrUnsupported = errors.New("unsupported 1PUX archive feature")
var ErrLimit = errors.New("1PUX inventory capacity exceeded")

type Category struct {
	Code  string `json:"code"`
	Items int    `json:"items"`
}

// FileReferenceReport describes only literal item.file.path references. Files
// without these links may be icons or use other unimplemented link layouts;
// they are not proven orphans and must never be deleted based on this report.
type FileReferenceReport struct {
	Explicit                  int `json:"explicit"`
	Matched                   int `json:"matched"`
	Missing                   int `json:"missing"`
	Repeated                  int `json:"repeated"`
	LinkedFiles               int `json:"linked_files"`
	FilesWithoutExplicitLinks int `json:"files_without_explicit_links"`
	ItemsWithoutExplicitPath  int `json:"items_without_explicit_path"`
	SizeMismatches            int `json:"size_mismatches"`
}

// Report contains counts and fixed reason codes, not names, IDs, paths or
// values. Category codes are restricted to three ASCII decimal digits.
// Successful inventory always leaves MappingVerified false: no general
// importer has proved a lossless mapping for any item in this archive.
type Report struct {
	LoginFieldInventory LoginFieldReport    `json:"login_field_inventory"`
	SectionInventory    SectionReport       `json:"section_inventory"`
	Version             int                 `json:"version"`
	Accounts            int                 `json:"accounts"`
	Vaults              int                 `json:"vaults"`
	Items               int                 `json:"items"`
	Active              int                 `json:"active"`
	Archived            int                 `json:"archived"`
	OtherStates         int                 `json:"other_states"`
	Files               int                 `json:"files"`
	FileBytes           uint64              `json:"file_bytes"`
	FileReferences      FileReferenceReport `json:"file_references"`
	Categories          []Category          `json:"categories"`
	UnmappedItems       int                 `json:"unmapped_items"`
	MappingVerified     bool                `json:"mapping_verified"`
	ReviewReasons       []string            `json:"review_reasons"`
}

// Inspect accepts an immutable byte snapshot owned by the caller, not a path.
// Neither the version tag nor the counts prove a genuine 1Password origin.
// All errors return a zero report and fixed, input-free error text.
func Inspect(archive []byte) (Report, error) {
	if len(archive) > MaxArchive {
		return Report{}, ErrLimit
	}
	if err := directoryBudget(archive); err != nil {
		return Report{}, err
	}
	z, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return Report{}, ErrInvalid
	}
	if len(z.File) > MaxEntries {
		return Report{}, ErrLimit
	}
	seen := map[string]bool{}
	var expanded uint64
	// Validate every header before inflating any entry.
	for _, f := range z.File {
		if len(f.Name) > 1024 {
			return Report{}, ErrLimit
		}
		kind := f.Mode().Type()
		if !archiveName(f.Name) || kind != 0 && kind != fs.ModeDir {
			return Report{}, ErrInvalid
		}
		folded := strings.ToLower(f.Name)
		if seen[folded] {
			return Report{}, ErrInvalid
		}
		seen[folded] = true
		if f.Mode().IsDir() {
			if f.Name != "files/" || f.UncompressedSize64 != 0 || f.CompressedSize64 != 0 || f.CRC32 != 0 {
				return Report{}, ErrInvalid
			}
		} else if f.Name != "export.attributes" && f.Name != "export.data" && !strings.HasPrefix(f.Name, "files/") {
			return Report{}, ErrUnsupported
		}
		if f.Flags&0x41 != 0 || f.Method != zip.Store && f.Method != zip.Deflate {
			return Report{}, ErrUnsupported
		}
		if f.CompressedSize64 > uint64(len(archive)) {
			return Report{}, ErrInvalid
		}
		if f.UncompressedSize64 > MaxEntry || f.UncompressedSize64 > MaxExpanded-expanded {
			return Report{}, ErrLimit
		}
		if (f.Name == "export.attributes" || f.Name == "export.data") && f.UncompressedSize64 > MaxJSON {
			return Report{}, ErrLimit
		}
		expanded += f.UncompressedSize64
	}
	var report Report
	files := map[string]uint64{}
	var attributes, data map[string]any
	for _, f := range z.File {
		if f.Mode().IsDir() {
			continue
		}
		keep := f.Name == "export.attributes" || f.Name == "export.data"
		limit := int64(MaxEntry)
		if keep {
			limit = MaxJSON
		}
		raw, n, err := readEntry(f, limit, keep)
		if err != nil {
			return Report{}, err
		}
		if !keep {
			report.Files++
			report.FileBytes += uint64(n)
			files[f.Name] = uint64(n)
			continue
		}
		object, err := decodeObject(raw)
		if err != nil {
			return Report{}, err
		}
		if f.Name == "export.attributes" {
			attributes = object
		} else {
			data = object
		}
	}
	if attributes == nil || data == nil {
		return Report{}, ErrInvalid
	}
	version, ok := attributes["version"].(json.Number)
	n, err := strconv.ParseInt(string(version), 10, 64)
	if !ok || err != nil || strconv.FormatInt(n, 10) != string(version) {
		return Report{}, ErrInvalid
	}
	if n != 3 || attributes["description"] != "1Password Unencrypted Export" {
		return Report{}, ErrUnsupported
	}
	stamp, ok := attributes["createdAt"].(json.Number)
	n, err = strconv.ParseInt(string(stamp), 10, 64)
	if !ok || err != nil || n < 0 || strconv.FormatInt(n, 10) != string(stamp) {
		return Report{}, ErrInvalid
	}
	reasons := map[string]bool{"mapping-not-implemented": true}
	if report.Files > 0 {
		reasons["file-linkage-unverified"] = true
	}
	if extra(attributes, "version", "description", "createdAt") {
		reasons["additional-metadata"] = true
	}
	if err = inventory(data, &report, reasons, files); err != nil {
		return Report{}, err
	}
	report.Version, report.UnmappedItems = 3, report.Items
	for reason := range reasons {
		report.ReviewReasons = append(report.ReviewReasons, reason)
	}
	sort.Strings(report.ReviewReasons)
	return report, nil
}

func archiveName(name string) bool {
	if name == "" || !utf8.ValidString(name) || strings.ContainsAny(name, "\\:") || strings.HasPrefix(name, "/") {
		return false
	}
	for _, c := range name {
		if unicode.IsControl(c) {
			return false
		}
	}
	plain := strings.TrimSuffix(name, "/")
	if path.Clean(plain) != plain {
		return false
	}
	parts := strings.Split(plain, "/")
	if len(parts) > 2 {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return false
		}
	}
	return len(parts) != 2 || parts[0] == "files"
}

func readEntry(f *zip.File, limit int64, keep bool) ([]byte, int64, error) {
	r, err := f.Open()
	if err != nil {
		return nil, 0, ErrInvalid
	}
	var out bytes.Buffer
	var dst io.Writer = io.Discard
	if keep {
		dst = &out
	}
	n, err := io.Copy(dst, io.LimitReader(r, limit+1))
	closed := r.Close()
	if n > limit {
		return nil, 0, ErrLimit
	}
	if err != nil || closed != nil || uint64(n) != f.UncompressedSize64 {
		return nil, 0, ErrInvalid
	}
	return out.Bytes(), n, nil
}
