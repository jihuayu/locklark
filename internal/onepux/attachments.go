package onepux

import (
	"encoding/json"
	"strconv"
	"strings"
)

// Names and sizes here come only from CRC/length-checked files. Source paths
// remain private and are matched literally, never opened or normalized.
type fileInventory struct {
	files   map[string]uint64
	targets map[string]bool
	linked  map[string]bool
}

func (f *fileInventory) item(item map[string]any, r *FileReferenceReport, reasons map[string]bool) error {
	details, _ := item["details"].(map[string]any) // Already checked by inventory.
	rawDoc, hasDoc := details["documentAttributes"]
	var expected uint64
	hasSize := false
	if hasDoc {
		doc, ok := rawDoc.(map[string]any)
		if !ok {
			return ErrInvalid
		}
		if extra(doc, "documentId", "fileName", "decryptedSize") {
			reasons["additional-metadata"] = true
		}
		if value, exists := doc["decryptedSize"]; exists {
			number, ok := value.(json.Number)
			n, err := strconv.ParseUint(string(number), 10, 64)
			if !ok || err != nil || strconv.FormatUint(n, 10) != string(number) {
				return ErrInvalid
			}
			expected, hasSize = n, true
		}
	}
	rawFile, hasFile := item["file"]
	if hasDoc || hasFile || item["categoryUuid"] == "114" {
		reasons["file-linkage-unverified"] = true
	}
	if hasFile {
		file, ok := rawFile.(map[string]any)
		if !ok {
			return ErrInvalid
		}
		if extra(file, "attrs", "path") {
			reasons["additional-metadata"] = true
		}
		if rawAttrs, exists := file["attrs"]; exists {
			attrs, ok := rawAttrs.(map[string]any)
			if !ok {
				return ErrInvalid
			}
			if len(attrs) > 0 {
				reasons["file-attributes-unmapped"] = true
			}
		}
		if value, exists := file["path"]; exists {
			name, ok := value.(string)
			if !ok {
				return ErrInvalid
			}
			if len(name) > 1024 {
				return ErrLimit
			}
			if !archiveName(name) || strings.HasSuffix(name, "/") || name == "export.data" || name == "export.attributes" {
				return ErrInvalid
			}
			if !strings.HasPrefix(name, "files/") {
				return ErrUnsupported
			}
			r.Explicit++
			if f.targets[name] {
				r.Repeated++
				reasons["repeated-file-reference"] = true
			}
			f.targets[name] = true
			size, found := f.files[name]
			if !found {
				r.Missing++
				reasons["missing-referenced-file"] = true
				return nil
			}
			r.Matched++
			if !f.linked[name] {
				f.linked[name] = true
				r.LinkedFiles++
			}
			if hasSize && expected != size {
				r.SizeMismatches++
				reasons["file-size-mismatch"] = true
			}
			return nil
		}
	}
	if hasDoc || hasFile || item["categoryUuid"] == "114" {
		r.ItemsWithoutExplicitPath++
		reasons["file-path-not-provided"] = true
	}
	return nil
}
