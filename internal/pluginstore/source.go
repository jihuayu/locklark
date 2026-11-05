package pluginstore

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
)

// ReadPackage reads a bounded regular source without extracting or executing it.
// Once returned, callers verify and commit these same bytes, never reopen a path.
func ReadPackage(path string) ([]byte, error) {
	return readRegular(path, MaxPackage)
}
func readRegular(path string, limit int) ([]byte, error) {
	f, e := os.OpenFile(path, os.O_RDONLY|nonblock, 0)
	if e != nil {
		return nil, ErrInvalid
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > int64(limit) {
		return nil, ErrInvalid
	}
	raw, e := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if e != nil || len(raw) > limit {
		return nil, ErrInvalid
	}
	return raw, nil
}

// ReadPins reads operator-controlled public trust configuration. Whitespace is
// allowed here; duplicates, non-string values and unbounded maps are rejected.
func ReadPins(path string) (Pins, error) {
	raw, e := readRegular(path, 16<<10)
	if e != nil {
		return nil, e
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, e := d.Token()
	if e != nil || token != json.Delim('{') {
		return nil, ErrInvalid
	}
	pins := Pins{}
	for d.More() {
		if len(pins) >= maxPlugins {
			return nil, ErrInvalid
		}
		token, e := d.Token()
		id, ok := token.(string)
		if e != nil || !ok || pins[id] != "" {
			return nil, ErrInvalid
		}
		var pub string
		if d.Decode(&pub) != nil || pub == "" {
			return nil, ErrInvalid
		}
		pins[id] = pub
	}
	if token, e = d.Token(); e != nil || token != json.Delim('}') {
		return nil, ErrInvalid
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, ErrInvalid
	}
	return copyPins(pins)
}
