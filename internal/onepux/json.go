package onepux

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"
)

func decodeObject(data []byte) (map[string]any, error) {
	if !utf8.Valid(data) || !pairedEscapes(data) {
		return nil, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	nodes := 0
	var walk func(int) error
	walk = func(depth int) error {
		nodes++
		if depth > MaxDepth || nodes > MaxNodes {
			return ErrLimit
		}
		token, err := d.Token()
		if err != nil {
			return ErrInvalid
		}
		switch token {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				t, err := d.Token()
				key, ok := t.(string)
				if err != nil || !ok {
					return ErrInvalid
				}
				nodes++
				if nodes > MaxNodes || len(key) > 256 {
					return ErrLimit
				}
				for _, c := range key {
					if c > 127 {
						return ErrUnsupported
					}
				}
				folded := strings.ToLower(key)
				if seen[folded] {
					return ErrInvalid
				}
				seen[folded] = true
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
			if end, err := d.Token(); err != nil || end != json.Delim('}') {
				return ErrInvalid
			}
		case json.Delim('['):
			for d.More() {
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
			if end, err := d.Token(); err != nil || end != json.Delim(']') {
				return ErrInvalid
			}
		case json.Delim('}'), json.Delim(']'):
			return ErrInvalid
		}
		return nil
	}
	if err := walk(0); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrInvalid
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var object map[string]any
	if err := d.Decode(&object); err != nil || object == nil {
		return nil, ErrInvalid
	}
	return object, nil
}

// encoding/json replaces isolated UTF-16 surrogates with U+FFFD. Reject those
// escapes rather than silently normalizing source metadata or identities.
func pairedEscapes(data []byte) bool {
	hex4 := func(s []byte) (uint16, bool) {
		var n uint16
		for _, c := range s {
			n <<= 4
			switch {
			case c >= '0' && c <= '9':
				n += uint16(c - '0')
			case c >= 'a' && c <= 'f':
				n += uint16(c-'a') + 10
			case c >= 'A' && c <= 'F':
				n += uint16(c-'A') + 10
			default:
				return 0, false
			}
		}
		return n, true
	}
	for i := 0; i < len(data); i++ {
		if data[i] != '"' {
			continue
		}
		i++
		for i < len(data) && data[i] != '"' {
			if data[i] != '\\' {
				i++
				continue
			}
			i++
			if i >= len(data) {
				return false
			}
			if data[i] != 'u' {
				i++
				continue
			}
			if i+5 > len(data) {
				return false
			}
			n, ok := hex4(data[i+1 : i+5])
			if !ok || n >= 0xdc00 && n <= 0xdfff {
				return false
			}
			i += 5
			if n >= 0xd800 && n <= 0xdbff {
				if i+6 > len(data) || data[i] != '\\' || data[i+1] != 'u' {
					return false
				}
				low, ok := hex4(data[i+2 : i+6])
				if !ok || low < 0xdc00 || low > 0xdfff {
					return false
				}
				i += 6
			}
		}
	}
	return true
}
