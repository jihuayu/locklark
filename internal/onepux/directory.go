package onepux

import (
	"bytes"
	"encoding/binary"
)

// Cap directory objects before archive/zip allocates them. This inventory
// profile accepts a single-disk, non-ZIP64 EOCD with no trailing payload.
// Local ZIP64 size fields remain subject to the ordinary entry bounds.
func directoryBudget(data []byte) error {
	end := -1
	for i := len(data) - 22; i >= max(0, len(data)-22-65535); i-- {
		if bytes.Equal(data[i:i+4], []byte{'P', 'K', 5, 6}) {
			// Match archive/zip's last-signature selection. Do not skip a
			// malformed later signature and validate a different directory.
			if int(binary.LittleEndian.Uint16(data[i+20:i+22])) != len(data)-i-22 {
				return ErrInvalid
			}
			end = i
			break
		}
	}
	if end < 0 {
		return ErrInvalid
	}
	e := data[end:]
	if binary.LittleEndian.Uint16(e[4:6]) != 0 || binary.LittleEndian.Uint16(e[6:8]) != 0 {
		return ErrUnsupported
	}
	count := binary.LittleEndian.Uint16(e[10:12])
	size, offset := binary.LittleEndian.Uint32(e[12:16]), binary.LittleEndian.Uint32(e[16:20])
	if count == 0xffff || size == 0xffffffff || offset == 0xffffffff {
		return ErrUnsupported
	}
	if count > MaxEntries {
		return ErrLimit
	}
	if binary.LittleEndian.Uint16(e[8:10]) != count || uint64(offset)+uint64(size) != uint64(end) {
		return ErrInvalid
	}
	seen := 0
	for at := int(offset); at < end; {
		if end-at < 46 || !bytes.Equal(data[at:at+4], []byte{'P', 'K', 1, 2}) {
			return ErrInvalid
		}
		if binary.LittleEndian.Uint16(data[at+34:at+36]) != 0 {
			return ErrUnsupported
		}
		seen++
		if seen > MaxEntries {
			return ErrLimit
		}
		name := int(binary.LittleEndian.Uint16(data[at+28 : at+30]))
		extra := int(binary.LittleEndian.Uint16(data[at+30 : at+32]))
		comment := int(binary.LittleEndian.Uint16(data[at+32 : at+34]))
		if name > 1024 {
			return ErrLimit
		}
		length := 46 + name + extra + comment
		if length > end-at {
			return ErrInvalid
		}
		at += length
	}
	if seen != int(count) {
		return ErrInvalid
	}
	return nil
}
