// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package boundedmeta

import "encoding/binary"

// AppendUint32 appends one canonical big-endian uint32.
func AppendUint32(dst []byte, value uint32) []byte {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	return append(dst, encoded[:]...)
}

// AppendUint64 appends one canonical big-endian uint64.
func AppendUint64(dst []byte, value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return append(dst, encoded[:]...)
}

// AppendField appends one uint32-length-prefixed byte field.
func AppendField(dst, value []byte) []byte {
	dst = AppendUint32(dst, uint32(len(value)))
	return append(dst, value...)
}
