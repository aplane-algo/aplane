// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

//go:build !linux && !darwin

package fsutil

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"os"
)

// RegularFileSHA256 hashes one regular file. Server binaries are supported on
// Linux and Darwin, where the implementation also rejects final-component
// symlinks atomically.
func RegularFileSHA256(path string) (string, int64, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", 0, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", 0, fmt.Errorf("path is not a regular file: %s", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = file.Close() }()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

// ReadRegularFile reads one regular file and returns its permission bits.
// Server binaries use the Linux/Darwin implementation, which rejects
// final-component symlinks atomically.
func ReadRegularFile(path string) ([]byte, os.FileMode, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, 0, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("path is not a regular file: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	return data, info.Mode().Perm(), nil
}

// ReadRegularFileLimited reads no more than max+1 bytes and rejects rather
// than truncates an oversized regular file. Server platforms use the
// Linux/Darwin implementation, which also rejects final-component symlinks
// atomically.
func ReadRegularFileLimited(path string, max int64) ([]byte, os.FileMode, error) {
	if max < 0 || max == math.MaxInt64 {
		return nil, 0, fmt.Errorf("invalid regular-file size limit %d", max)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, 0, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("path is not a regular file: %s", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil {
		return nil, 0, err
	}
	if int64(len(data)) > max {
		return nil, 0, fmt.Errorf("file exceeds size limit %d", max)
	}
	return data, info.Mode().Perm(), nil
}
