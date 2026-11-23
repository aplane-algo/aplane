// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

//go:build linux || darwin

package fsutil

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"

	"golang.org/x/sys/unix"
)

// RegularFileSHA256 hashes one regular file without following a
// final-component symlink.
func RegularFileSHA256(path string) (string, int64, error) {
	file, _, err := openRegularFile(path)
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

// RegularFileSHA256Limited hashes one regular file of at most max bytes without
// following a final-component symlink, rejecting oversized files rather than
// hashing past the cap.
func RegularFileSHA256Limited(path string, max int64) (string, int64, error) {
	if max < 0 || max == math.MaxInt64 {
		return "", 0, fmt.Errorf("invalid regular-file size limit %d", max)
	}
	file, info, err := openRegularFile(path)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = file.Close() }()
	if info.Size() > max {
		return "", 0, fmt.Errorf("%w %d", ErrFileTooLarge, max)
	}
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(file, max+1))
	if err != nil {
		return "", 0, err
	}
	if size > max {
		return "", 0, fmt.Errorf("%w %d", ErrFileTooLarge, max)
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

// ReadRegularFile reads one regular file without following a final-component
// symlink and returns its permission bits.
func ReadRegularFile(path string) ([]byte, os.FileMode, error) {
	file, info, err := openRegularFile(path)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, 0, err
	}
	return data, info.Mode().Perm(), nil
}

// ReadRegularFileLimited reads no more than max+1 bytes without following a
// final-component symlink, then rejects rather than truncates an oversized
// regular file.
func ReadRegularFileLimited(path string, max int64) ([]byte, os.FileMode, error) {
	if max < 0 || max == math.MaxInt64 {
		return nil, 0, fmt.Errorf("invalid regular-file size limit %d", max)
	}
	file, info, err := openRegularFile(path)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = file.Close() }()
	if info.Size() > max {
		return nil, 0, fmt.Errorf("%w %d", ErrFileTooLarge, max)
	}
	data, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil {
		return nil, 0, err
	}
	if int64(len(data)) > max {
		return nil, 0, fmt.Errorf("%w %d", ErrFileTooLarge, max)
	}
	return data, info.Mode().Perm(), nil
}

func openRegularFile(path string) (*os.File, os.FileInfo, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, nil, fmt.Errorf("%w: %s: %w", ErrNotRegularFile, path, err)
		}
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, nil, fmt.Errorf("%w: %s", ErrNotRegularFile, path)
	}
	return file, info, nil
}
