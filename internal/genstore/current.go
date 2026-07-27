// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package genstore implements generation-based active storage
// (docs/ARCH_GENERATIONS.md): reading and durably replacing the CURRENT
// pointer, the generation manifest and seal records, and the strict
// structural validator. CURRENT is the sole commit record; a published but
// uncommitted generation is discarded, never resumed.
package genstore

import (
	"fmt"
	"os"
	"strings"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// maxCurrentPointerSize bounds CURRENT reads; a well-formed pointer is one
// generation ID plus a newline.
const maxCurrentPointerSize = 128

// ReadCurrent returns the generation ID named by identities/<id>/CURRENT.
// Strict: the pointer must be a regular file containing exactly one
// well-formed generation ID (trailing newline permitted), and the named
// generation directory must exist as a regular directory. Any deviation is
// an error; callers fail closed into recovery, never guess a generation.
func ReadCurrent(paths storepaths.Paths, identityID string) (string, error) {
	pointerPath := paths.CurrentPointerPath(identityID)
	info, err := os.Lstat(pointerPath)
	if err != nil {
		return "", fmt.Errorf("read CURRENT pointer: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", fmt.Errorf("CURRENT pointer is not a regular file: %s", pointerPath)
	}
	if info.Size() > maxCurrentPointerSize {
		return "", fmt.Errorf("CURRENT pointer is malformed (%d bytes)", info.Size())
	}
	data, _, err := fsutil.ReadRegularFile(pointerPath)
	if err != nil {
		return "", fmt.Errorf("read CURRENT pointer: %w", err)
	}
	generationID := strings.TrimSuffix(string(data), "\n")
	if strings.ContainsAny(generationID, "\n\r\x00") {
		return "", fmt.Errorf("CURRENT pointer is malformed")
	}
	if err := storepaths.ValidateGenerationID(generationID); err != nil {
		return "", fmt.Errorf("CURRENT pointer: %w", err)
	}
	if err := requireRegularDirectory(paths.GenerationDir(identityID, generationID)); err != nil {
		return "", fmt.Errorf("selected generation: %w", err)
	}
	return generationID, nil
}

// WriteCurrent durably points CURRENT at generationID: temp file, fsync,
// rename over CURRENT, fsync the identity directory. The caller must already
// have published and fsynced the generation directory (and sealed the
// outgoing generation) per the commit protocol.
func WriteCurrent(paths storepaths.Paths, identityID, generationID string) error {
	if err := storepaths.ValidateGenerationID(generationID); err != nil {
		return err
	}
	if err := requireRegularDirectory(paths.GenerationDir(identityID, generationID)); err != nil {
		return fmt.Errorf("refusing to point CURRENT at %s: %w", generationID, err)
	}
	return fsutil.WriteFileDurable(paths.CurrentPointerPath(identityID), []byte(generationID+"\n"))
}

// Resolve reads CURRENT once and returns the bound generation paths.
// Mutating callers must hold the identity mutation lock across Resolve and
// every use of the result; never re-resolve mid-operation.
func Resolve(paths storepaths.Paths, identityID string) (storepaths.GenPaths, error) {
	generationID, err := ReadCurrent(paths, identityID)
	if err != nil {
		return storepaths.GenPaths{}, err
	}
	return paths.GenerationPaths(identityID, generationID), nil
}

// IsGenerational reports whether the identity store uses the generation
// layout (a CURRENT pointer exists). It deliberately does not validate the
// pointer: layout detection and pointer validation are separate failures.
func IsGenerational(paths storepaths.Paths, identityID string) (bool, error) {
	_, err := os.Lstat(paths.CurrentPointerPath(identityID))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func requireRegularDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("not a regular directory: %s", path)
	}
	return nil
}
