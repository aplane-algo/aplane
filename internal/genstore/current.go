// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package genstore implements generation-based active storage
// (docs/ARCH_GENERATIONS.md): reading and durably replacing the CURRENT
// pointer, the generation manifest and seal records, and the strict
// structural validator. CURRENT is the sole commit record; a published but
// uncommitted generation is discarded, never resumed.
package genstore

import (
	"errors"
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
func ReadCurrent(paths storepaths.Paths) (string, error) {
	pointerPath := paths.CurrentPointerPath()
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
	if err := requireRegularDirectory(paths.GenerationDir(generationID)); err != nil {
		return "", fmt.Errorf("selected generation: %w", err)
	}
	return generationID, nil
}

// ErrCommitDurabilityUnknown reports that CURRENT names the new generation
// but the directory sync that makes the flip durable could not be confirmed:
// the commit is visible now and may or may not survive a power loss. Callers
// must treat the store state as uncertain — reload against the visible state
// and enter recovery mode rather than assuming nothing was committed.
var ErrCommitDurabilityUnknown = fmt.Errorf("CURRENT flip visible but its durability is unconfirmed")

// WriteCurrent durably points CURRENT at generationID: temp file, fsync,
// rename over CURRENT, fsync the identity directory. The caller must already
// have published and fsynced the generation directory (and sealed the
// outgoing generation) per the commit protocol.
//
// A failure after the rename is not "nothing committed": CURRENT already
// names the new generation. WriteCurrent detects that window, retries the
// directory sync once, and otherwise returns ErrCommitDurabilityUnknown.
func WriteCurrent(paths storepaths.Paths, generationID string) error {
	if err := storepaths.ValidateGenerationID(generationID); err != nil {
		return err
	}
	if err := requireRegularDirectory(paths.GenerationDir(generationID)); err != nil {
		return fmt.Errorf("refusing to point CURRENT at %s: %w", generationID, err)
	}
	writeErr := fsutil.WriteFileDurable(paths.CurrentPointerPath(), []byte(generationID+"\n"))
	if writeErr == nil {
		return nil
	}
	current, readErr := ReadCurrent(paths)
	if readErr != nil {
		if errors.Is(readErr, os.ErrNotExist) {
			// An absent pointer proves non-commit: a rename cannot remove
			// its destination, so the pointer was never created — the
			// first-ever flip failed before publishing anything.
			return writeErr
		}
		// Any other read failure proves nothing about whether the rename
		// landed; the commit state is unknown and must never be classified
		// as not-committed.
		return fmt.Errorf("%w: generation %s: write: %v; read-back: %v",
			ErrCommitDurabilityUnknown, generationID, writeErr, readErr)
	}
	if current != generationID {
		// The old pointer is intact and authoritative; nothing committed.
		return writeErr
	}
	if syncErr := fsutil.SyncDir(paths.ProductDir()); syncErr == nil {
		return nil
	}
	return fmt.Errorf("%w: generation %s: %v", ErrCommitDurabilityUnknown, generationID, writeErr)
}

// Resolve reads CURRENT once and returns the bound generation paths.
// Mutating callers must hold the identity mutation lock across Resolve and
// every use of the result; never re-resolve mid-operation.
func Resolve(paths storepaths.Paths) (storepaths.GenPaths, error) {
	generationID, err := ReadCurrent(paths)
	if err != nil {
		return storepaths.GenPaths{}, err
	}
	return paths.GenerationPaths(generationID), nil
}

// ResolveActive resolves the identity's active namespaces: the generation
// named by CURRENT. All stores are generation-based; a missing or invalid
// CURRENT is an error (recovery), never a fallback.
func ResolveActive(paths storepaths.Paths) (storepaths.ActivePaths, error) {
	return Resolve(paths)
}

// IsGenerational reports whether the identity store exists as a
// generation-based store (all supported stores are). It distinguishes an
// uninitialized store from one whose CURRENT pointer is present, so callers
// can produce a friendly not-initialized error instead of a pointer error.
func IsGenerational(paths storepaths.Paths) (bool, error) {
	_, err := os.Lstat(paths.CurrentPointerPath())
	if err == nil {
		return true, nil
	}
	if !os.IsNotExist(err) {
		return false, err
	}
	return false, nil
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
