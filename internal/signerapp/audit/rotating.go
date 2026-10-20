// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
)

// RotatingRelease is the newest ROTATING_RELEASE entry of an account read
// back from the audit log, with every leaf the same stage released.
type RotatingRelease struct {
	Account   string
	Stage     uint64
	TxID      string
	LastValid uint64
	Tree      uint64
	Index     uint32
	// Leaves lists every distinct transaction the stage released, oldest
	// first, with the leaf each signed with; the last is this entry.
	Leaves []RotatingLeaf
	// Reused reports that two entries of the same stage signed with the
	// same leaf: for a family with one key per stage, any two distinct
	// transactions. Entries the log has rotated past cannot be seen, so
	// false means none was seen, not none was made.
	Reused bool
}

// RotatingLeaf is one release of a stage: the leaf and the transaction.
type RotatingLeaf struct {
	Tree      uint64
	Index     uint32
	TxID      string
	LastValid uint64
}

// ReadRotatingReleases returns the newest ROTATING_RELEASE entry per account
// from the audit log at path and its rotated predecessors (path+".2", then
// path+".1", then path), oldest first so later entries win. Entries that no
// longer exist because the log rotated past them are simply absent: the
// release memory this feeds is observational and degrades to silence, never
// to a wrong signature. Malformed lines are skipped.
func ReadRotatingReleases(path string) (map[string]RotatingRelease, error) {
	out := make(map[string]RotatingRelease)
	for _, file := range []string{path + ".2", path + ".1", path} {
		if err := readRotatingReleasesFrom(file, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func readRotatingReleasesFrom(file string, out map[string]RotatingRelease) error {
	f, err := os.Open(file)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		var entry AuditEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		if entry.Event != AuditRotatingRelease || entry.TxnAuth == "" || entry.RotatingStage == nil {
			continue
		}
		leaf := RotatingLeaf{Tree: entry.RotatingTree, Index: entry.RotatingIndex, TxID: entry.TxID, LastValid: entry.RotatingLastValid}
		r := RotatingRelease{
			Account:   entry.TxnAuth,
			Stage:     *entry.RotatingStage,
			TxID:      entry.TxID,
			LastValid: entry.RotatingLastValid,
			Tree:      leaf.Tree,
			Index:     leaf.Index,
			Leaves:    []RotatingLeaf{leaf},
		}
		if prev, ok := out[r.Account]; ok && prev.Stage == r.Stage {
			r.Leaves = appendLeaf(prev.Leaves, leaf)
			r.Reused = prev.Reused || leavesReused(r.Leaves)
		}
		out[r.Account] = r
	}
	return scanner.Err()
}

// appendLeaf adds leaf to leaves unless the same transaction is already
// listed: a retry of one transaction is one release.
func appendLeaf(leaves []RotatingLeaf, leaf RotatingLeaf) []RotatingLeaf {
	for _, l := range leaves {
		if l.TxID == leaf.TxID {
			return leaves
		}
	}
	return append(append([]RotatingLeaf(nil), leaves...), leaf)
}

// leavesReused reports whether two listed releases share a leaf.
func leavesReused(leaves []RotatingLeaf) bool {
	seen := make(map[[2]uint64]bool, len(leaves))
	for _, l := range leaves {
		k := [2]uint64{l.Tree, uint64(l.Index)}
		if seen[k] {
			return true
		}
		seen[k] = true
	}
	return false
}
