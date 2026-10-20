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
	acc := make(map[string]*releaseAccumulator)
	for _, file := range []string{path + ".2", path + ".1", path} {
		if err := readRotatingReleasesFrom(file, acc); err != nil {
			return nil, err
		}
	}
	out := make(map[string]RotatingRelease, len(acc))
	for account, a := range acc {
		out[account] = a.r
	}
	return out, nil
}

// releaseAccumulator gathers one account's releases of its newest stage as
// the log is read: the release itself, the transactions already listed and
// the leaves already used, so each entry costs one map lookup and an
// amortized append rather than a scan and a copy of the history.
type releaseAccumulator struct {
	r     RotatingRelease
	txids map[string]bool
	used  map[[2]uint64]bool
}

func (a *releaseAccumulator) add(leaf RotatingLeaf) {
	a.r.TxID, a.r.LastValid, a.r.Tree, a.r.Index = leaf.TxID, leaf.LastValid, leaf.Tree, leaf.Index
	if a.txids[leaf.TxID] {
		// A retry of one transaction is one release.
		return
	}
	a.txids[leaf.TxID] = true
	k := [2]uint64{leaf.Tree, uint64(leaf.Index)}
	if a.used[k] {
		a.r.Reused = true
	}
	a.used[k] = true
	a.r.Leaves = append(a.r.Leaves, leaf)
}

func readRotatingReleasesFrom(file string, acc map[string]*releaseAccumulator) error {
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
		a, ok := acc[entry.TxnAuth]
		if !ok || a.r.Stage != *entry.RotatingStage {
			// A new stage starts a fresh list; reuse is per stage.
			a = &releaseAccumulator{
				r:     RotatingRelease{Account: entry.TxnAuth, Stage: *entry.RotatingStage},
				txids: make(map[string]bool),
				used:  make(map[[2]uint64]bool),
			}
			acc[entry.TxnAuth] = a
		}
		a.add(leaf)
	}
	return scanner.Err()
}
