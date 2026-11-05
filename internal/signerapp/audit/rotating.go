// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
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
	// Leaves lists the stage's distinct transactions found in the retained
	// log, in first-seen order, with the leaf each signed with. Identical
	// retries do not append another entry.
	Leaves []RotatingLeaf
	// Reused reports that two distinct transactions of the same stage signed
	// with the same leaf. Entries the log has rotated past cannot be seen, so
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
// path+".1", then path), oldest first so later entries win. The collected
// history feeds both one-time leaf selection and release alerts. Entries
// the log rotated past are absent, and malformed lines are skipped; missing
// history can cause undetected leaf reuse after release memory is rebuilt.
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
	reader := bufio.NewReaderSize(f, 64*1024)
	for {
		line, tooLong, err := readAuditLine(reader, maxReleaseLine)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if tooLong {
			// No release entry is this long, so skipping the line loses
			// none; failing would lose the whole history at unlock.
			continue
		}
		var entry AuditEntry
		if err := json.Unmarshal(line, &entry); err != nil {
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
}

// maxReleaseLine bounds the audit lines the release reader parses; a
// ROTATING_RELEASE entry is a few hundred bytes.
const maxReleaseLine = 1 << 20

// readAuditLine returns the next line of r without its newline. A line
// longer than limit is read to its end and reported as too long, with no
// bytes. io.EOF is returned once no line is left.
func readAuditLine(r *bufio.Reader, limit int) ([]byte, bool, error) {
	var line []byte
	tooLong := false
	for {
		chunk, err := r.ReadSlice('\n')
		if !tooLong {
			if len(line)+len(chunk) > limit+1 {
				tooLong, line = true, nil
			} else {
				line = append(line, chunk...)
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil && (!errors.Is(err, io.EOF) || (len(line) == 0 && !tooLong)) {
			return nil, false, err
		}
		return bytes.TrimSuffix(line, []byte("\n")), tooLong, nil
	}
}
