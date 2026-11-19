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
// path+".1", then path), oldest first so later entries win, except that an
// entry from an earlier stage never replaces a later stage's. The collected
// history feeds both one-time leaf selection and release alerts. Entries
// the log rotated past are absent, and malformed lines are skipped; missing
// history can cause undetected leaf reuse after release memory is rebuilt.
//
// It is for a log no AuditLogger is writing: a rotation between two of its
// opens would hide a whole file. The signer reads its own log with
// AuditLogger.ReadRotatingReleases.
func ReadRotatingReleases(path string) (map[string]RotatingRelease, error) {
	files, err := openReleaseLogs(path)
	if err != nil {
		return nil, err
	}
	return readReleaseLogs(files)
}

// ReadRotatingReleases reads the release history of the log this logger
// writes, as the package function does. It opens the current file and both
// rotated files under the logger's mutex, which every rotation holds, so a
// rotation cannot move a file between two opens and hide it: the three are
// the log at one instant. The reads run after the mutex is released, so
// audit writes are not held up; they read the open files, which a later
// rotation's renames do not change, and see what was appended until then.
func (a *AuditLogger) ReadRotatingReleases() (map[string]RotatingRelease, error) {
	a.mu.Lock()
	files, err := openReleaseLogs(a.path)
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return readReleaseLogs(files)
}

// afterReleaseLogOpen, when a test sets it, runs before each attempt to open
// a further file once openReleaseLogs holds at least one open.
var afterReleaseLogOpen func()

// openReleaseLogs opens the audit log at path and its rotated predecessors,
// oldest first. A file that does not exist is left out.
func openReleaseLogs(path string) ([]*os.File, error) {
	var files []*os.File
	for _, name := range []string{path + ".2", path + ".1", path} {
		if afterReleaseLogOpen != nil && len(files) > 0 {
			afterReleaseLogOpen()
		}
		f, err := os.Open(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			for _, open := range files {
				_ = open.Close()
			}
			return nil, err
		}
		files = append(files, f)
	}
	return files, nil
}

// readReleaseLogs reads files in order into the per-account history and
// closes them.
func readReleaseLogs(files []*os.File) (map[string]RotatingRelease, error) {
	defer func() {
		for _, f := range files {
			_ = f.Close()
		}
	}()
	acc := make(map[string]*releaseAccumulator)
	for _, f := range files {
		if err := readRotatingReleasesFrom(f, acc); err != nil {
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

func readRotatingReleasesFrom(f io.Reader, acc map[string]*releaseAccumulator) error {
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
		if ok && *entry.RotatingStage < a.r.Stage {
			// An account only moves forward, so a release from an earlier
			// stage than one already read was signed on a chain read that
			// was behind. The later stage may still be live: its list stays.
			continue
		}
		if !ok || a.r.Stage != *entry.RotatingStage {
			// A later stage starts a fresh list; reuse is per stage.
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
