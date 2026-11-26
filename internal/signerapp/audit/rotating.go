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
	// Leaves lists the stage's releases found in the retained log, oldest
	// first, each pair of leaf and transaction once. A rotation's copies keep
	// that order (see releaseAccumulator.add). An identical
	// retry (the same transaction on the same leaf) does not append another
	// entry. The same transaction on another leaf, which a retry signs once
	// the history was lost, does: that leaf is spent too.
	Leaves []RotatingLeaf
	// Reused reports that two distinct transactions of the same stage signed
	// with the same leaf. One transaction on two leaves is not reuse: neither
	// leaf signed a second message. Entries the log lost (see carryReleases)
	// cannot be seen, so false means none was seen, not none was made.
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
// from the log this logger writes and its rotated predecessors (.2, then .1,
// then the current file), oldest first so later entries win, except that an
// entry from an earlier stage never replaces a later stage's. The collected
// history feeds both one-time leaf selection and release alerts. A rotation
// carries each account's newest stage forward (carryReleases), so earlier
// stages' entries are the ones it drops. Malformed lines are skipped; missing
// history can cause undetected leaf reuse after release memory is rebuilt.
//
// It opens the current file and both rotated files under the logger's mutex,
// which every rotation holds, so a rotation cannot move a file between two
// opens and hide it: the three are the log at one instant. The reads run after
// the mutex is released, so audit writes are not held up; they read the open
// files, which a later rotation's renames do not change, and see what was
// appended until then.
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
	acc := make(releaseHistory)
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

// releaseHistory is each account's newest stage, as read so far.
type releaseHistory map[string]*releaseAccumulator

// releaseAccumulator gathers one account's releases of its newest stage as
// the log is read: the release itself, the releases already listed and the
// leaves already used, so each entry costs one map lookup and an amortized
// append rather than a scan and a copy of the history.
type releaseAccumulator struct {
	r      RotatingRelease
	listed map[leafRelease]bool
	used   map[[2]uint64]bool
	// batch is the copies read since the account's last release that was not
	// one: a rotation's batch, until its outcomeCarriedLatest.
	batch []RotatingLeaf
}

// leafRelease is one release as the reader dedupes it: the leaf (tree and
// index) and the transaction it signed.
type leafRelease struct {
	leaf [2]uint64
	txID string
}

// add lists leaf. It is the newest release read, unless it is a copy that a
// rotation made: of those only the one marked so is, or the first when nothing
// else was read. A copy that was cut short by a crash, a full disk or a reader
// that came partway then only repeats what is listed.
func (a *releaseAccumulator) add(leaf RotatingLeaf, outcome string) {
	if outcome != outcomeCarried || len(a.r.Leaves) == 0 {
		a.r.TxID, a.r.LastValid, a.r.Tree, a.r.Index = leaf.TxID, leaf.LastValid, leaf.Tree, leaf.Index
	}
	switch outcome {
	case outcomeCarried:
		a.batch = append(a.batch, leaf)
		a.list(leaf)
	case outcomeCarriedLatest:
		a.list(leaf)
		a.orderBy(append(a.batch, leaf))
		a.batch = nil
	default:
		a.batch = nil
		a.list(leaf)
	}
}

// orderBy puts the releases of a complete batch first, in its order, and the
// rest after them as they were. A file holding live releases ahead of its
// batch is read before the files the batch copied, so without this the order
// would change at each rotation, and with it which release carried keeps as
// the first on a leaf.
func (a *releaseAccumulator) orderBy(batch []RotatingLeaf) {
	placed := make(map[leafRelease]bool, len(a.r.Leaves))
	ordered := make([]RotatingLeaf, 0, len(a.r.Leaves))
	for _, list := range [][]RotatingLeaf{batch, a.r.Leaves} {
		for _, l := range list {
			if rel := (leafRelease{leaf: l.leaf(), txID: l.TxID}); !placed[rel] {
				placed[rel] = true
				ordered = append(ordered, l)
			}
		}
	}
	a.r.Leaves = ordered
}

// list adds leaf to the stage's releases unless it is listed already.
func (a *releaseAccumulator) list(leaf RotatingLeaf) {
	k := leaf.leaf()
	rel := leafRelease{leaf: k, txID: leaf.TxID}
	if a.listed[rel] {
		// A retry of one transaction on its leaf is one release.
		return
	}
	a.listed[rel] = true
	// The pair is new, so a leaf already used was used by another
	// transaction. The same transaction on a new leaf is listed and marks
	// that leaf used without being reuse.
	if a.used[k] {
		a.r.Reused = true
	}
	a.used[k] = true
	a.r.Leaves = append(a.r.Leaves, leaf)
}

// leaf is l's tree and index, without its transaction.
func (l RotatingLeaf) leaf() [2]uint64 {
	return [2]uint64{l.Tree, uint64(l.Index)}
}

func readRotatingReleasesFrom(f io.Reader, into ...releaseHistory) error {
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
		// Parsing every line would dominate the read: almost none is a release.
		if !bytes.Contains(line, []byte(AuditRotatingRelease)) {
			continue
		}
		var entry AuditEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		if entry.Event != AuditRotatingRelease || entry.TxnAuth == "" || entry.RotatingStage == nil {
			continue
		}
		for _, history := range into {
			history.add(entry)
		}
	}
}

// add adds a ROTATING_RELEASE entry to its account's history.
func (h releaseHistory) add(entry AuditEntry) {
	a, ok := h[entry.TxnAuth]
	if ok && *entry.RotatingStage < a.r.Stage {
		// An account only moves forward, so a release from an earlier
		// stage than one already read was signed on a chain read that
		// was behind. The later stage may still be live: its list stays.
		return
	}
	if !ok || a.r.Stage != *entry.RotatingStage {
		// A later stage starts a fresh list; reuse is per stage.
		a = &releaseAccumulator{
			r:      RotatingRelease{Account: entry.TxnAuth, Stage: *entry.RotatingStage},
			listed: make(map[leafRelease]bool),
			used:   make(map[[2]uint64]bool),
		}
		h[entry.TxnAuth] = a
	}
	a.add(RotatingLeaf{Tree: entry.RotatingTree, Index: entry.RotatingIndex, TxID: entry.TxID, LastValid: entry.RotatingLastValid}, entry.Outcome)
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
