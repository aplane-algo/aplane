// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"time"
)

// A rotation copies the releases of each account's newest stage into the file it
// is about to make .1, so the copies outlive the file it drops and the next
// rotation makes them again. A copy repeats a release already listed, so a batch
// cut short changes nothing a reader finds: outcomeCarried lists its leaf, and
// outcomeCarriedLatest, written last, also marks the account's newest release
// and makes the batch's order the account's.
const (
	outcomeCarried       = "carried"
	outcomeCarriedLatest = "carried_latest"
)

// carriedWhole is the most releases of one stage that are all carried. A stage
// has at most 64 leaves, so a stage with more has reused one, or has none to
// reuse (a stateless family, which writes them all on tree 0, index 0).
const carriedWhole = 64

// carried is the releases of r to copy: all of them, or past carriedWhole the
// first on each leaf and the first that reused a leaf, which keep every used
// leaf and whether one was reused. A transaction left out was signed on a used
// leaf: once the stage had none unused, that is its own pick (chooseLeaf), which
// its retry signs on again.
func (r RotatingRelease) carried() []RotatingLeaf {
	if len(r.Leaves) <= carriedWhole {
		return r.Leaves
	}
	var kept []RotatingLeaf
	used := make(map[[2]uint64]bool)
	reuseKept := false
	for _, l := range r.Leaves {
		if used[l.leaf()] {
			if reuseKept {
				continue
			}
			reuseKept = true
		}
		used[l.leaf()] = true
		kept = append(kept, l)
	}
	return kept
}

// newest is r's newest release.
func (r RotatingRelease) newest() RotatingLeaf {
	return RotatingLeaf{Tree: r.Tree, Index: r.Index, TxID: r.TxID, LastValid: r.LastValid}
}

// holds reports whether a file's own history has all of kept, its releases in
// r's order, and r's newest release as its newest. Once the files before it
// are dropped, the file is read first and its order becomes the account's.
func (h releaseHistory) holds(r RotatingRelease, kept []RotatingLeaf) bool {
	a := h[r.Account]
	if a == nil || a.r.Stage != r.Stage || a.r.newest() != r.newest() {
		return false
	}
	for _, l := range kept {
		if !a.listed[leafRelease{leaf: l.leaf(), txID: l.TxID}] {
			return false
		}
	}
	// Each release is listed once, so the file's are in r's order if they are
	// found in it one after another.
	next := 0
	for _, l := range r.Leaves {
		if next < len(a.r.Leaves) && a.r.Leaves[next] == l {
			next++
		}
	}
	return next == len(a.r.Leaves)
}

// carryReleases appends to the current file, in one write, the releases of each
// account's newest stage that it doesn't hold already. It then holds them all
// until the rotation opens a new file, since what is appended after them is in
// the history too, so a rotation that keeps failing reads the log once. A file
// that can't be read is left out and reported, and the rest is carried; for the
// current file that copies every account. Must be called with a.mu held, which
// every rotation takes, so no file moves while it reads.
func (a *AuditLogger) carryReleases() error {
	if a.file == nil || a.releasesCarried {
		return nil
	}
	all, current := make(releaseHistory), make(releaseHistory)
	var skipped error
	for _, name := range []string{a.path + ".2", a.path + ".1", a.path} {
		into := []releaseHistory{all}
		if name == a.path {
			into = append(into, current)
		}
		if err := readReleaseFile(name, into...); err != nil {
			skipped = errors.Join(skipped, fmt.Errorf("left out %s: %w", name, err))
		}
	}
	var lines []byte
	var err error
	for _, account := range slices.Sorted(maps.Keys(all)) {
		r := all[account].r
		kept := r.carried()
		if current.holds(r, kept) {
			continue
		}
		if lines, err = appendCarried(lines, r, kept); err != nil {
			return err
		}
	}
	if len(lines) > 0 {
		if err := a.writeLineLocked(lines); err != nil {
			return err
		}
	}
	a.releasesCarried = true
	return skipped
}

// readReleaseFile reads the releases in the file at name into each history. A
// file that does not exist holds none.
func readReleaseFile(name string, into ...releaseHistory) error {
	f, err := os.Open(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return readRotatingReleasesFrom(f, into...)
}

// appendCarried appends kept to lines as copies, the newest release last.
func appendCarried(lines []byte, r RotatingRelease, kept []RotatingLeaf) ([]byte, error) {
	if kept[len(kept)-1] == r.newest() {
		kept = kept[:len(kept)-1]
	}
	stage := r.Stage
	add := func(l RotatingLeaf, outcome string) error {
		data, err := json.Marshal(AuditEntry{
			Timestamp: time.Now().UTC(), Event: AuditRotatingRelease, Outcome: outcome,
			TxnAuth: r.Account, TxnSender: r.Account, TxID: l.TxID,
			RotatingStage: &stage, RotatingLastValid: l.LastValid, RotatingTree: l.Tree, RotatingIndex: l.Index,
		})
		lines = append(append(lines, data...), '\n')
		return err
	}
	for _, l := range kept {
		if err := add(l, outcomeCarried); err != nil {
			return nil, err
		}
	}
	if err := add(r.newest(), outcomeCarriedLatest); err != nil {
		return nil, err
	}
	return lines, nil
}
