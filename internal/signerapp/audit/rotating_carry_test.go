// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// carryLogger is an audit log with a directory of its own.
func carryLogger(t *testing.T) (*AuditLogger, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logger.Close() })
	return logger, path
}

func release(t *testing.T, logger *AuditLogger, account, txid string, stage, tree uint64, index uint32) {
	t.Helper()
	if err := logger.LogRotatingReleaseAttributed(Attribution{}, account, txid, stage, 9000+stage, tree, index); err != nil {
		t.Fatal(err)
	}
}

// rotateOnce makes the next entry rotate the log, and writes one.
func rotateOnce(logger *AuditLogger) {
	logger.mu.Lock()
	logger.written = maxAuditLogSize
	logger.mu.Unlock()
	logger.Log(AuditEntry{Event: AuditSignRequest, Reason: "filler"})
}

func history(t *testing.T, path string) map[string]RotatingRelease {
	t.Helper()
	got, err := readReleasesAt(path)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// Every account's newest stage reads back the same however often the log
// rotates: its leaves, whether one was reused, and its newest release, which a
// retry of an older leaf can be.
func TestReleasesSurviveEveryRotation(t *testing.T) {
	logger, path := carryLogger(t)
	for i := range 3 {
		release(t, logger, "PLAIN", fmt.Sprintf("P%d", i), 7, 2, uint32(10+i))
	}
	release(t, logger, "RETRIED", "R0", 4, 0, 5)
	release(t, logger, "RETRIED", "R1", 4, 0, 6)
	release(t, logger, "RETRIED", "R0", 4, 0, 5)
	release(t, logger, "RESIGNED", "S0", 4, 0, 5)
	release(t, logger, "RESIGNED", "S0", 4, 0, 6) // one transaction on two leaves
	release(t, logger, "RESIGNED", "S0", 4, 0, 5) // and again on the first
	release(t, logger, "REUSED", "U0", 1, 0, 5)
	release(t, logger, "REUSED", "U1", 1, 0, 5)
	release(t, logger, "REUSED", "U2", 1, 0, 8)
	release(t, logger, "MOVED", "M0", 1, 0, 5)
	release(t, logger, "MOVED", "M1", 2, 0, 5)
	want := history(t, path)
	if !want["REUSED"].Reused || want["RETRIED"].TxID != "R0" || want["MOVED"].Stage != 2 {
		t.Fatalf("the history before any rotation = %+v", want)
	}
	for n := range 10 {
		rotateOnce(logger)
		if got := history(t, path); !reflect.DeepEqual(got, want) {
			t.Fatalf("after %d rotations:\n got %+v\nwant %+v", n+1, got, want)
		}
	}
	// What an account signs after that is its newest release.
	release(t, logger, "PLAIN", "P3", 7, 2, 13)
	rotateOnce(logger)
	if got := history(t, path)["PLAIN"]; got.TxID != "P3" || got.Index != 13 || len(got.Leaves) != 4 {
		t.Fatalf("a release after the rotations reads back as %+v", got)
	}
	// A later stage replaces the one the log carried.
	release(t, logger, "PLAIN", "P4", 8, 2, 64)
	for range 4 {
		rotateOnce(logger)
	}
	if got := history(t, path)["PLAIN"]; got.Stage != 8 || len(got.Leaves) != 1 {
		t.Fatalf("after a later stage = %+v", got)
	}
	for _, name := range []string{path, path + ".1", path + ".2"} {
		if data, err := os.ReadFile(name); err != nil || bytes.Contains(data, []byte(`"txid":"P0"`)) {
			t.Errorf("%s still carries the earlier stage, %v", name, err)
		}
	}
}

// carriedLines is the copies in the file at path, by account.
func carriedLines(t *testing.T, path string) map[string]int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int{}
	for _, line := range bytes.Split(data, []byte("\n")) {
		var e AuditEntry
		if json.Unmarshal(line, &e) == nil && (e.Outcome == outcomeCarried || e.Outcome == outcomeCarriedLatest) {
			out[e.TxnAuth]++
		}
	}
	return out
}

// txids is r's releases' transactions, in r's order.
func txids(r RotatingRelease) []string {
	var out []string
	for _, l := range r.Leaves {
		out = append(out, l.TxID)
	}
	return out
}

// Past 64 releases of a stage the copies are bounded, whether its leaves are
// used up or it has none, and no used leaf, no reuse and no newest release is
// forgotten.
func TestCarriedReleasesAreBounded(t *testing.T) {
	logger, path := carryLogger(t)
	for i := range 64 {
		release(t, logger, "EXACT", fmt.Sprintf("E%d", i), 3, 0, uint32(i))
		release(t, logger, "EXHAUSTED", fmt.Sprintf("X%d", i), 3, 0, uint32(i))
	}
	for i := range 200 {
		release(t, logger, "EXHAUSTED", fmt.Sprintf("Y%d", i), 3, 0, uint32(i%64))
		release(t, logger, "STATELESS", fmt.Sprintf("Z%d", i), 3, 0, 0)
	}
	for i := range 65 {
		if i < 64 {
			release(t, logger, "STATELESS64", fmt.Sprintf("S%d", i), 3, 0, 0)
		}
		release(t, logger, "STATELESS65", fmt.Sprintf("T%d", i), 3, 0, 0)
	}
	for i := range 5 { // several on one leaf, as after lost histories
		release(t, logger, "LOSSY", fmt.Sprintf("L%d", i), 3, 0, 7)
	}
	before := history(t, path)
	for range 5 {
		rotateOnce(logger)
	}
	want := map[string]int{"EXACT": 64, "EXHAUSTED": 66, "STATELESS": 3, "STATELESS64": 64, "STATELESS65": 3, "LOSSY": 5}
	if got := carriedLines(t, path+".1"); !reflect.DeepEqual(got, want) {
		t.Fatalf("copies = %v, want %v", got, want)
	}
	after := history(t, path)
	for _, account := range []string{"EXACT", "STATELESS64", "LOSSY"} {
		if !reflect.DeepEqual(after[account], before[account]) {
			t.Errorf("%s, with no more than 64 releases, changed: %+v", account, after[account])
		}
	}
	for _, account := range []string{"EXHAUSTED", "STATELESS", "STATELESS65"} {
		b, a := before[account], after[account]
		if a.newest() != b.newest() || a.Reused != b.Reused || a.Stage != b.Stage {
			t.Errorf("%s = newest %+v reused %t, want %+v %t", account, a.newest(), a.Reused, b.newest(), b.Reused)
		}
		leaves := func(r RotatingRelease) map[[2]uint64]bool {
			out := map[[2]uint64]bool{}
			for _, l := range r.Leaves {
				out[l.leaf()] = true
			}
			return out
		}
		if !reflect.DeepEqual(leaves(a), leaves(b)) {
			t.Errorf("%s forgot a used leaf: %d of %d", account, len(leaves(a)), len(leaves(b)))
		}
	}
}

// A batch of copies cut short anywhere, by a crash, a full disk or a reader that
// came partway, changes nothing, whether the log still holds the originals or
// only an earlier batch.
func TestACutShortCarryChangesNothing(t *testing.T) {
	logger, path := carryLogger(t)
	for i := range 3 {
		release(t, logger, "A", fmt.Sprintf("A%d", i), 7, 2, uint32(10+i))
	}
	release(t, logger, "A", "A0", 7, 2, 10) // the newest is a retry
	release(t, logger, "B", "B0", 2, 0, 1)
	release(t, logger, "B", "B1", 2, 0, 1) // reused
	want := history(t, path)
	originals, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var batch []byte
	for _, account := range []string{"A", "B"} {
		if batch, err = appendCarried(batch, want[account], want[account].carried()); err != nil {
			t.Fatal(err)
		}
	}
	for name, start := range map[string][]byte{"originals": originals, "an earlier batch": batch} {
		for cut := range len(batch) + 1 {
			file := filepath.Join(t.TempDir(), "audit.log")
			if err := os.WriteFile(file, append(bytes.Clone(start), batch[:cut]...), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := history(t, file); !reflect.DeepEqual(got, want) {
				t.Fatalf("after %s and a batch cut at byte %d of %d:\n got %+v\nwant %+v", name, cut, len(batch), got, want)
			}
		}
	}
}

// A rotation that keeps failing copies once, not on every entry.
func TestAFailingRotationCarriesOnce(t *testing.T) {
	logger, path := carryLogger(t)
	release(t, logger, "A", "A0", 7, 0, 10)
	rotateOnce(logger) // the originals are now in .1
	original := renameAuditFile
	renameAuditFile = func(string, string) error { return errors.New("simulated rename failure") }
	t.Cleanup(func() { renameAuditFile = original })
	for range 5 {
		rotateOnce(logger)
	}
	if got := carriedLines(t, path)["A"]; got != 1 {
		t.Fatalf("5 failed rotations wrote %d copies, want 1", got)
	}
	renameAuditFile = original
	rotateOnce(logger)
	if got := carriedLines(t, path+".1")["A"]; got != 1 {
		t.Fatalf("the rotation that followed wrote copies again: %d", got)
	}
}

// A carry that fails warns, and the rotation goes on; the copies of the rotation
// before are still there for the next one.
func TestAFailedCarryWarnsAndRotates(t *testing.T) {
	t.Run("a write cut short", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.log")
		var cut *faultyFile
		useFaultyFiles(t, func(f *faultyFile) { cut = f })
		logger, err := NewAuditLogger(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = logger.Close() })
		for i := range 3 {
			release(t, logger, "A", fmt.Sprintf("A%d", i), 7, 0, uint32(10+i))
		}
		rotateOnce(logger)
		want := history(t, path)
		cut.shortWrites = 1 // the next carry's
		warned := captureStderr(t, func() { rotateOnce(logger) })
		if !strings.Contains(warned, "release history was not carried") {
			t.Fatalf("stderr = %q, want a warning", warned)
		}
		for range 5 {
			if got := history(t, path); !reflect.DeepEqual(got, want) {
				t.Fatalf("got %+v\nwant %+v", got, want)
			}
			rotateOnce(logger)
		}
	})
	t.Run("an unreadable file", func(t *testing.T) {
		logger, path := carryLogger(t)
		if err := os.Mkdir(path+".2", 0o700); err != nil {
			t.Fatal(err)
		}
		release(t, logger, "A", "A0", 7, 0, 10)
		warned := captureStderr(t, func() { rotateOnce(logger) })
		if !strings.Contains(warned, "release history was not carried") {
			t.Fatalf("stderr = %q, want a warning", warned)
		}
		if data, err := os.ReadFile(path + ".1"); err != nil || !bytes.Contains(data, []byte(`"txid":"A0"`)) {
			t.Fatalf("the log did not rotate: %v", err)
		}
	})
}

// A restore that reads while the log rotates finds the same history.
func TestAReadDuringRotationsFindsTheSameHistory(t *testing.T) {
	logger, path := carryLogger(t)
	for i := range 3 {
		release(t, logger, "A", fmt.Sprintf("A%d", i), 7, 0, uint32(10+i))
	}
	release(t, logger, "A", "A1", 7, 0, 11)
	want := history(t, path)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 60 {
			rotateOnce(logger)
		}
	}()
	for reading := true; reading; {
		select {
		case <-done:
			reading = false
		default:
		}
		got, err := logger.ReadRotatingReleases()
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("read %+v, %v during rotations\nwant %+v", got, err, want)
		}
	}
}

// An account that signs a little between rotations, so that the current file
// always has some of its releases, keeps all of them.
func TestAnAccountThatKeepsSigningLosesNothing(t *testing.T) {
	logger, path := carryLogger(t)
	for i := range 12 {
		release(t, logger, "A", fmt.Sprintf("A%d", i), 7, 0, uint32(i))
		rotateOnce(logger)
		got := history(t, path)["A"]
		var want []string
		for j := range i + 1 {
			want = append(want, fmt.Sprintf("A%d", j))
		}
		if !slices.Equal(txids(got), want) || got.TxID != want[i] {
			t.Fatalf("after %d releases and rotations: %+v", i+1, got)
		}
	}
}

// Releases keep the order they were signed in, though a file read first can
// hold a live release ahead of the copies of earlier ones.
func TestReleasesKeepTheirOrder(t *testing.T) {
	logger, path := carryLogger(t)
	release(t, logger, "A", "OLD", 7, 0, 1)
	rotateOnce(logger)
	rotateOnce(logger)
	release(t, logger, "A", "NEW", 7, 0, 2)
	for n := range 6 {
		rotateOnce(logger)
		if got := txids(history(t, path)["A"]); !slices.Equal(got, []string{"OLD", "NEW"}) {
			t.Fatalf("after %d rotations the releases read %v", n+1, got)
		}
	}
}

// A rotation copies nothing of an account the file it rotates out holds whole,
// so the first rotation after its releases copies nothing.
func TestARotationCopiesNothingTheFileHolds(t *testing.T) {
	logger, path := carryLogger(t)
	release(t, logger, "A", "A0", 7, 0, 10)
	release(t, logger, "B", "B0", 7, 0, 10)
	rotateOnce(logger)
	if got := carriedLines(t, path+".1"); len(got) != 0 {
		t.Fatalf("copies of releases the file held: %v", got)
	}
	release(t, logger, "A", "A1", 7, 0, 11)
	rotateOnce(logger)
	if got := carriedLines(t, path+".1"); !reflect.DeepEqual(got, map[string]int{"A": 2, "B": 1}) {
		t.Fatalf("copies = %v, want A's two and B's one", got)
	}
}

// A batch of copies starts after the account's last release that was not one:
// copies an earlier batch left cut short don't order the next.
func TestABatchStartsAfterTheLastRelease(t *testing.T) {
	stage := uint64(7)
	line := func(txid string, index uint32, outcome string) string {
		data, err := json.Marshal(AuditEntry{Event: AuditRotatingRelease, TxnAuth: "A", TxID: txid, RotatingStage: &stage, RotatingIndex: index, Outcome: outcome})
		if err != nil {
			t.Fatal(err)
		}
		return string(data) + "\n"
	}
	log := line("K1", 1, "released") + line("K2", 2, "released") + line("X", 1, "released") +
		line("X", 1, outcomeCarried) + // a batch cut short
		line("L", 3, "released") +
		line("K1", 1, outcomeCarried) + line("K2", 2, outcomeCarried) + line("L", 3, outcomeCarriedLatest)
	h := make(releaseHistory)
	if err := readRotatingReleasesFrom(strings.NewReader(log), h); err != nil {
		t.Fatal(err)
	}
	if got := txids(h["A"].r); !slices.Equal(got, []string{"K1", "K2", "L", "X"}) {
		t.Fatalf("releases read %v", got)
	}
}

// A file that holds every release, but with an older one retried after a newer
// one, gets copies too: they set its order, which a cut carry in the next file
// would otherwise leave as the account's.
func TestARetryAfterANewerReleaseKeepsTheOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	var current *faultyFile
	useFaultyFiles(t, func(f *faultyFile) { current = f })
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logger.Close() })
	release(t, logger, "A", "OLD", 7, 0, 1)
	rotateOnce(logger)
	rotateOnce(logger)
	release(t, logger, "A", "NEW", 7, 0, 2)
	release(t, logger, "A", "OLD", 7, 0, 1)
	rotateOnce(logger)
	current.shortWrites = 1 // the next file's carry
	_ = captureStderr(t, func() { rotateOnce(logger) })
	for n := range 4 {
		if got := history(t, path)["A"]; !slices.Equal(txids(got), []string{"OLD", "NEW"}) || got.TxID != "OLD" {
			t.Fatalf("%d rotations after the cut: %v, newest %s", n, txids(got), got.TxID)
		}
		rotateOnce(logger)
	}
}

// Past 64 releases the copies keep the first release on each leaf, so a
// transaction signed before the stage ran out of leaves stays listed on the
// leaf it took, which its retry signs on, however often the log rotates.
func TestTheCapKeepsTheReleasesBeforeTheStageRanOut(t *testing.T) {
	logger, path := carryLogger(t)
	for i := range 63 {
		release(t, logger, "A", fmt.Sprintf("T%02d", i), 3, 0, uint32(i))
	}
	release(t, logger, "A", "TA", 3, 0, 63) // its pick, leaf 0, was taken
	release(t, logger, "A", "TC", 3, 0, 5)  // the stage is out of leaves
	release(t, logger, "A", "TB", 3, 0, 63)
	want := history(t, path)["A"]
	for n := range 8 {
		rotateOnce(logger)
		// Both are still in flight and retried in every file.
		release(t, logger, "A", "TC", 3, 0, 5)
		release(t, logger, "A", "TB", 3, 0, 63)
		if got := history(t, path)["A"]; !reflect.DeepEqual(got, want) {
			t.Fatalf("after %d rotations:\n got %v\nwant %v", n+1, txids(got), txids(want))
		}
	}
}

// A release of an earlier stage, signed on a chain read that was behind, with
// a later stage's leaf and transaction, hides no later stage from the copies.
func TestALaggingReleaseHidesNoLaterStage(t *testing.T) {
	logger, path := carryLogger(t)
	release(t, logger, "W", "T", 5, 0, 9)
	rotateOnce(logger)
	rotateOnce(logger) // stage 5 is only in the rotated files now
	for range 3 {
		if err := logger.LogRotatingReleaseAttributed(Attribution{}, "W", "T", 4, 9005, 0, 9); err != nil {
			t.Fatal(err)
		}
		rotateOnce(logger)
		if got := history(t, path)["W"]; got.Stage != 5 {
			t.Fatalf("the log reads back stage %d: %+v", got.Stage, got)
		}
	}
}

// A rotated file that can't be read is left out of the copies and reported,
// and the rest is carried.
func TestAnUnreadableRotatedFileIsLeftOut(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any file")
	}
	logger, path := carryLogger(t)
	release(t, logger, "A", "A0", 7, 0, 10)
	for range 3 {
		rotateOnce(logger) // until both rotated files hold A0
	}
	if err := os.Chmod(path+".1", 0); err != nil {
		t.Fatal(err)
	}
	for n := range 2 {
		warned := captureStderr(t, func() { rotateOnce(logger) })
		if !strings.Contains(warned, "left out "+path+".") {
			t.Fatalf("rotation %d warned %q", n+1, warned)
		}
	}
	if got := history(t, path)["A"]; got.TxID != "A0" {
		t.Fatalf("A's release, readable in .2, was not carried: %+v", got)
	}
}

// A rotation that keeps failing reads the log for its copies once.
func TestAStuckRotationReadsTheLogOnce(t *testing.T) {
	logger, path := carryLogger(t)
	release(t, logger, "A", "A0", 7, 0, 10)
	rotateOnce(logger)
	original := renameAuditFile
	renameAuditFile = func(string, string) error { return errors.New("simulated rename failure") }
	t.Cleanup(func() { renameAuditFile = original })
	rotateOnce(logger)
	// A release that only a second read would find.
	stage := uint64(7)
	line, err := json.Marshal(AuditEntry{Event: AuditRotatingRelease, Outcome: "released", TxnAuth: "B", TxID: "B0", RotatingStage: &stage})
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path+".1", os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write(append(line, '\n'))
	if err := errors.Join(err, f.Close()); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		rotateOnce(logger)
	}
	if got := carriedLines(t, path); !reflect.DeepEqual(got, map[string]int{"A": 1}) {
		t.Fatalf("copies = %v, want A's alone", got)
	}
	// Once the rotation goes through, the next carries B's release with the rest.
	renameAuditFile = original
	for n := range 4 {
		rotateOnce(logger)
		if got := history(t, path); got["A"].TxID != "A0" || got["B"].TxID != "B0" {
			t.Fatalf("after %d rotations: %+v", n+1, got)
		}
	}
}

// A crash before or between the rotation's renames loses nothing: the copies
// are written before either.
func TestACrashDuringARotationLosesNothing(t *testing.T) {
	for crashAt := 1; crashAt <= 2; crashAt++ {
		path := filepath.Join(t.TempDir(), "audit.log")
		logger, err := NewAuditLogger(path)
		if err != nil {
			t.Fatal(err)
		}
		for i := range 3 {
			release(t, logger, "A", fmt.Sprintf("A%d", i), 7, 0, uint32(10+i))
			rotateOnce(logger)
		}
		want := history(t, path)
		original, renames := renameAuditFile, 0
		renameAuditFile = func(from, to string) error {
			if renames++; renames == crashAt {
				return errors.New("simulated crash")
			}
			return original(from, to)
		}
		rotateOnce(logger)
		renameAuditFile = original
		_ = logger.Close()
		if got := history(t, path); !reflect.DeepEqual(got, want) {
			t.Fatalf("crash at rename %d:\n got %+v\nwant %+v", crashAt, got, want)
		}
		if logger, err = NewAuditLogger(path); err != nil {
			t.Fatal(err)
		}
		for n := range 4 {
			rotateOnce(logger)
			if got := history(t, path); !reflect.DeepEqual(got, want) {
				t.Fatalf("crash at rename %d, %d rotations after:\n got %+v\nwant %+v", crashAt, n+1, got, want)
			}
		}
		_ = logger.Close()
	}
}

// A file holds an account's history only when it has every release to copy and
// the newest one as its newest.
func TestAFileHoldsAnAccountOnlyWhole(t *testing.T) {
	entryAt := func(stage uint64, txid string, index uint32, outcome string) AuditEntry {
		return AuditEntry{Event: AuditRotatingRelease, TxnAuth: "A", TxID: txid, RotatingStage: &stage, RotatingIndex: index, Outcome: outcome}
	}
	entry := func(txid string, index uint32, outcome string) AuditEntry {
		return entryAt(7, txid, index, outcome)
	}
	all := make(releaseHistory)
	for _, e := range []AuditEntry{entry("A0", 1, "released"), entry("A1", 2, "released"), entry("A0", 1, "released")} {
		all.add(e)
	}
	r := all["A"].r
	for name, tc := range map[string]struct {
		entries []AuditEntry
		want    bool
	}{
		"nothing":                 {nil, false},
		"the originals":           {[]AuditEntry{entry("A0", 1, "released"), entry("A1", 2, "released"), entry("A0", 1, "released")}, true},
		"a whole batch":           {[]AuditEntry{entry("A0", 1, outcomeCarried), entry("A1", 2, outcomeCarried), entry("A0", 1, outcomeCarriedLatest)}, true},
		"a batch missing a leaf":  {[]AuditEntry{entry("A0", 1, outcomeCarriedLatest)}, false},
		"another newest":          {[]AuditEntry{entry("A0", 1, "released"), entry("A1", 2, "released")}, false},
		"a leaf of another spend": {[]AuditEntry{entry("B1", 2, outcomeCarried), entry("A0", 1, outcomeCarriedLatest)}, false},
		"an earlier stage":        {[]AuditEntry{entryAt(6, "A0", 1, "released"), entryAt(6, "A1", 2, "released"), entryAt(6, "A0", 1, "released")}, false},
	} {
		current := make(releaseHistory)
		for _, e := range tc.entries {
			current.add(e)
		}
		if got := current.holds(r, r.carried()); got != tc.want {
			t.Errorf("%s: holds = %t, want %t", name, got, tc.want)
		}
	}
}

// A copy is an account's newest release only where nothing else says which is.
func TestACopyIsTheNewestOnlyAlone(t *testing.T) {
	stage := uint64(7)
	h := make(releaseHistory)
	for _, txid := range []string{"A0", "A1"} {
		h.add(AuditEntry{Event: AuditRotatingRelease, TxnAuth: "A", TxID: txid, RotatingStage: &stage, RotatingIndex: 1, RotatingLastValid: 9, Outcome: outcomeCarried})
	}
	if got := h["A"].r; got.TxID != "A0" || got.LastValid != 9 {
		t.Fatalf("copies alone read back %+v, want the first as the newest", got)
	}
}
