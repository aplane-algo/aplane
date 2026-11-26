// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package audit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// faultyFile is an audit file that can stop a write partway or fail to
// close.
type faultyFile struct {
	*os.File
	shortWrites int  // writes to cut in half and fail
	failClose   bool // Close reports an error after closing
}

func (f *faultyFile) Write(b []byte) (int, error) {
	if f.shortWrites > 0 {
		f.shortWrites--
		n, _ := f.File.Write(b[:len(b)/2])
		return n, errors.New("simulated short write")
	}
	return f.File.Write(b)
}

func (f *faultyFile) Close() error {
	err := f.File.Close()
	if f.failClose {
		return errors.New("simulated close failure")
	}
	return err
}

// useFaultyFiles makes every audit file opened from now on a faultyFile set
// up by configure.
func useFaultyFiles(t *testing.T, configure func(*faultyFile)) {
	t.Helper()
	original := openAuditFile
	openAuditFile = func(path string) (auditFile, error) {
		file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		f := &faultyFile{File: file}
		configure(f)
		return f, nil
	}
	t.Cleanup(func() { openAuditFile = original })
}

func rotatingRelease(txid string) AuditEntry {
	stage := uint64(4)
	return AuditEntry{Event: AuditRotatingRelease, TxnAuth: "A", TxID: txid, RotatingStage: &stage, RotatingIndex: 1}
}

// A rotation that cannot move the previous log aside keeps it: the current
// file is not renamed over it, and stays in use.
func TestARotationThatCannotKeepThePreviousLogLosesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path+".1", []byte("previous history\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	original := renameAuditFile
	renameAuditFile = func(from, to string) error {
		if from == path+".1" {
			return errors.New("simulated rename failure")
		}
		return original(from, to)
	}
	t.Cleanup(func() { renameAuditFile = original })
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logger.Close() })
	logger.written = maxAuditLogSize // the next entry rotates

	logger.Log(AuditEntry{Event: AuditSignRequest, Reason: "after the failed rotation"})
	if previous, err := os.ReadFile(path + ".1"); err != nil || string(previous) != "previous history\n" {
		t.Fatalf("%s.1 = %q, %v; want the previous history kept", path, previous, err)
	}
	if current, err := os.ReadFile(path); err != nil || !strings.Contains(string(current), "after the failed rotation") {
		t.Fatalf("current log = %q, %v; want the entry in it", current, err)
	}
}

// A write that stops partway does not take the next entry with it: a
// durable rotating release written after the fragment is still read back.
func TestAShortWriteDoesNotSwallowTheNextEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	useFaultyFiles(t, func(f *faultyFile) { f.shortWrites = 1 })
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	if err := logger.logDurable(rotatingRelease("cut-short")); err == nil {
		t.Fatal("the short write reported success")
	}
	if err := logger.logDurable(rotatingRelease("after-the-fragment")); err != nil {
		t.Fatal(err)
	}
	releases, err := readReleasesAt(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := releases["A"]; got.TxID != "after-the-fragment" || len(got.Leaves) != 1 {
		t.Fatalf("releases read back = %+v; want the entry written after the fragment", got)
	}
}

// A rotation whose close fails does not leave the logger writing to a
// closed file: the next entries are written.
func TestAFailedCloseDoesNotStopTheLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	useFaultyFiles(t, func(f *faultyFile) { f.failClose = true })
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logger.Close() })
	logger.written = maxAuditLogSize // the next entry rotates, and its close fails

	if err := logger.logDurable(rotatingRelease("first")); err != nil {
		t.Fatalf("entry after the failed close: %v", err)
	}
	if err := logger.logDurable(rotatingRelease("second")); err != nil {
		t.Fatalf("next entry: %v", err)
	}
	current, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(current), `"txid":"first"`) || !strings.Contains(string(current), `"txid":"second"`) {
		t.Fatalf("current log = %q, %v; want both entries", current, err)
	}
}

// A line an earlier run left torn (a crash, or a full disk before a restart)
// is detected when the log is opened, so the first entry written after it is
// not merged into the fragment and lost.
func TestATornLineFromAnEarlierRunDoesNotSwallowTheFirstEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, []byte(`{"event":"ROTATING_RELEASE","txn_a`), 0o600); err != nil {
		t.Fatal(err)
	}
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logger.Close() })
	if err := logger.logDurable(rotatingRelease("after-restart")); err != nil {
		t.Fatal(err)
	}
	releases, err := readReleasesAt(path)
	if err != nil {
		t.Fatal(err)
	}
	if releases["A"].TxID != "after-restart" {
		t.Fatalf("releases = %+v; want the entry written after the torn line", releases)
	}
}

// After Close nothing is written and the file is not reopened, even by an
// entry that would rotate the log.
func TestNothingIsWrittenAfterClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
	logger.written = maxAuditLogSize
	logger.Log(AuditEntry{Event: AuditSignRequest})
	if err := logger.logDurable(rotatingRelease("late")); err == nil {
		t.Fatal("a durable entry after Close reported success")
	}
	if data, err := os.ReadFile(path); err != nil || len(data) != 0 {
		t.Fatalf("log after Close = %q, %v; want nothing written", data, err)
	}
	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Fatalf("the log rotated after Close: %v", err)
	}
}

// A rotation that cannot open the new log puts the old one back, so the
// entry is written once, in the current file, and the earlier history is
// kept in .2.
func TestARotationThatCannotOpenTheNewLogPutsTheOldOneBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path+".1", []byte("older history\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logger.Close() })
	logger.Log(AuditEntry{Event: AuditSignRequest, Reason: "before"})
	logger.written = maxAuditLogSize

	original := openAuditFile
	failOnce := true
	openAuditFile = func(p string) (auditFile, error) {
		if failOnce {
			failOnce = false
			return nil, errors.New("simulated open failure")
		}
		return original(p)
	}
	t.Cleanup(func() { openAuditFile = original })
	logger.Log(AuditEntry{Event: AuditSignRequest, Reason: "after"})

	current, err := os.ReadFile(path)
	if err != nil || strings.Count(string(current), `"reason":"before"`) != 1 || strings.Count(string(current), `"reason":"after"`) != 1 {
		t.Fatalf("current log = %q, %v; want both entries once", current, err)
	}
	if older, err := os.ReadFile(path + ".2"); err != nil || string(older) != "older history\n" {
		t.Fatalf("%s.2 = %q, %v; want the older history", path, older, err)
	}
}

// A rotation starts the new file cleanly even after a write was cut short:
// the guard newline belongs to the file the fragment is in.
func TestARotationAfterAShortWriteStartsCleanly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	shortFirst := true
	useFaultyFiles(t, func(f *faultyFile) {
		if shortFirst {
			shortFirst = false
			f.shortWrites = 1
		}
	})
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logger.Close() })
	_ = logger.logDurable(rotatingRelease("cut-short"))
	logger.written = maxAuditLogSize
	if err := logger.logDurable(rotatingRelease("in-the-new-file")); err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(path)
	if err != nil || len(current) == 0 || current[0] == '\n' {
		t.Fatalf("new log = %q, %v; want it to start with the entry", current, err)
	}
}
