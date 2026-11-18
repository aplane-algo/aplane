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
	releases, err := ReadRotatingReleases(path)
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
