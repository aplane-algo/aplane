// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotatingReleaseRoundTripsThroughTheLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	attr := Attribution{RequesterPrincipal: "client-1", Transport: "http"}
	if err := a.LogRotatingReleaseAttributed(attr, "ACCT1", "TX1", 0, 100, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := a.LogRotatingReleaseAttributed(attr, "ACCT1", "TX2", 1, 220, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := a.LogRotatingReleaseAttributed(attr, "ACCT2", "TX3", 7, 300, 0, 0); err != nil {
		t.Fatal(err)
	}
	// ACCT3 released twice from stage 2 (a retry of TX4, then a different
	// TX5): reuse. ACCT4 only retried the same transaction: not reuse.
	for _, e := range []struct {
		acct, txid string
		stage      uint64
	}{{"ACCT3", "TX4", 2}, {"ACCT3", "TX4", 2}, {"ACCT3", "TX5", 2}, {"ACCT4", "TX6", 9}, {"ACCT4", "TX6", 9}} {
		if err := a.LogRotatingReleaseAttributed(attr, e.acct, e.txid, e.stage, 400, 0, 0); err != nil {
			t.Fatal(err)
		}
	}
	a.LogSignApproved("ACCT1", "ACCT1", "unrelated")

	got, err := ReadRotatingReleases(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("releases = %+v, want four accounts", got)
	}
	if r := got["ACCT1"]; r.Stage != 1 || r.TxID != "TX2" || r.LastValid != 220 || r.Reused {
		t.Fatalf("ACCT1 newest = %+v", r)
	}
	if r := got["ACCT2"]; r.Stage != 7 || r.TxID != "TX3" || r.LastValid != 300 || r.Reused {
		t.Fatalf("ACCT2 = %+v", r)
	}
	if r := got["ACCT3"]; r.TxID != "TX5" || !r.Reused {
		t.Fatalf("ACCT3 reuse not detected: %+v", r)
	}
	if r := got["ACCT4"]; r.TxID != "TX6" || r.Reused {
		t.Fatalf("ACCT4 retry marked as reuse: %+v", r)
	}
	// Stage 0 survives: the field is a pointer, so omitempty cannot drop it.
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `"rotating_stage":0`) {
		t.Fatalf("stage 0 missing from the log:\n%s", data)
	}
}

func TestReadRotatingReleasesSpansRotatedFilesOldestFirst(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	line := func(acct, txid string, stage uint64) string {
		return `{"event":"ROTATING_RELEASE","txn_auth":"` + acct + `","txid":"` + txid + `","rotating_stage":` + itoa(stage) + `,"rotating_last_valid":9}` + "\n"
	}
	if err := os.WriteFile(path+".2", []byte(line("A", "old", 1)+"garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".1", []byte(line("A", "mid", 2)+line("B", "b", 5)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(line("A", "new", 3)), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadRotatingReleases(path)
	if err != nil {
		t.Fatal(err)
	}
	if got["A"].TxID != "new" || got["A"].Stage != 3 || got["A"].Reused || got["B"].TxID != "b" {
		t.Fatalf("releases = %+v", got)
	}
	// Reuse is seen across rotated files too.
	if err := os.WriteFile(path, []byte(line("A", "new", 3)+line("B", "b2", 5)), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = ReadRotatingReleases(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got["B"].Reused || got["B"].TxID != "b2" || got["A"].Reused {
		t.Fatalf("reuse across rotated files: %+v", got)
	}
	// No log at all is not an error.
	empty, err := ReadRotatingReleases(filepath.Join(dir, "missing.log"))
	if err != nil || len(empty) != 0 {
		t.Fatalf("missing log: %v, %v", empty, err)
	}
}

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte('0' + v%10)}, b...)
		v /= 10
	}
	return string(b)
}

// A family whose stage holds several leaves is reused only when two
// releases name the same leaf; distinct leaves are listed, not flagged.
func TestReadRotatingReleasesTracksLeaves(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	attr := Attribution{RequesterPrincipal: "client-1", Transport: "http"}
	for _, e := range []struct {
		txid  string
		index uint32
	}{{"TX7", 5}, {"TX8", 6}, {"TX8", 6}} {
		if err := a.LogRotatingReleaseAttributed(attr, "ACCT5", e.txid, 4, 500, 2, e.index); err != nil {
			t.Fatal(err)
		}
	}
	got, err := ReadRotatingReleases(path)
	if err != nil {
		t.Fatal(err)
	}
	r := got["ACCT5"]
	if r.Reused || r.Tree != 2 || r.Index != 6 || r.TxID != "TX8" || len(r.Leaves) != 2 || r.Leaves[0].Index != 5 || r.Leaves[1].Index != 6 {
		t.Fatalf("leaf releases = %+v", r)
	}
	if err := a.LogRotatingReleaseAttributed(attr, "ACCT5", "TX9", 4, 500, 2, 5); err != nil {
		t.Fatal(err)
	}
	got, err = ReadRotatingReleases(path)
	if err != nil {
		t.Fatal(err)
	}
	if r := got["ACCT5"]; !r.Reused || len(r.Leaves) != 3 {
		t.Fatalf("same leaf twice not reported as reuse: %+v", r)
	}
	// A new stage starts a fresh list.
	if err := a.LogRotatingReleaseAttributed(attr, "ACCT5", "TX10", 5, 600, 2, 64); err != nil {
		t.Fatal(err)
	}
	got, _ = ReadRotatingReleases(path)
	if r := got["ACCT5"]; r.Reused || len(r.Leaves) != 1 || r.Stage != 5 {
		t.Fatalf("new stage = %+v", r)
	}
}
