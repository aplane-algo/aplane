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
	if err := a.LogRotatingReleaseAttributed(attr, "ACCT1", "TX1", 0, 100); err != nil {
		t.Fatal(err)
	}
	if err := a.LogRotatingReleaseAttributed(attr, "ACCT1", "TX2", 1, 220); err != nil {
		t.Fatal(err)
	}
	if err := a.LogRotatingReleaseAttributed(attr, "ACCT2", "TX3", 7, 300); err != nil {
		t.Fatal(err)
	}
	a.LogSignApproved("ACCT1", "ACCT1", "unrelated")

	got, err := ReadRotatingReleases(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("releases = %+v, want two accounts", got)
	}
	if r := got["ACCT1"]; r.Stage != 1 || r.TxID != "TX2" || r.LastValid != 220 {
		t.Fatalf("ACCT1 newest = %+v", r)
	}
	if r := got["ACCT2"]; r.Stage != 7 || r.TxID != "TX3" || r.LastValid != 300 {
		t.Fatalf("ACCT2 = %+v", r)
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
	if got["A"].TxID != "new" || got["A"].Stage != 3 || got["B"].TxID != "b" {
		t.Fatalf("releases = %+v", got)
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
