// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package audit

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A rotation that comes while the signer reads its release history cannot
// hide a file: the logger's own read opens all three files before the
// rotation can run, so every consumed leaf is found.
func TestRotationDuringTheReleaseReadHidesNoFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	release := func(txid string, index int) string {
		return `{"event":"ROTATING_RELEASE","txn_auth":"A","txid":"` + txid + `","rotating_stage":4,"rotating_last_valid":9,"rotating_index":` + strconv.Itoa(index) + "}\n"
	}
	for name, content := range map[string]string{
		path + ".2": release("oldest", 0),
		path + ".1": release("middle", 1),
		path:        release("newest", 2),
	} {
		if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logger.Close() })
	logger.written = maxAuditLogSize // the next entry rotates the log

	// After the oldest file is open, an entry arrives and would rotate the
	// log, moving the middle file over the oldest's name and the newest
	// over the middle's.
	logged := make(chan struct{})
	afterReleaseLogOpen = func() {
		afterReleaseLogOpen = nil
		go func() {
			logger.Log(AuditEntry{Event: AuditSignRequest})
			close(logged)
		}()
		select {
		case <-logged: // the rotation ran between two opens
		case <-time.After(100 * time.Millisecond): // it waits for the opens
		}
	}
	t.Cleanup(func() { afterReleaseLogOpen = nil })

	got, err := logger.ReadRotatingReleases()
	<-logged
	if err != nil {
		t.Fatal(err)
	}
	leaves := got["A"].Leaves
	if len(leaves) != 3 || leaves[0].Index != 0 || leaves[1].Index != 1 || leaves[2].Index != 2 {
		t.Fatalf("read %+v across a rotation, want leaves 0, 1 and 2 in log order", leaves)
	}
	// The entry did rotate the log: the middle file now has the oldest's
	// name, and the current file holds only the new entry.
	if rotated, err := os.ReadFile(path + ".2"); err != nil || !strings.Contains(string(rotated), `"txid":"middle"`) {
		t.Fatalf("the entry did not rotate the log: %s.2 = %q, %v", path, rotated, err)
	}
	if current, err := os.ReadFile(path); err != nil || strings.Contains(string(current), "ROTATING_RELEASE") {
		t.Fatalf("the current file after the rotation = %q, %v; want only the new entry", current, err)
	}
}
