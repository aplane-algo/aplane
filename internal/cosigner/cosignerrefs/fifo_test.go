// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

//go:build unix

package cosignerrefs

import (
	"syscall"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/witness"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

// A FIFO named for a reference is refused by its type and never read, so
// show, remove and import of that name answer at once instead of blocking,
// and the list reports it.
func TestAFIFONamedForAReferenceIsRefusedUnread(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	if _, err := Import(paths, "valid", testExportJSON(t, witness.Falcon1024V1, bytesOfLen(falconfamily.PublicKeySize, 0xab))); err != nil {
		t.Fatal(err)
	}
	fifo := paths.CosignerRefPath("pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	export := testExportJSON(t, witness.Falcon1024V1, bytesOfLen(falconfamily.PublicKeySize, 0xcd))

	done := make(chan []error, 1)
	go func() {
		_, _, getErr := Get(paths, "pipe")
		_, removeErr := Remove(paths, "pipe")
		_, importErr := Import(paths, "pipe", export)
		_, invalid, listErr := List(paths)
		if listErr == nil && (len(invalid) != 1 || invalid[0].Reason != "is not a regular file" || invalid[0].Removable) {
			t.Errorf("List() invalid = %+v, want the FIFO reported as not removable", invalid)
		}
		done <- []error{getErr, removeErr, importErr, listErr}
	}()
	var errs []error
	select {
	case errs = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("reading a FIFO named for a reference blocked")
	}
	want := []string{
		"cosigner reference pipe is not a regular file",
		"cosigner reference pipe is not a regular file",
		`cannot import cosigner reference "pipe" over a file that is not a valid reference: "` + fifo + `": is not a regular file (remove does not reach it; delete the file to clear it)`,
		"",
	}
	for i, err := range errs {
		got := ""
		if err != nil {
			got = err.Error()
		}
		if got != want[i] {
			t.Errorf("call %d error = %q, want %q", i, got, want[i])
		}
	}
}
