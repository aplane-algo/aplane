// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storelock

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestAcquireExclusiveBlockedBySharedLock(t *testing.T) {
	dir := t.TempDir()

	shared, err := AcquireShared(dir)
	if err != nil {
		t.Fatalf("AcquireShared() error = %v", err)
	}
	defer func() { _ = shared.Close() }()

	exclusive, err := AcquireExclusive(dir)
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("AcquireExclusive() error = %v, want ErrBusy", err)
	}
	if exclusive != nil {
		t.Fatal("AcquireExclusive() returned guard while shared lock held")
	}
}

// One signer holds the signer lock at a time, and the next takes it once the
// first lets go, with nothing to clean up.
func TestAcquireSignerAllowsOne(t *testing.T) {
	dir := t.TempDir()
	for range 2 {
		signer, err := AcquireSigner(dir)
		if err != nil {
			t.Fatal(err)
		}
		if second, err := AcquireSigner(dir); !errors.Is(err, ErrBusy) || second != nil {
			t.Fatalf("AcquireSigner() beside another = %v, %v; want ErrBusy", second, err)
		}
		other, err := AcquireSigner(t.TempDir())
		if err != nil {
			t.Fatalf("AcquireSigner() of another directory = %v", err)
		}
		_ = other.Close()
		if err := signer.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

// The signer lock is not the store lock: holding it keeps out neither the
// offline readers nor the store's changes, which the shared store lock does.
func TestTheSignerLockIsNotTheStoreLock(t *testing.T) {
	dir := t.TempDir()
	signer, err := AcquireSigner(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = signer.Close() }()
	for name, acquire := range map[string]func(string) (*Guard, error){"shared": AcquireShared, "exclusive": AcquireExclusive} {
		guard, err := acquire(dir)
		if err != nil {
			t.Fatalf("%s store lock beside a signer lock = %v", name, err)
		}
		if err := guard.Close(); err != nil {
			t.Fatal(err)
		}
	}

	store, err := AcquireExclusive(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	if err := signer.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := AcquireSigner(dir)
	if err != nil {
		t.Fatalf("AcquireSigner() beside the exclusive store lock = %v", err)
	}
	_ = again.Close()
}

// A process the holder starts does not inherit a lock. A passphrase helper may
// leave an agent running, which would otherwise keep the signer lock after the
// signer is gone and refuse every later start.
func TestALockIsNotInheritedByAChildProcess(t *testing.T) {
	for name, acquire := range map[string]func(string) (*Guard, error){
		"shared": AcquireShared, "exclusive": AcquireExclusive, "signer": AcquireSigner,
	} {
		guard, err := acquire(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		flags, err := unix.FcntlInt(guard.f.Fd(), unix.F_GETFD, 0)
		if err != nil {
			t.Fatal(err)
		}
		if flags&unix.FD_CLOEXEC == 0 {
			t.Errorf("the %s lock's descriptor is not close-on-exec", name)
		}
		_ = guard.Close()
	}
}

// A lock file is opened as it is: no link is followed, and no file with another
// name is locked or changed.
func TestAcquireRefusesALinkedLockFile(t *testing.T) {
	for name, tc := range map[string]struct {
		file    string
		acquire func(string) (*Guard, error)
	}{
		"store":  {storeLockFileName, AcquireExclusive},
		"signer": {signerLockFileName, AcquireSigner},
	} {
		t.Run(name+" symlink", func(t *testing.T) {
			dir := t.TempDir()
			outside := filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(dir, tc.file)); err != nil {
				t.Fatal(err)
			}
			if _, err := tc.acquire(dir); err == nil {
				t.Fatal("a symlinked lock file was accepted")
			}
			data, err := os.ReadFile(outside)
			if err != nil || string(data) != "unchanged" {
				t.Fatalf("outside changed: %q, %v", data, err)
			}
		})
		t.Run(name+" hard link", func(t *testing.T) {
			dir := t.TempDir()
			original := filepath.Join(t.TempDir(), "original")
			if err := os.WriteFile(original, []byte("unchanged"), 0o640); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(original, filepath.Join(dir, tc.file)); err != nil {
				t.Fatal(err)
			}
			if _, err := tc.acquire(dir); err == nil || !strings.Contains(err.Error(), "exactly one link") {
				t.Fatalf("error = %v, want hardlink rejection", err)
			}
			info, err := os.Stat(original)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o640 {
				t.Fatalf("hardlink target mode changed to %04o", info.Mode().Perm())
			}
		})
	}
}
