// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/signerapp/storevalidate"
	"github.com/aplane-algo/aplane/internal/storeinit"
	"github.com/aplane-algo/aplane/internal/storelock"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// requireRunRefuses starts the daemon on dir and checks that it exits 1 saying
// why, and for no other reason.
func requireRunRefuses(t *testing.T, dir, reason string) {
	t.Helper()
	logs := &syncBuffer{}
	appLogger.SetOutput(logs)
	t.Cleanup(func() { appLogger.SetOutput(os.Stderr) })
	code := make(chan int, 1)
	go func() { code <- Run(dir) }()
	select {
	case got := <-code:
		if got != 1 || !strings.Contains(logs.String(), reason) {
			t.Fatalf("Run() = %d, want 1 saying %q; it logged:\n%s", got, reason, logs)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("the signer started; it logged:\n%s", logs)
	}
}

// signerLockDir is a data directory whose signer, if a test's guard fails and it
// starts, takes free ports rather than the default ones.
func signerLockDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	var ports [2]int
	for i := range ports {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = listener.Close() }()
		ports[i] = listener.Addr().(*net.TCPAddr).Port
	}
	config := fmt.Sprintf("endpoint:\n  signer_port: %d\n  ssh:\n    port: %d\n", ports[0], ports[1])
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A signer started on a data directory another one uses refuses before it
// touches the store. It once found the other's admin socket in use only after it
// had deleted the other's unfinished backup import and generation staging, and
// unlocked and reconciled the store.
func TestASecondSignerRefusesBeforeItTouchesTheStore(t *testing.T) {
	dir := signerLockDir(t)
	paths := storepaths.NewPaths(dir)
	if _, err := storeinit.Initialize([]byte("signer-lock-passphrase"), storeinit.Options{
		ValidateCandidate: storevalidate.FirstGeneration, DataDir: dir, Paths: paths,
	}); err != nil {
		t.Fatal(err)
	}
	unfinished := []string{
		filepath.Join(paths.ProductBackupsDir(), ".import-probe.part"),
		filepath.Join(paths.GenerationsDir(), storepaths.GenerationStagingPrefix+"probe", "keys.txt"),
	}
	for _, path := range unfinished {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("unfinished"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	first, err := storelock.AcquireSigner(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	t.Setenv("DISABLE_MEMORY_LOCK", "1")
	t.Setenv("TEST_PASSPHRASE", "signer-lock-passphrase")

	requireRunRefuses(t, dir, "another apsigner is already using "+dir+"; stop it first")
	for _, path := range unfinished {
		if data, err := os.ReadFile(path); err != nil || string(data) != "unfinished" {
			t.Errorf("%s = %q, %v; want it left alone", path, data, err)
		}
	}
	for _, name := range []string{"audit.log", "aplane.sock"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("a refused start created %s: %v", name, err)
		}
	}
}

// A start refused because apstore is changing the store creates no signer lock
// file in it.
func TestAStartRefusedByTheStoreLockCreatesNoSignerLock(t *testing.T) {
	dir := signerLockDir(t)
	offline, err := storelock.AcquireExclusive(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = offline.Close() }()
	requireRunRefuses(t, dir, "signer store is locked by an offline apstore mutation in "+dir)
	if _, err := os.Lstat(filepath.Join(dir, ".apsigner.lock")); !os.IsNotExist(err) {
		t.Fatalf("a refused start created the signer lock: %v", err)
	}
}
