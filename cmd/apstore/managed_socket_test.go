// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	signerbootstrap "github.com/aplane-algo/aplane/internal/bootstrap/signer"
)

// permissionTestStore points dataDirectory at a fresh store owned by the test
// user; managed adds the .prod marker and records the test user as the
// service principal.
func permissionTestStore(t *testing.T, managed bool) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket contract")
	}
	oldDataDirectory, oldOwner := dataDirectory, managedStoreOwner
	t.Cleanup(func() { dataDirectory, managedStoreOwner = oldDataDirectory, oldOwner })
	dataDirectory = t.TempDir()
	if err := os.Chmod(dataDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if managed {
		uid, gid := os.Getuid(), os.Getgid()
		managedStoreOwner = func(string) (int, int, error) { return uid, gid, nil }
		if err := os.WriteFile(filepath.Join(dataDirectory, signerbootstrap.ProdMarkerFile), []byte("systemd-managed\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dataDirectory
}

// staleSocket leaves a socket file behind with nothing listening on it, as a
// stopped daemon does.
func staleSocket(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
}

func requireMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %04o, want %04o", path, got, want)
	}
}

func TestPermissionsMigrateRepairsAManagedStore(t *testing.T) {
	root := permissionTestStore(t, true)
	file := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(file, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := cmdPermissions([]string{"migrate"}); err != nil {
		t.Fatalf("cmdPermissions(migrate) error = %v", err)
	}
	requireMode(t, file, 0o600)
}

// A managed daemon never binds inside the store, so a socket there is not
// residue the repair may remove: it is refused like any unexpected object.
func TestPermissionsMigrateRefusesAnInStoreSocketOnAManagedStore(t *testing.T) {
	root := permissionTestStore(t, true)
	socket := filepath.Join(root, "aplane.sock")
	staleSocket(t, socket)

	err := cmdPermissions([]string{"migrate"})
	want := "refusing unsafe signer-store migration: " + socket + ": unexpected filesystem object type (type)"
	if err == nil || err.Error() != want {
		t.Fatalf("cmdPermissions(migrate) error = %v, want %q", err, want)
	}
	if _, statErr := os.Lstat(socket); statErr != nil {
		t.Fatalf("refused migration removed the socket: %v", statErr)
	}
}

// The repair of a managed store reads nothing from config.yaml, so a
// config.yaml that does not parse does not stop it.
func TestPermissionsMigrateDoesNotReadConfig(t *testing.T) {
	root := permissionTestStore(t, true)
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), []byte("ipc_path: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdPermissions([]string{"migrate"}); err != nil {
		t.Fatalf("cmdPermissions(migrate) error = %v", err)
	}
}

// Conversion removes the socket the local daemon left at its configured
// in-store path, before it publishes the managed metadata. Without root that
// publication fails, after the socket is gone.
func TestPermissionsConvertManagedRemovesTheLocalDaemonSocket(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("conversion of the test user's store; root publishes the metadata")
	}
	for name, configured := range map[string]string{
		"default": "",
		"custom":  filepath.Join("run", "custom.sock"),
	} {
		t.Run(name, func(t *testing.T) {
			root := permissionTestStore(t, false)
			socket := filepath.Join(root, "aplane.sock")
			if configured != "" {
				socket = filepath.Join(root, configured)
				if err := os.WriteFile(filepath.Join(root, "config.yaml"), []byte("ipc_path: "+socket+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			staleSocket(t, socket)

			err := cmdPermissionsConvertManaged(convertManagedArgs())
			if err != nil && !strings.Contains(err.Error(), "install metadata directory") {
				t.Fatalf("cmdPermissionsConvertManaged() error = %v, want success or the root-only metadata step", err)
			}
			if _, statErr := os.Lstat(socket); !os.IsNotExist(statErr) {
				t.Fatalf("conversion left the local daemon's socket: %v", statErr)
			}
		})
	}
}

// A same-UID daemon run with the default socket, before config.yaml named a
// path outside the store, left the default behind; conversion removes it.
func TestPermissionsConvertManagedRemovesTheDefaultSocketWhenConfigNamesAnExternalPath(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("conversion of the test user's store; root publishes the metadata")
	}
	root := permissionTestStore(t, false)
	external := filepath.Join(t.TempDir(), "runtime", "custom.sock")
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), []byte("ipc_path: "+external+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(root, "aplane.sock")
	staleSocket(t, socket)

	err := cmdPermissionsConvertManaged(convertManagedArgs())
	if err != nil && !strings.Contains(err.Error(), "install metadata directory") {
		t.Fatalf("cmdPermissionsConvertManaged() error = %v, want success or the root-only metadata step", err)
	}
	if _, statErr := os.Lstat(socket); !os.IsNotExist(statErr) {
		t.Fatalf("conversion left the stale default socket: %v", statErr)
	}
}

func convertManagedArgs() []string {
	return []string{"--uid", strconv.Itoa(os.Getuid()), "--gid", strconv.Itoa(os.Getgid())}
}

// The systemd installer runs the conversion on every install, an already
// managed store included. There it repairs as permissions migrate does: a
// socket inside the store is refused, not removed.
func TestPermissionsConvertManagedRepairsAnAlreadyManagedStoreAsMigrateDoes(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("conversion of the test user's store; root publishes the metadata")
	}
	root := permissionTestStore(t, true)
	socket := filepath.Join(root, "aplane.sock")
	staleSocket(t, socket)

	err := cmdPermissionsConvertManaged(convertManagedArgs())
	want := "refusing unsafe signer-store migration: " + socket + ": unexpected filesystem object type (type)"
	if err == nil || err.Error() != want {
		t.Fatalf("cmdPermissionsConvertManaged() error = %v, want %q", err, want)
	}
	if _, statErr := os.Lstat(socket); statErr != nil {
		t.Fatalf("refused conversion removed the socket: %v", statErr)
	}
}
