// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package fsutil

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileDurableCreatesNewFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fresh.bin")

	if err := WriteFileDurable(path, []byte("hello")); err != nil {
		t.Fatalf("WriteFileDurable: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("contents = %q, want %q", string(data), "hello")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != StoreFilePerm {
		t.Fatalf("mode = %04o, want %04o", got, StoreFilePerm)
	}

	matches, err := filepath.Glob(filepath.Join(dir, "fresh.bin.tmp-*"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("leftover temp files: %v", matches)
	}
}

func TestWriteFileDurableReplacesAndPreservesMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.bin")

	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	if err := WriteFileDurable(path, []byte("new")); err != nil {
		t.Fatalf("WriteFileDurable: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "new" {
		t.Fatalf("contents = %q, want %q", string(data), "new")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != os.FileMode(0o600) {
		t.Fatalf("mode = %04o, want 0600", got)
	}
}

func TestWriteFileDurableClampsPermissiveMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.bin")
	if err := os.WriteFile(path, []byte("old"), 0o666); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	if err := WriteFileDurable(path, []byte("new")); err != nil {
		t.Fatalf("WriteFileDurable: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != StoreFilePerm {
		t.Fatalf("mode = %04o, want %04o", got, StoreFilePerm)
	}
}

func TestWriteFileDurablePrivateProfileCreatesOwnerOnlyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "private.bin")

	if err := WriteFileDurableWithProfile(path, []byte("secret"), PrivateStoreFileProfile); err != nil {
		t.Fatalf("WriteFileDurableWithProfile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %04o, want 0600", got)
	}
}

func TestWriteFileDurableRejectsSymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(dir, "outside")
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil {
		t.Fatalf("WriteFile(outside): %v", err)
	}
	if err := os.Symlink(outside, target); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	if err := WriteFileDurable(target, []byte("attacker")); err == nil {
		t.Fatal("WriteFileDurable accepted symlink target")
	}
	data, err := os.ReadFile(outside)
	if err != nil {
		t.Fatalf("ReadFile(outside): %v", err)
	}
	if string(data) != "unchanged" {
		t.Fatalf("outside contents = %q, want unchanged", data)
	}
}

func TestWriteFileDurableRejectsNonRegularTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := WriteFileDurable(target, []byte("data")); err == nil {
		t.Fatal("WriteFileDurable accepted directory target")
	}
}

func TestWriteFileDurableRejectsSymlinkParent(t *testing.T) {
	dir := t.TempDir()
	realDir := filepath.Join(dir, "real")
	linkDir := filepath.Join(dir, "link")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if err := WriteFileDurable(filepath.Join(linkDir, "target"), []byte("data")); err == nil {
		t.Fatal("WriteFileDurable accepted symlink parent")
	}
}

func TestWriteFileDurableRejectsUnknownProfile(t *testing.T) {
	dir := t.TempDir()
	err := WriteFileDurableWithProfile(filepath.Join(dir, "target"), []byte("data"), DurableFileProfile(255))
	if err == nil {
		t.Fatal("WriteFileDurableWithProfile accepted unknown profile")
	}
}

func TestWriteFileSetDurableRejectsOmittedProfile(t *testing.T) {
	dir := t.TempDir()
	err := WriteFileSetDurable(DurableFileWrite{Path: filepath.Join(dir, "target"), Data: []byte("data")})
	if err == nil {
		t.Fatal("WriteFileSetDurable accepted an omitted profile")
	}
}

func TestWriteFileDurableOperationOrdering(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ordered.bin")

	var ops []HookOp
	TestHook = func(op HookOp, hookPath string) error {
		ops = append(ops, op)
		return nil
	}
	defer func() { TestHook = nil }()

	if err := WriteFileDurable(path, []byte("x")); err != nil {
		t.Fatalf("WriteFileDurable: %v", err)
	}

	want := []HookOp{OpFileSync, OpRename, OpDirSync}
	if len(ops) != len(want) {
		t.Fatalf("ops = %v, want %v", ops, want)
	}
	for i := range want {
		if ops[i] != want[i] {
			t.Fatalf("ops = %v, want %v", ops, want)
		}
	}
}

func TestWriteFileDurableFailureBeforeRenameLeavesTargetUntouched(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target.bin")

	if err := os.WriteFile(path, []byte("old"), 0o660); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	for _, failAt := range []HookOp{OpFileSync, OpRename} {
		injected := errors.New("injected " + string(failAt))
		TestHook = func(op HookOp, hookPath string) error {
			if op == failAt {
				return injected
			}
			return nil
		}

		err := WriteFileDurable(path, []byte("new"))
		TestHook = nil
		if !errors.Is(err, injected) {
			t.Fatalf("failAt=%s: err = %v, want %v", failAt, err, injected)
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("ReadFile: %v", readErr)
		}
		if string(data) != "old" {
			t.Fatalf("failAt=%s: contents = %q, want old content preserved", failAt, string(data))
		}

		matches, globErr := filepath.Glob(filepath.Join(dir, "target.bin.tmp-*"))
		if globErr != nil {
			t.Fatalf("Glob: %v", globErr)
		}
		if len(matches) != 0 {
			t.Fatalf("failAt=%s: leftover temp files: %v", failAt, matches)
		}
	}
}

func TestWriteFileDurableDirSyncFailureIsReported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target.bin")

	injected := errors.New("injected dir-sync")
	TestHook = func(op HookOp, hookPath string) error {
		if op == OpDirSync {
			return injected
		}
		return nil
	}
	defer func() { TestHook = nil }()

	if err := WriteFileDurable(path, []byte("new")); !errors.Is(err, injected) {
		t.Fatalf("err = %v, want %v", err, injected)
	}
}

func TestWriteFileSetDurableStagesAllMembersBeforePublishing(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.bin")
	second := filepath.Join(dir, "second.bin")
	for _, path := range []string{first, second} {
		if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	injected := errors.New("injected second file sync")
	TestHook = func(op HookOp, path string) error {
		if op == OpFileSync && path == second {
			return injected
		}
		return nil
	}
	defer func() { TestHook = nil }()

	err := WriteFileSetDurable(
		DurableFileWrite{Path: first, Data: []byte("new-first"), Profile: PrivateStoreFileProfile},
		DurableFileWrite{Path: second, Data: []byte("new-second"), Profile: PrivateStoreFileProfile},
	)
	if !errors.Is(err, injected) {
		t.Fatalf("WriteFileSetDurable() error = %v, want %v", err, injected)
	}
	for _, path := range []string{first, second} {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if string(data) != "old" {
			t.Fatalf("%s contents = %q, want old", path, data)
		}
	}
}

func TestRemoveDurableWriteTempsRemovesOnlyReservedRegularFiles(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.bin")
	temp := filepath.Join(dir, "target.bin.tmp-crash")
	unrelated := filepath.Join(dir, "other.tmp-crash")
	for _, path := range []string{target, temp, unrelated} {
		if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", path, err)
		}
	}
	if err := RemoveDurableWriteTemps(target); err != nil {
		t.Fatalf("RemoveDurableWriteTemps() error = %v", err)
	}
	if _, err := os.Stat(temp); !os.IsNotExist(err) {
		t.Fatalf("reserved temp survived cleanup: %v", err)
	}
	for _, path := range []string{target, unrelated} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("cleanup removed %s: %v", path, err)
		}
	}
}

func TestRemoveDurableWriteTempsRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.bin")
	if err := os.WriteFile(target, []byte("data"), 0o600); err != nil {
		t.Fatalf("WriteFile(target) error = %v", err)
	}
	temp := filepath.Join(dir, "target.bin.tmp-crash")
	if err := os.Symlink(target, temp); err != nil {
		t.Fatalf("Symlink(temp) error = %v", err)
	}
	if err := RemoveDurableWriteTemps(target); err == nil {
		t.Fatal("RemoveDurableWriteTemps() accepted symlink residue")
	}
	if _, err := os.Lstat(temp); err != nil {
		t.Fatalf("rejected symlink residue was removed: %v", err)
	}
}

func TestSyncDir(t *testing.T) {
	if err := SyncDir(t.TempDir()); err != nil {
		t.Fatalf("SyncDir: %v", err)
	}
}

func TestRemoveDurable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "victim.bin")
	if err := os.WriteFile(path, []byte("x"), 0o660); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	if err := RemoveDurable(path); err != nil {
		t.Fatalf("RemoveDurable: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("file still exists after RemoveDurable")
	}

	// Removing a missing path is not an error.
	if err := RemoveDurable(path); err != nil {
		t.Fatalf("RemoveDurable on missing path: %v", err)
	}
}
