// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package genstore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const (
	testIdentity = "default"
	testGenA     = "gen-1753500000-0badc0de"
	testGenB     = "gen-1753500001-1badc0de"
)

// mintTestGeneration lays down a structurally valid generation with a
// complete manifest and the given namespace files.
func mintTestGeneration(t *testing.T, paths storepaths.Paths, generationID string, files map[string]string) storepaths.GenPaths {
	t.Helper()
	gen := paths.GenerationPaths(testIdentity, generationID)
	for _, namespace := range []string{"keys", "keytypes"} {
		if err := os.MkdirAll(filepath.Join(gen.Dir(), namespace), 0o770); err != nil {
			t.Fatalf("MkdirAll(%s) error = %v", namespace, err)
		}
	}
	for relative, content := range files {
		if err := os.WriteFile(filepath.Join(gen.Dir(), filepath.FromSlash(relative)), []byte(content), 0o660); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", relative, err)
		}
	}
	inventory, err := BuildInventory(gen)
	if err != nil {
		t.Fatalf("BuildInventory() error = %v", err)
	}
	if err := WriteManifest(gen, Manifest{
		GenerationID:  generationID,
		CreatedAtUnix: 1_753_500_000,
		Operation:     "test-mint",
		OperationID:   "op-" + generationID,
		Inventory:     inventory,
		Complete:      true,
	}); err != nil {
		t.Fatalf("WriteManifest() error = %v", err)
	}
	return gen
}

func TestCurrentPointerRoundTripAndResolve(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	mintTestGeneration(t, paths, testGenA, map[string]string{"keys/A.key": "a"})

	if err := WriteCurrent(paths, testIdentity, testGenA); err != nil {
		t.Fatalf("WriteCurrent() error = %v", err)
	}
	gen, err := Resolve(paths, testIdentity)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if gen.GenerationID() != testGenA {
		t.Fatalf("resolved generation = %s, want %s", gen.GenerationID(), testGenA)
	}
	if !strings.HasSuffix(gen.KeysDir(), filepath.Join("generations", testGenA, "keys")) {
		t.Fatalf("KeysDir = %s, not generation-qualified", gen.KeysDir())
	}
	if err := ValidateCurrent(gen); err != nil {
		t.Fatalf("ValidateCurrent() error = %v", err)
	}
}

func TestWriteCurrentRefusesMissingGeneration(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	if err := os.MkdirAll(paths.IdentityDir(testIdentity), 0o770); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := WriteCurrent(paths, testIdentity, testGenA); err == nil {
		t.Fatal("WriteCurrent pointed CURRENT at a generation that does not exist")
	}
}

func TestReadCurrentFailsClosedOnMalformedPointer(t *testing.T) {
	cases := map[string]string{
		"empty":              "",
		"garbage":            "not-a-generation\n",
		"traversal":          "../escape\n",
		"multiline":          testGenA + "\n" + testGenB + "\n",
		"embedded-nul":       testGenA + "\x00",
		"missing-generation": testGenA + "\n", // valid shape, no directory
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			paths := storepaths.NewPaths(t.TempDir())
			if err := os.MkdirAll(paths.IdentityDir(testIdentity), 0o770); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			if err := os.WriteFile(paths.CurrentPointerPath(testIdentity), []byte(content), 0o660); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			if _, err := ReadCurrent(paths, testIdentity); err == nil {
				t.Fatalf("ReadCurrent accepted malformed pointer %q", content)
			}
		})
	}
}

func TestReadCurrentRejectsSymlinkPointer(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	mintTestGeneration(t, paths, testGenA, nil)
	target := filepath.Join(paths.IdentityDir(testIdentity), "pointer-target")
	if err := os.WriteFile(target, []byte(testGenA+"\n"), 0o660); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Symlink(target, paths.CurrentPointerPath(testIdentity)); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if _, err := ReadCurrent(paths, testIdentity); err == nil {
		t.Fatal("ReadCurrent followed a symlinked CURRENT pointer")
	}
}

func TestSealRoundTripAndTamperDetection(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	gen := mintTestGeneration(t, paths, testGenA, map[string]string{
		"keys/A.key":            "credential-a",
		"keytypes/ed25519.json": "{}",
	})

	if err := WriteSeal(gen, 1_753_500_100); err != nil {
		t.Fatalf("WriteSeal() error = %v", err)
	}
	if err := ValidateSealed(gen); err != nil {
		t.Fatalf("ValidateSealed(untampered) error = %v", err)
	}

	// Content change after sealing must be detected.
	if err := os.WriteFile(filepath.Join(gen.KeysDir(), "A.key"), []byte("tampered"), 0o660); err != nil {
		t.Fatalf("tamper write: %v", err)
	}
	if err := ValidateSealed(gen); err == nil {
		t.Fatal("ValidateSealed accepted content that does not match the seal")
	}

	// So must a file the seal never recorded.
	if err := os.WriteFile(filepath.Join(gen.KeysDir(), "A.key"), []byte("credential-a"), 0o660); err != nil {
		t.Fatalf("restore write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gen.KeysDir(), "B.key"), []byte("new"), 0o660); err != nil {
		t.Fatalf("extra write: %v", err)
	}
	if err := ValidateSealed(gen); err == nil {
		t.Fatal("ValidateSealed accepted an unsealed extra file")
	}
}

func TestUnsealedGenerationFailsSealedValidation(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	gen := mintTestGeneration(t, paths, testGenA, map[string]string{"keys/A.key": "a"})
	if err := ValidateSealed(gen); err == nil {
		t.Fatal("ValidateSealed accepted a generation with no seal (uncommitted attempts must fail here)")
	}
	sealed, err := HasSeal(gen)
	if err != nil || sealed {
		t.Fatalf("HasSeal = (%v, %v), want (false, nil)", sealed, err)
	}
}

func TestValidateCurrentIgnoresStaleSealButChecksStructure(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	gen := mintTestGeneration(t, paths, testGenA, map[string]string{"keys/A.key": "a"})
	if err := WriteSeal(gen, 1_753_500_100); err != nil {
		t.Fatalf("WriteSeal() error = %v", err)
	}
	// Mutate after sealing: the current generation is mutable, so current
	// validation must not compare against the stale seal.
	if err := os.WriteFile(filepath.Join(gen.KeysDir(), "B.key"), []byte("b"), 0o660); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := ValidateCurrent(gen); err != nil {
		t.Fatalf("ValidateCurrent rejected a legitimately mutated current generation: %v", err)
	}

	// Structure violations still fail closed.
	if err := os.MkdirAll(filepath.Join(gen.Dir(), "unexpected"), 0o770); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := ValidateCurrent(gen); err == nil {
		t.Fatal("ValidateCurrent accepted an unsupported generation entry")
	}
}

func TestValidateRejectsSymlinkInNamespace(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	gen := mintTestGeneration(t, paths, testGenA, map[string]string{"keys/A.key": "a"})
	outside := filepath.Join(paths.Root(), "outside.key")
	if err := os.WriteFile(outside, []byte("x"), 0o660); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(gen.KeysDir(), "link.key")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if err := ValidateCurrent(gen); err == nil {
		t.Fatal("ValidateCurrent accepted a symlink inside a namespace")
	}
}

func TestManifestIncompleteFailsValidation(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	gen := paths.GenerationPaths(testIdentity, testGenA)
	for _, namespace := range []string{"keys", "keytypes"} {
		if err := os.MkdirAll(filepath.Join(gen.Dir(), namespace), 0o770); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
	}
	if err := WriteManifest(gen, Manifest{
		GenerationID:  testGenA,
		CreatedAtUnix: 1,
		Operation:     "test-mint",
		OperationID:   "op",
		Complete:      false,
	}); err != nil {
		t.Fatalf("WriteManifest() error = %v", err)
	}
	if err := ValidateCurrent(gen); err == nil {
		t.Fatal("ValidateCurrent accepted an incomplete (aborted-mint) manifest")
	}
}

func TestIsGenerational(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	if err := os.MkdirAll(paths.IdentityDir(testIdentity), 0o770); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	generational, err := IsGenerational(paths, testIdentity)
	if err != nil || generational {
		t.Fatalf("IsGenerational(legacy) = (%v, %v), want (false, nil)", generational, err)
	}
	mintTestGeneration(t, paths, testGenA, nil)
	if err := WriteCurrent(paths, testIdentity, testGenA); err != nil {
		t.Fatalf("WriteCurrent() error = %v", err)
	}
	generational, err = IsGenerational(paths, testIdentity)
	if err != nil || !generational {
		t.Fatalf("IsGenerational(migrated) = (%v, %v), want (true, nil)", generational, err)
	}
}

func TestGenerationIDValidation(t *testing.T) {
	valid := []string{testGenA, "gen-1-00000000"}
	for _, id := range valid {
		if err := storepaths.ValidateGenerationID(id); err != nil {
			t.Fatalf("ValidateGenerationID(%q) = %v, want nil", id, err)
		}
	}
	invalid := []string{"", "gen-", "gen-abc-00000000", "gen-1-xyz", "gen-1-0000000", "GEN-1-00000000", "gen-1-00000000/..", "../gen-1-00000000"}
	for _, id := range invalid {
		if err := storepaths.ValidateGenerationID(id); err == nil {
			t.Fatalf("ValidateGenerationID(%q) accepted an invalid ID", id)
		}
	}
}

func TestResolveActiveResolvesGeneration(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())

	// An uninitialized store (no CURRENT) is an error, never a fallback.
	if _, err := ResolveActive(paths, testIdentity); err == nil {
		t.Fatal("ResolveActive resolved a store with no CURRENT pointer")
	}

	gen := mintTestGeneration(t, paths, testGenA, nil)
	if err := WriteCurrent(paths, testIdentity, testGenA); err != nil {
		t.Fatalf("WriteCurrent: %v", err)
	}
	active, err := ResolveActive(paths, testIdentity)
	if err != nil {
		t.Fatalf("ResolveActive() error = %v", err)
	}
	if active.KeysDir() != gen.KeysDir() {
		t.Fatalf("KeysDir = %s, want %s", active.KeysDir(), gen.KeysDir())
	}

	// A present-but-invalid CURRENT is an error.
	if err := os.WriteFile(paths.CurrentPointerPath(testIdentity), []byte("garbage"+"\n"), 0o660); err != nil {
		t.Fatalf("corrupt CURRENT: %v", err)
	}
	if _, err := ResolveActive(paths, testIdentity); err == nil {
		t.Fatal("ResolveActive accepted an invalid CURRENT pointer")
	}
}

// TestWriteCurrentUnreadablePointerIsUnknownNotUncommitted proves the
// classification rule: only a successful read of the old pointer proves the
// rename never landed; an unreadable pointer is unknown commit state.
func TestWriteCurrentUnreadablePointerIsUnknownNotUncommitted(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	mintTestGeneration(t, paths, testGenA, nil)

	// A pointer that ReadCurrent rejects (symlink) plus an injected write
	// failure: the write path cannot prove non-commit by reading back.
	target := filepath.Join(paths.IdentityDir(testIdentity), "pointer-target")
	if err := os.WriteFile(target, []byte("x\n"), 0o660); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Symlink(target, paths.CurrentPointerPath(testIdentity)); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	injected := errors.New("injected file-sync failure")
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpFileSync && filepath.Base(path) == storepaths.CurrentPointerName {
			return injected
		}
		return nil
	}
	defer func() { fsutil.TestHook = nil }()

	err := WriteCurrent(paths, testIdentity, testGenA)
	if !errors.Is(err, ErrCommitDurabilityUnknown) {
		t.Fatalf("WriteCurrent error = %v, want ErrCommitDurabilityUnknown (unreadable pointer proves nothing)", err)
	}
}
