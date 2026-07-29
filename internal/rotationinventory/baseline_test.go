// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rotationinventory

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const (
	baselineGeneration = "gen-1785300100-feedface"
	baselinePrior      = "gen-1785300000-cafef00d"
)

func TestBaselineWriteReadAndAuthority(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	if err := fsutil.MkdirAll(paths.IdentityDir(inventoryIdentity)); err != nil {
		t.Fatalf("MkdirAll(identity) error = %v", err)
	}
	kr := cryptotest.KeyringAtTerm(t, 2, bytes.Repeat([]byte{0x92}, 32))
	baseline, err := NewBaseline(baselineGeneration, baselineInventory())
	if err != nil {
		t.Fatalf("NewBaseline() error = %v", err)
	}

	var operations []fsutil.HookOp
	baselinePath := paths.RotationBaselinePath(inventoryIdentity)
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if path == baselinePath || path == filepath.Dir(baselinePath) {
			operations = append(operations, op)
		}
		return nil
	}
	t.Cleanup(func() { fsutil.TestHook = nil })

	if err := WriteBaseline(paths, inventoryIdentity, baseline, kr); err != nil {
		t.Fatalf("WriteBaseline() error = %v", err)
	}
	wantOperations := []fsutil.HookOp{fsutil.OpFileSync, fsutil.OpRename, fsutil.OpDirSync}
	if !slices.Equal(operations, wantOperations) {
		t.Fatalf("durable operations = %v, want %v", operations, wantOperations)
	}
	exact, err := os.ReadFile(baselinePath)
	if err != nil {
		t.Fatalf("ReadFile(baseline) error = %v", err)
	}
	if term, err := crypto.EnvelopeTerm(exact); err != nil || term != 2 {
		t.Fatalf("baseline envelope term = %d, %v, want 2", term, err)
	}
	opened, err := ReadBaseline(paths, inventoryIdentity, kr)
	if err != nil {
		t.Fatalf("ReadBaseline() error = %v", err)
	}
	if *opened != *baseline {
		t.Fatalf("ReadBaseline() = %#v, want %#v", opened, baseline)
	}
	authority, err := BaselineAuthority(opened)
	if err != nil {
		t.Fatalf("BaselineAuthority() error = %v", err)
	}
	if authority.Source != AuthorityRotationBaseline ||
		authority.EntryCount != baseline.EntryCount ||
		authority.InventorySHA256 != baseline.InventorySHA256 {
		t.Fatalf("BaselineAuthority() = %#v", authority)
	}

	exact[len(exact)-1] ^= 1
	if err := os.WriteFile(baselinePath, exact, fsutil.StoreFilePerm); err != nil {
		t.Fatalf("WriteFile(mutated baseline) error = %v", err)
	}
	if _, err := ReadBaseline(paths, inventoryIdentity, kr); err == nil {
		t.Fatal("ReadBaseline() accepted mutated encrypted bytes")
	}
}

func TestBaselineStrictSchema(t *testing.T) {
	valid, err := NewBaseline(baselineGeneration, baselineInventory())
	if err != nil {
		t.Fatalf("NewBaseline() error = %v", err)
	}
	encoded, err := MarshalBaseline(valid)
	if err != nil {
		t.Fatalf("MarshalBaseline() error = %v", err)
	}
	if _, err := ParseBaseline(encoded); err != nil {
		t.Fatalf("ParseBaseline(valid) error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "wrong schema",
			mutate: func(wire map[string]any) {
				wire["schema"] = "aplane.rotation-baseline.v2"
			},
		},
		{
			name: "invalid generation",
			mutate: func(wire map[string]any) {
				wire["generation_id"] = "../escape"
			},
		},
		{
			name: "missing entry count",
			mutate: func(wire map[string]any) {
				delete(wire, "entry_count")
			},
		},
		{
			name: "null entry count",
			mutate: func(wire map[string]any) {
				wire["entry_count"] = nil
			},
		},
		{
			name: "negative entry count",
			mutate: func(wire map[string]any) {
				wire["entry_count"] = -1
			},
		},
		{
			name: "noncanonical digest",
			mutate: func(wire map[string]any) {
				wire["inventory_sha256"] = strings.Repeat("A", 64)
			},
		},
		{
			name: "unknown field",
			mutate: func(wire map[string]any) {
				wire["unknown"] = true
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var wire map[string]any
			if err := json.Unmarshal(encoded, &wire); err != nil {
				t.Fatalf("Unmarshal(valid) error = %v", err)
			}
			tt.mutate(wire)
			if _, err := ParseBaseline(marshalBaselineTest(t, wire)); err == nil {
				t.Fatal("ParseBaseline() accepted an invalid baseline")
			}
		})
	}
	if _, err := ParseBaseline(append(slices.Clone(encoded), []byte("{}")...)); err == nil {
		t.Fatal("ParseBaseline() accepted trailing JSON")
	}
	if _, err := ParseBaseline(bytes.Repeat([]byte{'x'}, int(MaxRotationBaselineBytes)+1)); err == nil ||
		!strings.Contains(err.Error(), "size limit") {
		t.Fatalf("ParseBaseline(oversized) error = %v, want size limit", err)
	}
}

func TestBaselineRejectsWrongContextTermAndOversizedFile(t *testing.T) {
	baseline, err := NewBaseline(baselineGeneration, baselineInventory())
	if err != nil {
		t.Fatalf("NewBaseline() error = %v", err)
	}
	plaintext, err := MarshalBaseline(baseline)
	if err != nil {
		t.Fatalf("MarshalBaseline() error = %v", err)
	}

	t.Run("wrong context", func(t *testing.T) {
		paths := baselineTestPaths(t)
		kr := cryptotest.KeyringAtTerm(t, 2, bytes.Repeat([]byte{0xa2}, 32))
		sealed, err := kr.Seal(plaintext, crypto.RotationSnapshotContext())
		if err != nil {
			t.Fatalf("Seal() error = %v", err)
		}
		if err := fsutil.WriteFileDurable(paths.RotationBaselinePath(inventoryIdentity), sealed); err != nil {
			t.Fatalf("WriteFileDurable() error = %v", err)
		}
		if _, err := ReadBaseline(paths, inventoryIdentity, kr); err == nil ||
			!strings.Contains(err.Error(), "open fixed context") {
			t.Fatalf("ReadBaseline() error = %v, want context rejection", err)
		}
	})

	t.Run("retired term", func(t *testing.T) {
		paths := baselineTestPaths(t)
		key1 := bytes.Repeat([]byte{0xa1}, 32)
		key2 := bytes.Repeat([]byte{0xa2}, 32)
		old := cryptotest.Keyring(t, key1)
		sealed, err := old.Seal(plaintext, crypto.RotationBaselineContext())
		if err != nil {
			t.Fatalf("Seal() error = %v", err)
		}
		if err := fsutil.WriteFileDurable(paths.RotationBaselinePath(inventoryIdentity), sealed); err != nil {
			t.Fatalf("WriteFileDurable() error = %v", err)
		}
		multi := cryptotest.KeyringWithTerms(t, 2, map[int64][]byte{1: key1, 2: key2})
		if _, err := ReadBaseline(paths, inventoryIdentity, multi); err == nil ||
			!strings.Contains(err.Error(), "does not match current term") {
			t.Fatalf("ReadBaseline() error = %v, want current-term rejection", err)
		}
	})

	t.Run("oversized encrypted file", func(t *testing.T) {
		paths := baselineTestPaths(t)
		if err := os.WriteFile(
			paths.RotationBaselinePath(inventoryIdentity),
			bytes.Repeat([]byte{'x'}, int(MaxRotationBaselineBytes)+1),
			fsutil.StoreFilePerm,
		); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		kr := cryptotest.KeyringAtTerm(t, 2, bytes.Repeat([]byte{0xa2}, 32))
		if _, err := ReadBaseline(paths, inventoryIdentity, kr); err == nil ||
			!strings.Contains(err.Error(), "size limit") {
			t.Fatalf("ReadBaseline() error = %v, want size limit", err)
		}
	})
}

func TestWriteBaselineReportsDurabilityFailure(t *testing.T) {
	paths := baselineTestPaths(t)
	kr := cryptotest.KeyringAtTerm(t, 2, bytes.Repeat([]byte{0xb2}, 32))
	baseline, err := NewBaseline(baselineGeneration, baselineInventory())
	if err != nil {
		t.Fatalf("NewBaseline() error = %v", err)
	}
	injected := errors.New("injected baseline rename failure")
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpRename && path == paths.RotationBaselinePath(inventoryIdentity) {
			return injected
		}
		return nil
	}
	t.Cleanup(func() { fsutil.TestHook = nil })
	if err := WriteBaseline(paths, inventoryIdentity, baseline, kr); !errors.Is(err, injected) {
		t.Fatalf("WriteBaseline() error = %v, want injected durability error", err)
	}
	if _, err := os.Stat(paths.RotationBaselinePath(inventoryIdentity)); !os.IsNotExist(err) {
		t.Fatalf("baseline exists after pre-rename failure: %v", err)
	}
}

func TestReconcileBaselineForPreflight(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		paths := baselineTestPaths(t)
		kr := cryptotest.KeyringAtTerm(t, 2, bytes.Repeat([]byte{0xc2}, 32))
		got, err := ReconcileBaselineForPreflight(
			paths,
			inventoryIdentity,
			baselineGeneration,
			kr,
		)
		if err != nil || got != nil {
			t.Fatalf("ReconcileBaselineForPreflight() = (%#v, %v), want (nil, nil)", got, err)
		}
	})

	t.Run("matching", func(t *testing.T) {
		paths := baselineTestPaths(t)
		kr := cryptotest.KeyringAtTerm(t, 2, bytes.Repeat([]byte{0xc2}, 32))
		baseline := writeBaselineTest(t, paths, baselineGeneration, kr)
		got, err := ReconcileBaselineForPreflight(
			paths,
			inventoryIdentity,
			baselineGeneration,
			kr,
		)
		if err != nil || got == nil || *got != *baseline {
			t.Fatalf("ReconcileBaselineForPreflight() = (%#v, %v), want %#v", got, err, baseline)
		}
		if _, err := os.Stat(paths.RotationBaselinePath(inventoryIdentity)); err != nil {
			t.Fatalf("matching baseline was removed: %v", err)
		}
	})

	t.Run("valid stale", func(t *testing.T) {
		paths := baselineTestPaths(t)
		kr := cryptotest.KeyringAtTerm(t, 2, bytes.Repeat([]byte{0xc2}, 32))
		writeBaselineTest(t, paths, baselinePrior, kr)
		var synced bool
		fsutil.TestHook = func(op fsutil.HookOp, path string) error {
			if op == fsutil.OpDirSync &&
				path == filepath.Dir(paths.RotationBaselinePath(inventoryIdentity)) {
				synced = true
			}
			return nil
		}
		t.Cleanup(func() { fsutil.TestHook = nil })
		got, err := ReconcileBaselineForPreflight(
			paths,
			inventoryIdentity,
			baselineGeneration,
			kr,
		)
		if err != nil || got != nil {
			t.Fatalf("ReconcileBaselineForPreflight() = (%#v, %v), want (nil, nil)", got, err)
		}
		if !synced {
			t.Fatal("stale baseline removal did not sync its directory")
		}
		if _, err := os.Stat(paths.RotationBaselinePath(inventoryIdentity)); !os.IsNotExist(err) {
			t.Fatalf("stale baseline still exists: %v", err)
		}
	})

	t.Run("malformed preserved", func(t *testing.T) {
		paths := baselineTestPaths(t)
		kr := cryptotest.KeyringAtTerm(t, 2, bytes.Repeat([]byte{0xc2}, 32))
		sealed, err := kr.Seal([]byte(`{"schema":"broken"}`), crypto.RotationBaselineContext())
		if err != nil {
			t.Fatalf("Seal() error = %v", err)
		}
		baselinePath := paths.RotationBaselinePath(inventoryIdentity)
		if err := fsutil.WriteFileDurable(baselinePath, sealed); err != nil {
			t.Fatalf("WriteFileDurable() error = %v", err)
		}
		if _, err := ReconcileBaselineForPreflight(
			paths,
			inventoryIdentity,
			baselineGeneration,
			kr,
		); err == nil {
			t.Fatal("ReconcileBaselineForPreflight() accepted malformed evidence")
		}
		if _, err := os.Stat(baselinePath); err != nil {
			t.Fatalf("malformed baseline evidence was removed: %v", err)
		}
	})

	t.Run("unauthorized term preserved", func(t *testing.T) {
		paths := baselineTestPaths(t)
		key1 := bytes.Repeat([]byte{0xc1}, 32)
		key2 := bytes.Repeat([]byte{0xc2}, 32)
		old := cryptotest.Keyring(t, key1)
		writeBaselineTest(t, paths, baselineGeneration, old)
		multi := cryptotest.KeyringWithTerms(t, 2, map[int64][]byte{1: key1, 2: key2})
		baselinePath := paths.RotationBaselinePath(inventoryIdentity)
		if _, err := ReconcileBaselineForPreflight(
			paths,
			inventoryIdentity,
			baselineGeneration,
			multi,
		); err == nil {
			t.Fatal("ReconcileBaselineForPreflight() accepted retired-term evidence")
		}
		if _, err := os.Stat(baselinePath); err != nil {
			t.Fatalf("unauthorized baseline evidence was removed: %v", err)
		}
	})
}

func TestEvaluateRollbackCutoverUsesEffectiveAuthority(t *testing.T) {
	atMint := baselineInventory()
	manifest := &genstore.Manifest{
		GenerationID: baselineGeneration,
		Inventory:    slices.Clone(atMint),
	}

	cutover, err := EvaluateRollbackCutover(
		baselineGeneration,
		slices.Clone(atMint),
		manifest,
		nil,
	)
	if err != nil {
		t.Fatalf("EvaluateRollbackCutover(manifest clean) error = %v", err)
	}
	if cutover.Decision != DecisionClean ||
		cutover.Authority.Source != AuthorityGenerationManifest {
		t.Fatalf("manifest cutover = %#v", cutover)
	}

	diverged := slices.Clone(atMint)
	diverged[0].Size++
	cutover, err = EvaluateRollbackCutover(
		baselineGeneration,
		diverged,
		manifest,
		nil,
	)
	if err != nil {
		t.Fatalf("EvaluateRollbackCutover(manifest diverged) error = %v", err)
	}
	if cutover.Decision != DecisionDiverged {
		t.Fatalf("manifest-diverged decision = %q, want %q", cutover.Decision, DecisionDiverged)
	}

	rewrapped := slices.Clone(atMint)
	rewrapped[0].SHA256 = strings.Repeat("3", 64)
	rewrapped[0].Term = 2
	baseline, err := NewBaseline(baselineGeneration, rewrapped)
	if err != nil {
		t.Fatalf("NewBaseline(rewrapped) error = %v", err)
	}
	cutover, err = EvaluateRollbackCutover(
		baselineGeneration,
		slices.Clone(rewrapped),
		manifest,
		baseline,
	)
	if err != nil {
		t.Fatalf("EvaluateRollbackCutover(baseline clean) error = %v", err)
	}
	if cutover.Decision != DecisionClean ||
		cutover.Authority.Source != AuthorityRotationBaseline {
		t.Fatalf("baseline cutover = %#v", cutover)
	}

	changedAfterBaseline := slices.Clone(rewrapped)
	changedAfterBaseline[0].Size++
	cutover, err = EvaluateRollbackCutover(
		baselineGeneration,
		changedAfterBaseline,
		manifest,
		baseline,
	)
	if err != nil {
		t.Fatalf("EvaluateRollbackCutover(baseline diverged) error = %v", err)
	}
	if cutover.Decision != DecisionDiverged {
		t.Fatalf("post-baseline divergence decision = %q, want %q", cutover.Decision, DecisionDiverged)
	}

	stale, err := NewBaseline(baselinePrior, rewrapped)
	if err != nil {
		t.Fatalf("NewBaseline(stale) error = %v", err)
	}
	if _, err := EvaluateRollbackCutover(
		baselineGeneration,
		rewrapped,
		manifest,
		stale,
	); err == nil {
		t.Fatal("EvaluateRollbackCutover() accepted another generation's baseline")
	}
}

func baselineInventory() []genstore.InventoryEntry {
	return []genstore.InventoryEntry{
		{
			Path:   "keys/ACCOUNT.key",
			SHA256: strings.Repeat("1", 64),
			Size:   100,
			Term:   1,
		},
		{
			Path:   "keytypes/example.v1.json",
			SHA256: strings.Repeat("2", 64),
			Size:   50,
		},
	}
}

func baselineTestPaths(t *testing.T) storepaths.Paths {
	t.Helper()
	paths := storepaths.NewPaths(t.TempDir())
	if err := fsutil.MkdirAll(paths.IdentityDir(inventoryIdentity)); err != nil {
		t.Fatalf("MkdirAll(identity) error = %v", err)
	}
	return paths
}

func writeBaselineTest(
	t *testing.T,
	paths storepaths.Paths,
	generationID string,
	kr *crypto.Keyring,
) *Baseline {
	t.Helper()
	baseline, err := NewBaseline(generationID, baselineInventory())
	if err != nil {
		t.Fatalf("NewBaseline() error = %v", err)
	}
	if err := WriteBaseline(paths, inventoryIdentity, baseline, kr); err != nil {
		t.Fatalf("WriteBaseline() error = %v", err)
	}
	return baseline
}

func marshalBaselineTest(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return data
}
