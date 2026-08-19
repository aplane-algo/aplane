// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package genstore

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
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const (
	testIdentity = "default"
	testGenA     = "gen-1753500000-0badc0de"
	testGenB     = "gen-1753500001-1badc0de"
)

func testKeyring(t *testing.T) *crypto.Keyring {
	t.Helper()
	return cryptotest.Keyring(t, bytes.Repeat([]byte{0x5a}, 32))
}

// mintTestGeneration lays down a structurally valid generation with a
// complete manifest and the given namespace files.
func mintTestGeneration(t *testing.T, paths storepaths.Paths, generationID string, files map[string]string) storepaths.GenPaths {
	t.Helper()
	gen := paths.GenerationPaths(generationID)
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

	if err := WriteCurrent(paths, testGenA); err != nil {
		t.Fatalf("WriteCurrent() error = %v", err)
	}
	gen, err := Resolve(paths)
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
	if err := os.MkdirAll(paths.ProductDir(), 0o770); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := WriteCurrent(paths, testGenA); err == nil {
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
			if err := os.MkdirAll(paths.ProductDir(), 0o770); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			if err := os.WriteFile(paths.CurrentPointerPath(), []byte(content), 0o660); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			if _, err := ReadCurrent(paths); err == nil {
				t.Fatalf("ReadCurrent accepted malformed pointer %q", content)
			}
		})
	}
}

func TestReadCurrentRejectsSymlinkPointer(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	mintTestGeneration(t, paths, testGenA, nil)
	target := filepath.Join(paths.ProductDir(), "pointer-target")
	if err := os.WriteFile(target, []byte(testGenA+"\n"), 0o660); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Symlink(target, paths.CurrentPointerPath()); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if _, err := ReadCurrent(paths); err == nil {
		t.Fatal("ReadCurrent followed a symlinked CURRENT pointer")
	}
}

func TestSealRoundTripAndTamperDetection(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	gen := mintTestGeneration(t, paths, testGenA, map[string]string{
		"keys/A.key":            "credential-a",
		"keytypes/ed25519.json": "{}",
	})

	if err := WriteSeal(gen, 1_753_500_100, testKeyring(t)); err != nil {
		t.Fatalf("WriteSeal() error = %v", err)
	}
	if err := ValidateSealed(gen, testKeyring(t)); err != nil {
		t.Fatalf("ValidateSealed(untampered) error = %v", err)
	}
	seal, err := ReadSeal(gen, testKeyring(t))
	if err != nil {
		t.Fatalf("ReadSeal() error = %v", err)
	}
	if seal.Schema != SealSchema || seal.SchemaVersion != sealSchemaVersion {
		t.Fatalf("seal schema = %s/%d, want %s/%d", seal.Schema, seal.SchemaVersion, SealSchema, sealSchemaVersion)
	}
	if seal.IntegrityTerm != 1 || len(seal.IntegrityMAC) != 64 || len(seal.ManifestSHA256) != 64 {
		t.Fatalf("seal integrity metadata = term %d, mac %q, manifest %q", seal.IntegrityTerm, seal.IntegrityMAC, seal.ManifestSHA256)
	}

	// Content change after sealing must be detected.
	if err := os.WriteFile(filepath.Join(gen.KeysDir(), "A.key"), []byte("tampered"), 0o660); err != nil {
		t.Fatalf("tamper write: %v", err)
	}
	if err := ValidateSealed(gen, testKeyring(t)); err == nil {
		t.Fatal("ValidateSealed accepted content that does not match the seal")
	}

	// So must a file the seal never recorded.
	if err := os.WriteFile(filepath.Join(gen.KeysDir(), "A.key"), []byte("credential-a"), 0o660); err != nil {
		t.Fatalf("restore write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gen.KeysDir(), "B.key"), []byte("new"), 0o660); err != nil {
		t.Fatalf("extra write: %v", err)
	}
	if err := ValidateSealed(gen, testKeyring(t)); err == nil {
		t.Fatal("ValidateSealed accepted an unsealed extra file")
	}
}

func TestGenerationInventoryAndSealAuthenticateMemberTerms(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	gen := mintTestGeneration(t, paths, testGenA, map[string]string{
		"keys/A.key":               "placeholder",
		"keytypes/example.v1.json": "{}",
		"keys/WITNESS.wit.json":    `{"schema":"public"}`,
	})
	kr := cryptotest.Keyring(t, bytes.Repeat([]byte{0x41}, 32))
	sealed, err := kr.Seal([]byte("credential"), crypto.AccountKeyContext("A"))
	if err != nil {
		t.Fatalf("Seal(credential) error = %v", err)
	}
	if err := fsutil.WriteFileDurable(filepath.Join(gen.KeysDir(), "A.key"), sealed); err != nil {
		t.Fatalf("WriteFileDurable(A.key) error = %v", err)
	}
	inventory, err := BuildInventory(gen)
	if err != nil {
		t.Fatalf("BuildInventory() error = %v", err)
	}
	for _, path := range []string{"keytypes/example.v1.json", "keys/WITNESS.wit.json"} {
		entry := inventoryEntry(t, inventory, path)
		if entry.Term != 0 {
			t.Fatalf("plaintext inventory entry %s term = %d, want 0", path, entry.Term)
		}
	}
	if entry := inventoryEntry(t, inventory, "keys/A.key"); entry.Term != 1 {
		t.Fatalf("term-envelope inventory entry term = %d, want 1", entry.Term)
	}

	if err := WriteSeal(gen, 1_753_500_100, kr); err != nil {
		t.Fatalf("WriteSeal() error = %v", err)
	}
	seal, err := ReadSeal(gen, kr)
	if err != nil {
		t.Fatalf("ReadSeal() error = %v", err)
	}
	index := slices.IndexFunc(seal.Inventory, func(entry InventoryEntry) bool {
		return entry.Path == "keys/A.key"
	})
	if index < 0 {
		t.Fatal("seal inventory is missing keys/A.key")
	}
	seal.Inventory[index].Term = 0
	if err := writeJSONDurable(gen.SealPath(), seal); err != nil {
		t.Fatalf("writeJSONDurable(mutated seal) error = %v", err)
	}
	if _, err := ReadSeal(gen, kr); err == nil ||
		!strings.Contains(err.Error(), "integrity verification failed") {
		t.Fatalf("ReadSeal(term-mutated) error = %v, want MAC rejection", err)
	}
}

func TestUnanchoredSealRejectsRetiredMemberTerm(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	gen := mintTestGeneration(t, paths, testGenA, map[string]string{
		"keys/A.key": "placeholder",
	})
	key1 := bytes.Repeat([]byte{0x51}, 32)
	key2 := bytes.Repeat([]byte{0x52}, 32)
	old := cryptotest.Keyring(t, key1)
	sealed, err := old.Seal([]byte("credential"), crypto.AccountKeyContext("A"))
	if err != nil {
		t.Fatalf("Seal(old term) error = %v", err)
	}
	if err := fsutil.WriteFileDurable(filepath.Join(gen.KeysDir(), "A.key"), sealed); err != nil {
		t.Fatalf("WriteFileDurable(A.key) error = %v", err)
	}
	current := cryptotest.KeyringAtTerm(t, 2, key2)
	if err := WriteSeal(gen, 1_753_500_100, current); err != nil {
		t.Fatalf("WriteSeal(current term) error = %v", err)
	}
	if _, err := ReadSeal(gen, current); err == nil ||
		!strings.Contains(err.Error(), "unanchored generation seal entry") {
		t.Fatalf("ReadSeal(mixed unanchored) error = %v, want retired-member rejection", err)
	}
	if _, err := BuildHistoricalAnchor(gen, current); err == nil {
		t.Fatal("BuildHistoricalAnchor() anchored a generation after a member term retired")
	}
}

func TestAnchoredHistoricalSealAndExactMemberOpen(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	gen := mintTestGeneration(t, paths, testGenA, map[string]string{
		"keys/A.key": "placeholder",
	})
	key1 := bytes.Repeat([]byte{0x61}, 32)
	key2 := bytes.Repeat([]byte{0x62}, 32)
	old := cryptotest.Keyring(t, key1)
	sealed, err := old.Seal([]byte("historical credential"), crypto.AccountKeyContext("A"))
	if err != nil {
		t.Fatalf("Seal(old term) error = %v", err)
	}
	if err := fsutil.WriteFileDurable(filepath.Join(gen.KeysDir(), "A.key"), sealed); err != nil {
		t.Fatalf("WriteFileDurable(A.key) error = %v", err)
	}
	if err := WriteSeal(gen, 1_753_500_100, old); err != nil {
		t.Fatalf("WriteSeal(old term) error = %v", err)
	}
	sealBytes, err := os.ReadFile(gen.SealPath())
	if err != nil {
		t.Fatalf("ReadFile(seal) error = %v", err)
	}
	anchor, err := BuildHistoricalAnchor(gen, old)
	if err != nil {
		t.Fatalf("BuildHistoricalAnchor() error = %v", err)
	}
	multi := cryptotest.KeyringWithTerms(t, 2, map[int64][]byte{1: key1, 2: key2})

	if _, err := ReadSeal(gen, multi); err == nil {
		t.Fatal("ReadSeal() authorized a retired-term seal without an anchor")
	}
	currentOnly := cryptotest.KeyringAtTerm(t, 2, key2)
	if err := ValidateAnchoredSealed(gen, anchor, currentOnly); err == nil ||
		!strings.Contains(err.Error(), "no key for term 1") {
		t.Fatalf("ValidateAnchoredSealed(missing retired term) error = %v", err)
	}
	if err := ValidateAnchoredSealed(gen, anchor, multi); err != nil {
		t.Fatalf("ValidateAnchoredSealed() error = %v", err)
	}
	plaintext, err := OpenAnchoredEnvelope(
		gen,
		anchor,
		"keys/A.key",
		crypto.AccountKeyContext("A"),
		multi,
	)
	if err != nil {
		t.Fatalf("OpenAnchoredEnvelope() error = %v", err)
	}
	defer crypto.ZeroBytes(plaintext)
	if string(plaintext) != "historical credential" {
		t.Fatalf("OpenAnchoredEnvelope() = %q", plaintext)
	}
	manifestBytes, err := os.ReadFile(gen.ManifestPath())
	if err != nil {
		t.Fatalf("ReadFile(manifest) error = %v", err)
	}
	bufferPlaintext, err := OpenAnchoredEnvelopeBytes(
		gen,
		anchor,
		sealBytes,
		manifestBytes,
		"keys/A.key",
		sealed,
		crypto.AccountKeyContext("A"),
		multi,
	)
	if err != nil {
		t.Fatalf("OpenAnchoredEnvelopeBytes() error = %v", err)
	}
	if string(bufferPlaintext) != "historical credential" {
		t.Fatalf("OpenAnchoredEnvelopeBytes() = %q", bufferPlaintext)
	}
	crypto.ZeroBytes(bufferPlaintext)
	if _, err := OpenAnchoredEnvelope(
		gen,
		anchor,
		"keys/A.key",
		crypto.SentryCredentialContext("A"),
		multi,
	); err == nil {
		t.Fatal("OpenAnchoredEnvelope() accepted the wrong logical context")
	}

	wrongAnchor := anchor
	wrongAnchor.SealSHA256 = strings.Repeat("a", 64)
	if err := ValidateAnchoredSealed(gen, wrongAnchor, multi); err == nil {
		t.Fatal("ValidateAnchoredSealed() accepted a mismatched root anchor")
	}

	var forged Seal
	if err := json.Unmarshal(sealBytes, &forged); err != nil {
		t.Fatalf("Unmarshal(seal) error = %v", err)
	}
	forged.SealedAtUnix++
	if err := writeJSONDurable(gen.SealPath(), forged); err != nil {
		t.Fatalf("writeJSONDurable(forged seal) error = %v", err)
	}
	forgedBytes, err := os.ReadFile(gen.SealPath())
	if err != nil {
		t.Fatalf("ReadFile(forged seal) error = %v", err)
	}
	forgedAnchor, err := crypto.NewHistoricalGenerationAnchor(gen.GenerationID(), forgedBytes)
	if err != nil {
		t.Fatalf("NewHistoricalGenerationAnchor(forged) error = %v", err)
	}
	if err := ValidateAnchoredSealed(gen, forgedAnchor, multi); err == nil ||
		!strings.Contains(err.Error(), "integrity verification failed") {
		t.Fatalf("ValidateAnchoredSealed(forged MAC) error = %v, want MAC rejection", err)
	}
	if err := fsutil.WriteFileDurable(gen.SealPath(), sealBytes); err != nil {
		t.Fatalf("WriteFileDurable(restore seal) error = %v", err)
	}

	mutated := slices.Clone(sealed)
	mutated[len(mutated)-1] ^= 1
	if err := os.WriteFile(filepath.Join(gen.KeysDir(), "A.key"), mutated, 0o660); err != nil {
		t.Fatalf("WriteFile(mutated member) error = %v", err)
	}
	if _, _, err := ReadAnchoredBytes(gen, anchor, "keys/A.key", multi); err == nil {
		t.Fatal("ReadAnchoredBytes() accepted member bytes not pinned by the anchored seal")
	}
}

func TestCanonicalInventoryDigestIsStableAndDomainSeparated(t *testing.T) {
	inventory := []InventoryEntry{
		{Path: "keys/A.key", SHA256: strings.Repeat("1", 64), Size: 10},
		{Path: "keytypes/example.v1.json", SHA256: strings.Repeat("2", 64), Size: 20},
	}
	first, err := CanonicalInventoryDigest(inventory)
	if err != nil {
		t.Fatalf("CanonicalInventoryDigest() error = %v", err)
	}
	second, err := CanonicalInventoryDigest(slices.Clone(inventory))
	if err != nil {
		t.Fatalf("CanonicalInventoryDigest(copy) error = %v", err)
	}
	if first != second || len(first) != 64 {
		t.Fatalf("canonical digest = %q then %q", first, second)
	}
	mutated := slices.Clone(inventory)
	mutated[0].Size++
	changed, err := CanonicalInventoryDigest(mutated)
	if err != nil {
		t.Fatalf("CanonicalInventoryDigest(mutated) error = %v", err)
	}
	if changed == first {
		t.Fatal("canonical digest did not bind entry size")
	}
	mutated = slices.Clone(inventory)
	mutated[0].Term = 1
	changed, err = CanonicalInventoryDigest(mutated)
	if err != nil {
		t.Fatalf("CanonicalInventoryDigest(term-mutated) error = %v", err)
	}
	if changed == first {
		t.Fatal("canonical digest did not bind entry term")
	}
	reordered := slices.Clone(inventory)
	reordered[0], reordered[1] = reordered[1], reordered[0]
	if _, err := CanonicalInventoryDigest(reordered); err == nil {
		t.Fatal("CanonicalInventoryDigest() accepted non-canonical ordering")
	}
}

func inventoryEntry(t *testing.T, inventory []InventoryEntry, path string) InventoryEntry {
	t.Helper()
	index := slices.IndexFunc(inventory, func(entry InventoryEntry) bool {
		return entry.Path == path
	})
	if index < 0 {
		t.Fatalf("inventory entry %q not found", path)
	}
	return inventory[index]
}

func TestSealAuthenticatesExactManifestBytes(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	gen := mintTestGeneration(t, paths, testGenA, map[string]string{"keys/A.key": "a"})
	if err := WriteSeal(gen, 1_753_500_100, testKeyring(t)); err != nil {
		t.Fatalf("WriteSeal() error = %v", err)
	}
	manifestBytes, err := os.ReadFile(gen.ManifestPath())
	if err != nil {
		t.Fatalf("ReadFile(manifest) error = %v", err)
	}
	// Appending JSON whitespace preserves the parsed manifest but changes
	// the exact immutable bytes pinned by manifest_sha256.
	if err := os.WriteFile(gen.ManifestPath(), append(manifestBytes, '\n'), 0o660); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}
	if _, err := ReadSeal(gen, testKeyring(t)); err == nil || !strings.Contains(err.Error(), "manifest digest mismatch") {
		t.Fatalf("ReadSeal() error = %v, want exact manifest digest mismatch", err)
	}
}

func TestSealRejectsForgedSecurityFieldsAndWrongAuthority(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	gen := mintTestGeneration(t, paths, testGenA, map[string]string{"keys/A.key": "a"})
	kr := testKeyring(t)
	if err := WriteSeal(gen, 1_753_500_100, kr); err != nil {
		t.Fatalf("WriteSeal() error = %v", err)
	}
	if _, err := ReadSeal(gen, cryptotest.Keyring(t, bytes.Repeat([]byte{0x6b}, 32))); err == nil {
		t.Fatal("ReadSeal() accepted a different integrity authority")
	}

	seal, err := ReadSeal(gen, kr)
	if err != nil {
		t.Fatalf("ReadSeal() error = %v", err)
	}
	seal.SealedAtUnix++
	if err := writeJSONDurable(gen.SealPath(), seal); err != nil {
		t.Fatalf("writeJSONDurable(forged seal) error = %v", err)
	}
	if _, err := ReadSeal(gen, kr); err == nil || !strings.Contains(err.Error(), "integrity verification failed") {
		t.Fatalf("ReadSeal() error = %v, want integrity verification failure", err)
	}
}

func TestSealParsingIsStrict(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	gen := mintTestGeneration(t, paths, testGenA, map[string]string{"keys/A.key": "a"})
	if err := WriteSeal(gen, 1_753_500_100, testKeyring(t)); err != nil {
		t.Fatalf("WriteSeal() error = %v", err)
	}
	sealBytes, err := os.ReadFile(gen.SealPath())
	if err != nil {
		t.Fatalf("ReadFile(seal) error = %v", err)
	}
	if err := os.WriteFile(gen.SealPath(), append(sealBytes, []byte("{}\n")...), 0o660); err != nil {
		t.Fatalf("WriteFile(seal) error = %v", err)
	}
	if _, err := ReadSeal(gen, testKeyring(t)); err == nil || !strings.Contains(err.Error(), "trailing data") {
		t.Fatalf("ReadSeal() error = %v, want strict trailing-data rejection", err)
	}
}

func TestWriteSealRejectsInvalidMetadata(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	gen := mintTestGeneration(t, paths, testGenA, map[string]string{"keys/A.key": "a"})
	if err := WriteSeal(gen, 0, testKeyring(t)); err == nil {
		t.Fatal("WriteSeal() accepted a non-positive sealed_at")
	}
}

func TestUnsealedGenerationFailsSealedValidation(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	gen := mintTestGeneration(t, paths, testGenA, map[string]string{"keys/A.key": "a"})
	if err := ValidateSealed(gen, testKeyring(t)); err == nil {
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
	if err := WriteSeal(gen, 1_753_500_100, testKeyring(t)); err != nil {
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
	gen := paths.GenerationPaths(testGenA)
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
	if err := os.MkdirAll(paths.ProductDir(), 0o770); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	generational, err := IsGenerational(paths)
	if err != nil || generational {
		t.Fatalf("IsGenerational(legacy) = (%v, %v), want (false, nil)", generational, err)
	}
	mintTestGeneration(t, paths, testGenA, nil)
	if err := WriteCurrent(paths, testGenA); err != nil {
		t.Fatalf("WriteCurrent() error = %v", err)
	}
	generational, err = IsGenerational(paths)
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
	if _, err := ResolveActive(paths); err == nil {
		t.Fatal("ResolveActive resolved a store with no CURRENT pointer")
	}

	gen := mintTestGeneration(t, paths, testGenA, nil)
	if err := WriteCurrent(paths, testGenA); err != nil {
		t.Fatalf("WriteCurrent: %v", err)
	}
	active, err := ResolveActive(paths)
	if err != nil {
		t.Fatalf("ResolveActive() error = %v", err)
	}
	if active.KeysDir() != gen.KeysDir() {
		t.Fatalf("KeysDir = %s, want %s", active.KeysDir(), gen.KeysDir())
	}

	// A present-but-invalid CURRENT is an error.
	if err := os.WriteFile(paths.CurrentPointerPath(), []byte("garbage"+"\n"), 0o660); err != nil {
		t.Fatalf("corrupt CURRENT: %v", err)
	}
	if _, err := ResolveActive(paths); err == nil {
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
	target := filepath.Join(paths.ProductDir(), "pointer-target")
	if err := os.WriteFile(target, []byte("x\n"), 0o660); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Symlink(target, paths.CurrentPointerPath()); err != nil {
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

	err := WriteCurrent(paths, testGenA)
	if !errors.Is(err, ErrCommitDurabilityUnknown) {
		t.Fatalf("WriteCurrent error = %v, want ErrCommitDurabilityUnknown (unreadable pointer proves nothing)", err)
	}
}
