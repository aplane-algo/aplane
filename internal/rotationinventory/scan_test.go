// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rotationinventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/backup/recovered"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const (
	inventoryIdentity = "default"
	inventoryGenA     = "gen-1785200000-0badc0de"
	inventoryGenB     = "gen-1785200001-1badc0de"
)

type inventoryFixture struct {
	paths storepaths.Paths
	kr    *crypto.Keyring
}

func TestScanClassifiesEveryK8DurableClass(t *testing.T) {
	fixture := newInventoryFixture(t)
	report, err := Scan(fixture.paths, inventoryIdentity, fixture.kr)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if report.CurrentGeneration != inventoryGenB {
		t.Fatalf("CurrentGeneration = %q, want %q", report.CurrentGeneration, inventoryGenB)
	}
	if !slices.IsSortedFunc(report.Entries, func(a, b Entry) int {
		return strings.Compare(a.Path, b.Path)
	}) {
		t.Fatal("inventory entries are not sorted")
	}

	wantKinds := []ArtifactKind{
		KindAccountKey,
		KindSentryCredential,
		KindKeyTypeTemplate,
		KindRecoveredBatch,
		KindRecoveredEntry,
		KindPolicyDocument,
		KindPolicySidecar,
		KindNodeRoleDocument,
		KindNodeRoleSidecar,
		KindKeyTypeState,
		KindWitnessPublicMetadata,
		KindGenerationManifest,
		KindGenerationSeal,
		KindRotationSnapshot,
		KindRotationBaseline,
	}
	seenKinds := make(map[ArtifactKind]bool)
	for _, entry := range report.Entries {
		seenKinds[entry.Kind] = true
		if strings.HasPrefix(entry.Path, "/") || strings.Contains(entry.Path, "\\") {
			t.Fatalf("non-canonical inventory path %q", entry.Path)
		}
		termEnvelope := entry.ObjectClass != ""
		if (termEnvelope || entry.Kind == KindPolicySidecar || entry.Kind == KindNodeRoleSidecar) && entry.Term != 1 {
			t.Fatalf("term-bearing entry %+v has term %d, want 1", entry, entry.Term)
		}
	}
	for _, kind := range wantKinds {
		if !seenKinds[kind] {
			t.Errorf("inventory is missing durable artifact kind %q", kind)
		}
	}
	for _, excluded := range []string{
		"config.yaml",
		"cache/network.json",
		"library/templates/source.yaml",
		"backups/default/archive.tar.gz",
		"identities/default/keyring.enc",
		"identities/default/.keystore",
		"identities/default/config.yaml",
		"identities/default/aplane.token",
	} {
		if slices.ContainsFunc(report.Entries, func(entry Entry) bool {
			return entry.Path == excluded
		}) {
			t.Errorf("independent artifact %q was included in the rotation inventory", excluded)
		}
	}

	account := findEntry(t, report, "identities/default/generations/"+inventoryGenB+"/keys/ACCOUNT.key")
	if account.Kind != KindAccountKey ||
		account.ObjectClass != crypto.ClassAccountKey ||
		account.ObjectSelector != "ACCOUNT" {
		t.Fatalf("account entry = %+v", account)
	}
	accountBytes, err := os.ReadFile(filepath.Join(fixture.paths.Root(), filepath.FromSlash(account.Path)))
	if err != nil {
		t.Fatalf("ReadFile(account) error = %v", err)
	}
	sum := sha256.Sum256(accountBytes)
	if account.Size != int64(len(accountBytes)) || account.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("account exact-byte pin = size %d digest %s", account.Size, account.SHA256)
	}

	// Generation copy, deleted archive moves, and recovered staging publication
	// preserve logical context because no physical path component enters AAD.
	for _, path := range []string{
		"identities/default/generations/" + inventoryGenA + "/keys/ACCOUNT.key",
		"identities/default/generations/" + inventoryGenB + "/keys/ACCOUNT.key",
		"identities/default/deleted/keys/ARCHIVED.key",
	} {
		entry := findEntry(t, report, path)
		if entry.ObjectClass != crypto.ClassAccountKey {
			t.Fatalf("%s context = %s:%s", path, entry.ObjectClass, entry.ObjectSelector)
		}
	}
}

func TestScanRetainsCurrentDecisionInputsFromExactScannedBytes(t *testing.T) {
	fixture := newInventoryFixture(t)
	report, err := Scan(fixture.paths, inventoryIdentity, fixture.kr)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if report.currentManifest == nil {
		t.Fatal("Scan() did not retain the parsed current manifest")
	}
	accountPath := filepath.Join(
		fixture.paths.GenerationPaths(inventoryIdentity, inventoryGenB).KeysDir(),
		"ACCOUNT.key",
	)
	account := findEntry(
		t,
		report,
		"identities/default/generations/"+inventoryGenB+"/keys/ACCOUNT.key",
	)
	pinned := slices.IndexFunc(report.currentInventory, func(entry genstore.InventoryEntry) bool {
		return entry.Path == "keys/ACCOUNT.key"
	})
	if pinned < 0 {
		t.Fatal("Scan() did not retain the current account inventory entry")
	}
	if got := report.currentInventory[pinned]; got.SHA256 != account.SHA256 ||
		got.Size != account.Size ||
		got.Term != account.Term {
		t.Fatalf("current decision input = %#v, want exact scanned entry %#v", got, account)
	}

	manifestOperation := report.currentManifest.Operation
	if err := os.WriteFile(accountPath, []byte("substituted after scan"), fsutil.StoreFilePerm); err != nil {
		t.Fatalf("substitute account after scan: %v", err)
	}
	manifestPath := fixture.paths.GenerationPaths(
		inventoryIdentity,
		inventoryGenB,
	).ManifestPath()
	if err := os.WriteFile(manifestPath, []byte("{\"substituted\":true}"), fsutil.StoreFilePerm); err != nil {
		t.Fatalf("substitute manifest after scan: %v", err)
	}
	if report.currentInventory[pinned].SHA256 != account.SHA256 {
		t.Fatal("post-scan file substitution changed the pinned current inventory")
	}
	if report.currentManifest.Operation != manifestOperation {
		t.Fatal("post-scan manifest substitution changed the pinned parsed manifest")
	}
}

func TestScanRejectsWrongEnvelopeContext(t *testing.T) {
	tests := []struct {
		name        string
		source      string
		destination string
	}{
		{
			name:        "selector",
			source:      "ACCOUNT.key",
			destination: "OTHER.key",
		},
		{
			name:        "class",
			source:      "ACCOUNT.key",
			destination: "WITNESS.sen",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newInventoryFixture(t)
			gen := fixture.paths.GenerationPaths(inventoryIdentity, inventoryGenB)
			data, err := os.ReadFile(filepath.Join(gen.KeysDir(), tt.source))
			if err != nil {
				t.Fatalf("ReadFile(source) error = %v", err)
			}
			if err := os.WriteFile(filepath.Join(gen.KeysDir(), tt.destination), data, fsutil.StoreFilePerm); err != nil {
				t.Fatalf("WriteFile(destination) error = %v", err)
			}
			if _, err := Scan(fixture.paths, inventoryIdentity, fixture.kr); err == nil {
				t.Fatal("Scan() error = nil, want logical-context rejection")
			}
		})
	}
}

func TestScanRejectsUnauthorizedIntegrityTerm(t *testing.T) {
	fixture := newInventoryFixture(t)
	path := policy.PolicyIntegritySidecarPath(policy.PolicyPath(fixture.paths.Root(), inventoryIdentity))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(sidecar) error = %v", err)
	}
	sidecar, err := policy.ParsePolicyIntegritySidecar(data)
	if err != nil {
		t.Fatalf("ParsePolicyIntegritySidecar() error = %v", err)
	}
	sidecar.IntegrityTerm++
	data, err = policy.MarshalPolicyIntegritySidecar(sidecar)
	if err != nil {
		t.Fatalf("MarshalPolicyIntegritySidecar() error = %v", err)
	}
	if err := os.WriteFile(path, data, fsutil.StoreFilePerm); err != nil {
		t.Fatalf("WriteFile(sidecar) error = %v", err)
	}
	if _, err := Scan(fixture.paths, inventoryIdentity, fixture.kr); err == nil {
		t.Fatal("Scan() error = nil, want unauthorized integrity-term rejection")
	}
}

func TestScanRejectsMutatedPlaintextRetainedGenerationMember(t *testing.T) {
	fixture := newInventoryFixture(t)
	path := fixture.paths.GenerationPaths(inventoryIdentity, inventoryGenA).KeyTypeRecord("example.type.v1")
	if err := os.WriteFile(path, []byte("{\"mutated\":true}\n"), fsutil.StoreFilePerm); err != nil {
		t.Fatalf("WriteFile(mutated state) error = %v", err)
	}
	if _, err := Scan(fixture.paths, inventoryIdentity, fixture.kr); err == nil {
		t.Fatal("Scan() error = nil, want authenticated-seal rejection")
	}
}

func TestScanRejectsUnsupportedInScopeArtifact(t *testing.T) {
	fixture := newInventoryFixture(t)
	path := filepath.Join(
		fixture.paths.GenerationPaths(inventoryIdentity, inventoryGenB).KeysDir(),
		"unclassified.bin",
	)
	if err := os.WriteFile(path, []byte("unclassified"), fsutil.StoreFilePerm); err != nil {
		t.Fatalf("WriteFile(unclassified) error = %v", err)
	}
	if _, err := Scan(fixture.paths, inventoryIdentity, fixture.kr); err == nil {
		t.Fatal("Scan() error = nil, want unclassified-artifact rejection")
	}
}

func TestScanRejectsTermEnvelopeSubstitutedForPlaintextMember(t *testing.T) {
	fixture := newInventoryFixture(t)
	gen := fixture.paths.GenerationPaths(inventoryIdentity, inventoryGenB)
	envelope, err := os.ReadFile(filepath.Join(gen.KeysDir(), "ACCOUNT.key"))
	if err != nil {
		t.Fatalf("ReadFile(account envelope) error = %v", err)
	}
	path := gen.KeyTypeRecord("example.type.v1")
	if err := os.WriteFile(path, envelope, fsutil.StoreFilePerm); err != nil {
		t.Fatalf("WriteFile(substituted plaintext member) error = %v", err)
	}
	if _, err := Scan(fixture.paths, inventoryIdentity, fixture.kr); err == nil ||
		!strings.Contains(err.Error(), "unexpectedly carries term envelope") {
		t.Fatalf("Scan() error = %v, want plaintext/envelope classification rejection", err)
	}
}

func TestScanRejectsMalformedRotationBaseline(t *testing.T) {
	fixture := newInventoryFixture(t)
	if err := writeEnvelope(
		fixture.paths.RotationBaselinePath(inventoryIdentity),
		[]byte(`{"schema":"broken"}`),
		crypto.RotationBaselineContext(),
		fixture.kr,
	); err != nil {
		t.Fatalf("write malformed rotation baseline: %v", err)
	}
	if _, err := Scan(fixture.paths, inventoryIdentity, fixture.kr); err == nil ||
		!strings.Contains(err.Error(), "rotation inventory baseline") {
		t.Fatalf("Scan() error = %v, want malformed-baseline rejection", err)
	}
}

func TestScanRejectsOversizedRotationBaseline(t *testing.T) {
	fixture := newInventoryFixture(t)
	if err := os.WriteFile(
		fixture.paths.RotationBaselinePath(inventoryIdentity),
		bytes.Repeat([]byte{'x'}, int(MaxRotationBaselineBytes)+1),
		fsutil.StoreFilePerm,
	); err != nil {
		t.Fatalf("write oversized rotation baseline: %v", err)
	}
	if _, err := Scan(fixture.paths, inventoryIdentity, fixture.kr); err == nil ||
		!strings.Contains(err.Error(), "size limit") {
		t.Fatalf("Scan() error = %v, want baseline size-limit rejection", err)
	}
}

func TestScanForSnapshotExcludesSnapshotButPinsExistingBaseline(t *testing.T) {
	fixture := newInventoryFixture(t)
	report, err := ScanForSnapshot(fixture.paths, inventoryIdentity, fixture.kr)
	if err != nil {
		t.Fatalf("ScanForSnapshot() error = %v", err)
	}
	if slices.ContainsFunc(report.Entries, func(entry Entry) bool {
		return entry.Kind == KindRotationSnapshot
	}) {
		t.Fatal("ScanForSnapshot() recursively included rotation.snapshot.enc")
	}
	if !slices.ContainsFunc(report.Entries, func(entry Entry) bool {
		return entry.Kind == KindRotationBaseline
	}) {
		t.Fatal("ScanForSnapshot() omitted the pre-existing rotation baseline input")
	}
}

func newInventoryFixture(t *testing.T) inventoryFixture {
	t.Helper()
	paths := storepaths.NewPaths(t.TempDir())
	kr := cryptotest.Keyring(t, bytes.Repeat([]byte{0x71}, 32))

	nodeBytes, _, err := noderole.SaveInitial(paths, noderole.RoleSigner, time.Unix(1_785_200_000, 0))
	if err != nil {
		t.Fatalf("SaveInitial(node role) error = %v", err)
	}
	if err := noderole.SaveIdentitySidecarWithKeyring(paths, inventoryIdentity, nodeBytes, kr, time.Unix(1_785_200_000, 0)); err != nil {
		t.Fatalf("SaveIdentitySidecarWithKeyring() error = %v", err)
	}
	if err := policy.SaveStoredConfigWithKeyring(
		paths.Root(),
		inventoryIdentity,
		&policy.StoredConfig{},
		kr,
		time.Unix(1_785_200_000, 0),
	); err != nil {
		t.Fatalf("SaveStoredConfigWithKeyring() error = %v", err)
	}

	if _, err := genstore.Mint(paths, inventoryIdentity, genstore.MintRequest{
		GenerationID:    inventoryGenA,
		FirstGeneration: true,
		Operation:       "inventory-fixture",
		OperationID:     "inventory-fixture-a",
		CreatedAt:       time.Unix(1_785_200_000, 0),
		Apply: func(staged storepaths.GenPaths) error {
			artifacts := []struct {
				path      string
				plaintext string
				ctx       crypto.ObjectContext
			}{
				{filepath.Join(staged.KeysDir(), "ACCOUNT.key"), "account", crypto.AccountKeyContext("ACCOUNT")},
				{filepath.Join(staged.KeysDir(), "WITNESS.sen"), "sentry", crypto.SentryCredentialContext("WITNESS")},
				{staged.KeyTypeTemplate("example.type.v1"), "template", crypto.KeyTypeTemplateContext("example.type.v1")},
			}
			for _, artifact := range artifacts {
				if err := writeEnvelope(artifact.path, []byte(artifact.plaintext), artifact.ctx, kr); err != nil {
					return err
				}
			}
			if err := fsutil.WriteFileDurable(
				filepath.Join(staged.KeysDir(), "WITNESS"+keys.WitnessPublicMetadataSuffix),
				[]byte("{\"public\":true}\n"),
			); err != nil {
				return err
			}
			return fsutil.WriteFileDurable(
				staged.KeyTypeRecord("example.type.v1"),
				[]byte("{\"key_type\":\"example.type.v1\"}\n"),
			)
		},
	}); err != nil {
		t.Fatalf("Mint(first) error = %v", err)
	}
	if _, err := genstore.Mint(paths, inventoryIdentity, genstore.MintRequest{
		GenerationID: inventoryGenB,
		Parent:       inventoryGenA,
		Operation:    "inventory-fixture",
		OperationID:  "inventory-fixture-b",
		CreatedAt:    time.Unix(1_785_200_001, 0),
		Integrity:    kr,
	}); err != nil {
		t.Fatalf("Mint(second) error = %v", err)
	}

	if err := fsutil.MkdirAll(paths.DeletedKeysDir(inventoryIdentity)); err != nil {
		t.Fatalf("MkdirAll(deleted keys) error = %v", err)
	}
	if err := fsutil.MkdirAll(filepath.Dir(paths.DeletedKeyTypeTemplate(inventoryIdentity, "archived.type.v1"))); err != nil {
		t.Fatalf("MkdirAll(deleted keytypes) error = %v", err)
	}
	for _, artifact := range []struct {
		path      string
		plaintext string
		ctx       crypto.ObjectContext
	}{
		{filepath.Join(paths.DeletedKeysDir(inventoryIdentity), "ARCHIVED.key"), "archived account", crypto.AccountKeyContext("ARCHIVED")},
		{filepath.Join(paths.DeletedKeysDir(inventoryIdentity), "ARCHWIT.sen"), "archived sentry", crypto.SentryCredentialContext("ARCHWIT")},
		{paths.DeletedKeyTypeTemplate(inventoryIdentity, "archived.type.v1"), "archived template", crypto.KeyTypeTemplateContext("archived.type.v1")},
	} {
		if err := writeEnvelope(artifact.path, []byte(artifact.plaintext), artifact.ctx, kr); err != nil {
			t.Fatalf("writeEnvelope(%s) error = %v", artifact.path, err)
		}
	}

	address, keyJSON := keystest.Ed25519KeyJSON(t)
	defer crypto.ZeroBytes(keyJSON)
	archiveSum := sha256.Sum256([]byte("archive"))
	if _, err := recovered.Create(paths, inventoryIdentity, recovered.CreateRequest{
		ArchiveName:        "archive.tar.gz",
		ArchiveSHA256:      hex.EncodeToString(archiveSum[:]),
		SourceNodeRole:     string(noderole.RoleSigner),
		SourcePolicyStatus: recovered.SourcePolicyMissing,
		CreatedAt:          time.Unix(1_785_200_002, 0),
		Entries: []recovered.Entry{{
			Selector: address,
			Category: keys.CategoryEd25519,
			KeyType:  "ed25519",
			KeyJSON:  keyJSON,
		}},
	}, kr); err != nil {
		t.Fatalf("recovered.Create() error = %v", err)
	}

	if err := writeEnvelope(
		paths.RotationSnapshotPath(inventoryIdentity),
		[]byte("snapshot"),
		crypto.RotationSnapshotContext(),
		kr,
	); err != nil {
		t.Fatalf("write rotation snapshot: %v", err)
	}
	currentInventory, err := genstore.BuildInventory(
		paths.GenerationPaths(inventoryIdentity, inventoryGenB),
	)
	if err != nil {
		t.Fatalf("BuildInventory(current) error = %v", err)
	}
	baseline, err := NewBaseline(inventoryGenB, currentInventory)
	if err != nil {
		t.Fatalf("NewBaseline() error = %v", err)
	}
	if err := WriteBaseline(paths, inventoryIdentity, baseline, kr); err != nil {
		t.Fatalf("WriteBaseline() error = %v", err)
	}
	for relative, data := range map[string]string{
		"config.yaml":                             "root config\n",
		"cache/network.json":                      "{}\n",
		"library/templates/source.yaml":           "source: true\n",
		"backups/default/archive.tar.gz":          "standalone backup",
		"identities/default/keyring.enc":          "independent root",
		"identities/default/.keystore":            "independent marker",
		"identities/default/config.yaml":          "identity config\n",
		"identities/default/aplane.token":         "token",
		"identities/default/unlock.yaml":          "unlock config\n",
		"identities/default/.ssh/authorized_keys": "ssh key\n",
	} {
		path := filepath.Join(paths.Root(), filepath.FromSlash(relative))
		if err := fsutil.MkdirAll(filepath.Dir(path)); err != nil {
			t.Fatalf("MkdirAll(excluded %s) error = %v", relative, err)
		}
		if err := fsutil.WriteFileDurable(path, []byte(data)); err != nil {
			t.Fatalf("WriteFileDurable(excluded %s) error = %v", relative, err)
		}
	}
	return inventoryFixture{paths: paths, kr: kr}
}

func writeEnvelope(path string, plaintext []byte, ctx crypto.ObjectContext, kr *crypto.Keyring) error {
	data, err := kr.Seal(plaintext, ctx)
	if err != nil {
		return err
	}
	return fsutil.WriteFileDurable(path, data)
}

func findEntry(t *testing.T, report *Report, path string) Entry {
	t.Helper()
	index := slices.IndexFunc(report.Entries, func(entry Entry) bool {
		return entry.Path == path
	})
	if index < 0 {
		t.Fatalf("inventory entry %q not found", path)
	}
	return report.Entries[index]
}
