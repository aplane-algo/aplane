// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storepass

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/asaset"
	"github.com/aplane-algo/aplane/internal/asasetstore"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const rotateFirstGeneration = "gen-1785200000-00000001"

type rotateFixture struct {
	paths          storepaths.Paths
	oldPassphrase  []byte
	accountPath    string
	deletedPath    string
	templatePath   string
	deletedTplPath string
	stateBytes     []byte
}

func newRotateFixture(t *testing.T) rotateFixture {
	t.Helper()
	paths := storepaths.NewPaths(t.TempDir())
	oldPassphrase := []byte("old-store-passphrase")
	kr, err := crypto.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()
	roleBytes, err := noderole.SaveInitial(paths, noderole.RoleSigner, time.Unix(1_785_200_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	stateBytes := []byte("{\"state\":\"enabled\"}\n")
	fixture := rotateFixture{paths: paths, oldPassphrase: oldPassphrase, stateBytes: stateBytes}
	_, err = genstore.Mint(paths, genstore.MintRequest{
		SkipCandidateValidation: true,
		GenerationID:            rotateFirstGeneration,
		FirstGeneration:         true,
		InitialPassphrase:       oldPassphrase,
		Integrity:               kr,
		Operation:               "store-initialize",
		OperationID:             "init-" + rotateFirstGeneration,
		CreatedAt:               time.Unix(1_785_200_000, 0),
		Apply: func(staged storepaths.GenPaths) error {
			if err := noderole.SaveGenerationSidecarWithKeyring(staged, roleBytes, kr, time.Unix(1_785_200_000, 0)); err != nil {
				return err
			}
			if err := policy.WriteEmbeddedDefault(staged, noderole.RoleSigner, kr, time.Unix(1_785_200_000, 0)); err != nil {
				return err
			}
			// An archived key policy: rotation must re-sign archived
			// sidecars too.
			if err := policy.WriteKeyPolicy(staged, noderole.RoleSigner, rotateArchivedPolicyKey, rotateArchivedPolicy, kr, time.Unix(1_785_200_000, 0)); err != nil {
				return err
			}
			if err := policy.ArchiveKeyPolicy(staged, rotateArchivedPolicyKey); err != nil {
				return err
			}
			// An ASA set: rotation must re-sign its sidecar.
			if err := asasetstore.Write(staged, rotateASASet(t), kr, time.Unix(1_785_200_000, 0)); err != nil {
				return err
			}
			fixture.accountPath = filepath.Join(staged.KeysDir(), "ACCOUNT.key")
			fixture.deletedPath = filepath.Join(staged.DeletedKeysDir(), "DELETED.key")
			fixture.templatePath = staged.KeyTypeTemplate("example.v1")
			fixture.deletedTplPath = staged.DeletedKeyTypeTemplate("removed.v1")
			for _, item := range []struct {
				path string
				ctx  crypto.ObjectContext
				text string
			}{
				{fixture.accountPath, crypto.AccountKeyContext("ACCOUNT"), "account-secret"},
				{fixture.deletedPath, crypto.AccountKeyContext("DELETED"), "deleted-secret"},
				{fixture.templatePath, crypto.KeyTypeTemplateContext("example.v1"), "template-secret"},
				{fixture.deletedTplPath, crypto.KeyTypeTemplateContext("removed.v1"), "deleted-template-secret"},
			} {
				sealed, err := kr.Seal([]byte(item.text), item.ctx)
				if err != nil {
					return err
				}
				if err := os.WriteFile(item.path, sealed, 0o600); err != nil {
					return err
				}
			}
			return os.WriteFile(staged.KeyTypeRecord("example.v1"), stateBytes, 0o600)
		},
	})
	if err != nil {
		t.Fatalf("Mint(first atomic generation) error = %v", err)
	}
	active := paths.GenerationPaths(rotateFirstGeneration)
	fixture.accountPath = filepath.Join(active.KeysDir(), "ACCOUNT.key")
	fixture.deletedPath = filepath.Join(active.DeletedKeysDir(), "DELETED.key")
	fixture.templatePath = active.KeyTypeTemplate("example.v1")
	fixture.deletedTplPath = active.DeletedKeyTypeTemplate("removed.v1")
	return fixture
}

func rotateASASet(t *testing.T) *asaset.Set {
	t.Helper()
	set, err := asaset.New([]asaset.Entry{{
		Identity:              asaset.Identity{Genesis: asaset.GenesisHash{1}, AssetID: 7},
		UnitName:              "XYZ",
		Decimals:              2,
		Creator:               rotateArchivedPolicyKey,
		ConfirmedAt:           time.Unix(1_785_200_000, 0),
		NetworkAtConfirmation: "private-dev",
	}})
	if err != nil {
		t.Fatal(err)
	}
	return set
}

const rotateArchivedPolicyKey = "CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM"

var rotateArchivedPolicy = []byte(policytest.MustDocument(noderole.RoleSigner, rotateArchivedPolicyKey, ""))

// acceptCandidate is a candidate validation that accepts every successor,
// for the tests about the rotation itself.
func acceptCandidate(storepaths.GenPaths, *crypto.Keyring) error { return nil }

// A passphrase change without candidate validation is refused before it
// writes anything, the outgoing seal included. Rotate once handed Mint a
// validation that accepted every successor when the caller gave none, so
// Mint's guard could not fire and the change published an unvalidated
// generation.
func TestRotateRefusesWithoutCandidateValidation(t *testing.T) {
	fixture := newRotateFixture(t)
	newPassphrase := []byte("new-store-passphrase")
	before, err := crypto.ReadStoreRootExact(fixture.paths.ProductDir())
	if err != nil {
		t.Fatal(err)
	}

	result, err := Rotate(fixture.paths, fixture.oldPassphrase, newPassphrase, RotateOptions{})
	if err == nil || result.RootCommitted || !strings.Contains(err.Error(), "requires candidate validation") {
		t.Fatalf("Rotate(no candidate validation) = %+v, %v; want the candidate validation refusal", result, err)
	}
	if sealed, err := genstore.HasSeal(fixture.paths.GenerationPaths(rotateFirstGeneration)); err != nil || sealed {
		t.Fatalf("selected generation sealed after the refusal = %v, %v; want no seal written", sealed, err)
	}
	after, err := crypto.ReadStoreRootExact(fixture.paths.ProductDir())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("the refused passphrase change replaced the store root")
	}
	if _, kr, err := genstore.ResolveStoreRoot(fixture.paths, newPassphrase); err == nil {
		kr.Zero()
		t.Fatal("the new passphrase opens the store after the refusal")
	}
	entries, err := os.ReadDir(fixture.paths.GenerationsDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != rotateFirstGeneration {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("generations after the refusal = %v, want only %s", names, rotateFirstGeneration)
	}
}

func TestRotatePublishesCompleteFreshTermSuccessor(t *testing.T) {
	fixture := newRotateFixture(t)
	newPassphrase := []byte("new-store-passphrase")
	result, err := Rotate(fixture.paths, fixture.oldPassphrase, newPassphrase, RotateOptions{ValidateCandidate: acceptCandidate})
	if err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if !result.RootCommitted || result.KeysMigrated != 2 || result.TemplatesMigrated != 2 ||
		result.PolicySidecarsMigrated != 2 || result.NodeRoleSidecarsMigrated != 1 {
		t.Fatalf("Rotate() result = %+v", result)
	}
	if _, _, err := genstore.ResolveStoreRoot(fixture.paths, fixture.oldPassphrase); err == nil {
		t.Fatal("old passphrase still opens committed root")
	}
	active, kr, err := genstore.ResolveStoreRoot(fixture.paths, newPassphrase)
	if err != nil {
		t.Fatalf("ResolveStoreRoot(new passphrase) error = %v", err)
	}
	defer kr.Zero()
	if active.GenerationID() == rotateFirstGeneration || kr.CurrentTerm() != 2 {
		t.Fatalf("selected=%s term=%d, want fresh successor term 2", active.GenerationID(), kr.CurrentTerm())
	}
	manifest, err := genstore.ReadManifest(active)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.ParentID != rotateFirstGeneration || manifest.Operation != "store-passphrase-change" {
		t.Fatalf("successor manifest = %+v", manifest)
	}

	for _, item := range []struct {
		path string
		ctx  crypto.ObjectContext
		want string
	}{
		{filepath.Join(active.KeysDir(), "ACCOUNT.key"), crypto.AccountKeyContext("ACCOUNT"), "account-secret"},
		{filepath.Join(active.DeletedKeysDir(), "DELETED.key"), crypto.AccountKeyContext("DELETED"), "deleted-secret"},
		{active.KeyTypeTemplate("example.v1"), crypto.KeyTypeTemplateContext("example.v1"), "template-secret"},
		{active.DeletedKeyTypeTemplate("removed.v1"), crypto.KeyTypeTemplateContext("removed.v1"), "deleted-template-secret"},
	} {
		encoded, err := os.ReadFile(item.path)
		if err != nil {
			t.Fatal(err)
		}
		term, present, err := crypto.InspectTermEnvelope(encoded)
		if err != nil || !present || term != kr.CurrentTerm() {
			t.Fatalf("%s term = %d, %v, %v", item.path, term, present, err)
		}
		plaintext, err := kr.Open(encoded, item.ctx)
		if err != nil || string(plaintext) != item.want {
			t.Fatalf("open %s = %q, %v", item.path, plaintext, err)
		}
		crypto.ZeroBytes(plaintext)
	}
	state, err := os.ReadFile(active.KeyTypeRecord("example.v1"))
	if err != nil || !bytes.Equal(state, fixture.stateBytes) {
		t.Fatalf("plaintext state = %q, %v", state, err)
	}
	if _, _, err := policy.LoadVerifiedDefault(active, noderole.RoleSigner, kr); err != nil {
		t.Fatalf("successor policy verification: %v", err)
	}
	archivedPath := filepath.Join(active.DeletedPoliciesDir(), rotateArchivedPolicyKey+".json")
	archived, err := os.ReadFile(archivedPath)
	if err != nil || !bytes.Equal(archived, rotateArchivedPolicy) {
		t.Fatalf("archived policy = %q, %v", archived, err)
	}
	archivedSidecar, err := policy.LoadPolicyIntegritySidecar(archivedPath + ".hmac")
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.VerifyPolicyIntegrity(archived, archivedSidecar, kr); err != nil {
		t.Fatalf("archived policy sidecar not re-signed for the successor term: %v", err)
	}
	if _, err := noderole.LoadAndVerifyGenerationWithKeyring(fixture.paths, active, kr); err != nil {
		t.Fatalf("successor node role verification: %v", err)
	}
	set, err := asasetstore.Load(active, kr)
	if err != nil || len(set.Entries()) != 1 {
		t.Fatalf("successor asa set = %+v, %v; want it re-signed for the successor term", set, err)
	}
	anchor, ok := kr.HistoricalGenerationAnchor(rotateFirstGeneration)
	if !ok {
		t.Fatal("outgoing generation has no historical anchor")
	}
	prior := fixture.paths.GenerationPaths(rotateFirstGeneration)
	if err := genstore.ValidateAnchoredSealed(prior, anchor, kr); err != nil {
		t.Fatalf("anchored prior verification: %v", err)
	}
	priorEnvelope, err := os.ReadFile(filepath.Join(prior.KeysDir(), "ACCOUNT.key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kr.Open(priorEnvelope, crypto.AccountKeyContext("ACCOUNT")); err == nil {
		t.Fatal("retired term retained ordinary current-state authority")
	}
	priorSeal, err := os.ReadFile(prior.SealPath())
	if err != nil {
		t.Fatal(err)
	}
	priorManifest, err := os.ReadFile(prior.ManifestPath())
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := genstore.OpenAnchoredEnvelopeBytes(prior, anchor, priorSeal, priorManifest, "keys/ACCOUNT.key", priorEnvelope, crypto.AccountKeyContext("ACCOUNT"), kr)
	if err != nil || string(plaintext) != "account-secret" {
		t.Fatalf("OpenAnchoredEnvelopeBytes() = %q, %v", plaintext, err)
	}
	crypto.ZeroBytes(plaintext)
	for _, retired := range []string{
		filepath.Join(fixture.paths.ProductDir(), "CURRENT"),
		filepath.Join(fixture.paths.ProductDir(), "keyring.enc"),
		filepath.Join(fixture.paths.ProductDir(), "rotation.snapshot.enc"),
		filepath.Join(fixture.paths.ProductDir(), "rotation.baseline.enc"),
	} {
		if _, err := os.Lstat(retired); !os.IsNotExist(err) {
			t.Fatalf("retired artifact exists at %s: %v", retired, err)
		}
	}
}

func TestRotatePreRootFailureLeavesOldAuthorityAndQuarantinableSuccessor(t *testing.T) {
	fixture := newRotateFixture(t)
	newPassphrase := []byte("new-store-passphrase")
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpRename && path == fixture.paths.StoreRootPath() {
			return errors.New("injected pre-root-rename failure")
		}
		return nil
	}
	t.Cleanup(func() { fsutil.TestHook = nil })
	result, err := Rotate(fixture.paths, fixture.oldPassphrase, newPassphrase, RotateOptions{ValidateCandidate: acceptCandidate})
	fsutil.TestHook = nil
	if err == nil || result.RootCommitted {
		t.Fatalf("Rotate() = %+v, %v; want definite precommit failure", result, err)
	}
	active, kr, err := genstore.ResolveStoreRoot(fixture.paths, fixture.oldPassphrase)
	if err != nil || active.GenerationID() != rotateFirstGeneration {
		t.Fatalf("old authority = %s, %v", active.GenerationID(), err)
	}
	defer kr.Zero()
	if _, _, err := genstore.ResolveStoreRoot(fixture.paths, newPassphrase); err == nil {
		t.Fatal("new passphrase opened after precommit failure")
	}
	report, err := genstore.ReconcileStoreRoot(fixture.paths, kr)
	if err != nil {
		t.Fatalf("ReconcileStoreRoot() error = %v", err)
	}
	if len(report.Quarantined) != 1 {
		t.Fatalf("quarantined = %+v, want one complete successor", report.Quarantined)
	}
}

func TestRotateWrongPassphraseAndDamagedAuthorityDoNotReplaceRoot(t *testing.T) {
	fixture := newRotateFixture(t)
	before, err := crypto.ReadStoreRootExact(fixture.paths.ProductDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Rotate(fixture.paths, []byte("wrong"), []byte("new"), RotateOptions{ValidateCandidate: acceptCandidate}); err == nil || !strings.Contains(err.Error(), "current passphrase") {
		t.Fatalf("Rotate(wrong passphrase) error = %v", err)
	}
	after, err := crypto.ReadStoreRootExact(fixture.paths.ProductDir())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("wrong passphrase changed store root")
	}
	if err := os.Remove(fixture.paths.GenerationPaths(rotateFirstGeneration).DefaultPolicyIntegritySidecar()); err != nil {
		t.Fatal(err)
	}
	if _, err := Rotate(fixture.paths, fixture.oldPassphrase, []byte("new"), RotateOptions{ValidateCandidate: acceptCandidate}); err == nil {
		t.Fatal("Rotate accepted damaged policy authority")
	}
	after, err = crypto.ReadStoreRootExact(fixture.paths.ProductDir())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("damaged authority changed store root")
	}
}

func TestRotateHelperFailureIsPostCommitWarning(t *testing.T) {
	fixture := newRotateFixture(t)
	result, err := Rotate(fixture.paths, fixture.oldPassphrase, []byte("new-passphrase"), RotateOptions{
		ValidateCandidate: acceptCandidate,
		AfterRootCommit:   func() error { return errors.New("helper unavailable") },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.RootCommitted || !strings.Contains(result.HelperWarning, "helper unavailable") {
		t.Fatalf("Rotate() result = %+v", result)
	}
}

// A passphrase change whose new root lands but cannot be read back says the
// new passphrase may be in effect, rather than reporting a plain failure the
// operator would answer with the old passphrase.
func TestRotateWithAnUnreadableRootSaysTheNewPassphraseMayBeInEffect(t *testing.T) {
	fixture := newRotateFixture(t)
	newPassphrase := []byte("new-store-passphrase")
	root, aside := fixture.paths.StoreRootPath(), fixture.paths.StoreRootPath()+".aside"
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op != fsutil.OpDirSync || path != fixture.paths.ProductDir() {
			return nil
		}
		fsutil.TestHook = nil
		if err := os.Rename(root, aside); err != nil {
			t.Error(err)
		}
		return errors.New("simulated identity-directory sync failure")
	}
	t.Cleanup(func() { fsutil.TestHook = nil })
	result, err := Rotate(fixture.paths, fixture.oldPassphrase, newPassphrase, RotateOptions{ValidateCandidate: acceptCandidate})
	fsutil.TestHook = nil
	if err := os.Rename(aside, root); err != nil {
		t.Fatal(err)
	}
	if err == nil || result.RootCommitted || !errors.Is(err, genstore.ErrStoreRootCommitStateUnknown) ||
		!strings.Contains(err.Error(), "the new passphrase may be in effect") {
		t.Fatalf("Rotate() = %+v, %v; want the may-be-in-effect error", result, err)
	}
	if _, kr, err := genstore.ResolveStoreRoot(fixture.paths, newPassphrase); err != nil {
		t.Fatalf("the new passphrase does not open the root that landed: %v", err)
	} else {
		kr.Zero()
	}
}

// A store whose selected generation grew past the quarantine candidate limits
// in place is refused before the outgoing seal reads and hashes all of it.
func TestRotateRefusesAnOverLimitGenerationBeforeSealing(t *testing.T) {
	fixture := newRotateFixture(t)
	active := fixture.paths.GenerationPaths(rotateFirstGeneration)
	// A sparse member one byte over the 64 MiB per-file limit.
	big := filepath.Join(active.KeysDir(), "OVERSIZED.key")
	if err := os.WriteFile(big, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(big, 64<<20+1); err != nil {
		t.Fatal(err)
	}
	before, err := crypto.ReadStoreRootExact(fixture.paths.ProductDir())
	if err != nil {
		t.Fatal(err)
	}

	_, err = Rotate(fixture.paths, fixture.oldPassphrase, []byte("new-store-passphrase"), RotateOptions{ValidateCandidate: acceptCandidate})
	if err == nil || !strings.Contains(err.Error(), "holds more than one generation may") {
		t.Fatalf("Rotate error = %v, want the size refusal", err)
	}
	if _, err := os.Lstat(active.SealPath()); !os.IsNotExist(err) {
		t.Fatalf("outgoing seal after the refusal: %v, want none written", err)
	}
	after, err := crypto.ReadStoreRootExact(fixture.paths.ProductDir())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("the refused passphrase change replaced the store root")
	}
}
