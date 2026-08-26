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

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
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
	roleBytes, _, err := noderole.SaveInitial(paths, noderole.RoleSigner, time.Unix(1_785_200_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	stateBytes := []byte("{\"state\":\"enabled\"}\n")
	fixture := rotateFixture{paths: paths, oldPassphrase: oldPassphrase, stateBytes: stateBytes}
	_, err = genstore.Mint(paths, genstore.MintRequest{
		GenerationID:      rotateFirstGeneration,
		FirstGeneration:   true,
		AtomicStoreRoot:   true,
		InitialPassphrase: oldPassphrase,
		Integrity:         kr,
		Operation:         "store-initialize",
		OperationID:       "init-" + rotateFirstGeneration,
		CreatedAt:         time.Unix(1_785_200_000, 0),
		Apply: func(staged storepaths.GenPaths) error {
			if err := noderole.SaveGenerationSidecarWithKeyring(paths, staged, roleBytes, kr, time.Unix(1_785_200_000, 0)); err != nil {
				return err
			}
			if err := policy.SaveStoredConfigActiveWithKeyring(staged, &policy.StoredConfig{}, kr, time.Unix(1_785_200_000, 0)); err != nil {
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

func TestRotatePublishesCompleteFreshTermSuccessor(t *testing.T) {
	fixture := newRotateFixture(t)
	newPassphrase := []byte("new-store-passphrase")
	result, err := Rotate(fixture.paths, fixture.oldPassphrase, newPassphrase, RotateOptions{})
	if err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if !result.RootCommitted || result.KeysMigrated != 2 || result.TemplatesMigrated != 2 ||
		result.PolicySidecarsMigrated != 1 || result.NodeRoleSidecarsMigrated != 1 {
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
		term, err := crypto.EnvelopeTerm(encoded)
		if err != nil || term != kr.CurrentTerm() {
			t.Fatalf("%s term = %d, %v", item.path, term, err)
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
	if _, err := policy.LoadVerifiedStoredConfigActive(active, kr); err != nil {
		t.Fatalf("successor policy verification: %v", err)
	}
	if _, err := noderole.LoadAndVerifyGenerationWithKeyring(fixture.paths, active, kr); err != nil {
		t.Fatalf("successor node role verification: %v", err)
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
	plaintext, err := genstore.OpenAnchoredEnvelope(prior, anchor, "keys/ACCOUNT.key", crypto.AccountKeyContext("ACCOUNT"), kr)
	if err != nil || string(plaintext) != "account-secret" {
		t.Fatalf("OpenAnchoredEnvelope() = %q, %v", plaintext, err)
	}
	crypto.ZeroBytes(plaintext)
	for _, retired := range []string{
		fixture.paths.CurrentPointerPath(),
		crypto.KeyringPath(fixture.paths.KeystoreMetadataDir()),
		fixture.paths.RotationSnapshotPath(),
		fixture.paths.RotationBaselinePath(),
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
	result, err := Rotate(fixture.paths, fixture.oldPassphrase, newPassphrase, RotateOptions{})
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
	report, err := genstore.ReconcileStoreRoot(fixture.paths, kr, nil)
	if err != nil {
		t.Fatalf("ReconcileStoreRoot() error = %v", err)
	}
	if len(report.Quarantined) != 1 {
		t.Fatalf("quarantined = %+v, want one complete successor", report.Quarantined)
	}
}

func TestRotateWrongPassphraseAndDamagedAuthorityDoNotReplaceRoot(t *testing.T) {
	fixture := newRotateFixture(t)
	before, err := crypto.ReadStoreRootExact(fixture.paths.KeystoreMetadataDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Rotate(fixture.paths, []byte("wrong"), []byte("new"), RotateOptions{}); err == nil || !strings.Contains(err.Error(), "current passphrase") {
		t.Fatalf("Rotate(wrong passphrase) error = %v", err)
	}
	after, err := crypto.ReadStoreRootExact(fixture.paths.KeystoreMetadataDir())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("wrong passphrase changed store root")
	}
	if err := os.Remove(fixture.paths.GenerationPaths(rotateFirstGeneration).PolicyIntegritySidecar()); err != nil {
		t.Fatal(err)
	}
	if _, err := Rotate(fixture.paths, fixture.oldPassphrase, []byte("new"), RotateOptions{}); err == nil {
		t.Fatal("Rotate accepted damaged policy authority")
	}
	after, err = crypto.ReadStoreRootExact(fixture.paths.KeystoreMetadataDir())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("damaged authority changed store root")
	}
}

func TestRotateHelperFailureIsPostCommitWarning(t *testing.T) {
	fixture := newRotateFixture(t)
	result, err := Rotate(fixture.paths, fixture.oldPassphrase, []byte("new-passphrase"), RotateOptions{
		AfterRootCommit: func() error { return errors.New("helper unavailable") },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.RootCommitted || !strings.Contains(result.HelperWarning, "helper unavailable") {
		t.Fatalf("Rotate() result = %+v", result)
	}
}
