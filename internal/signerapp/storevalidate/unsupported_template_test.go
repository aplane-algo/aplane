// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storevalidate_test

import (
	"slices"
	"testing"

	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/storevalidate"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/storeinit"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatelibrary"
	"github.com/aplane-algo/aplane/internal/templatestore"
	"github.com/aplane-algo/aplane/lsig/clientreg"
)

const (
	unsupportedTemplateKeyType = "test.unsupported-admin-fixture.v1"
	// Pinned from the code before generation support existed. The stored record
	// carries it, so a changed fingerprint reads as an external edit.
	unsupportedTemplateFingerprint = "1:3397306526ef0ad18780c4c45c729920b332d5ebd4e5fd2a4c335e8dccbd8167"
	unsupportedTemplateYAML        = `
schema_version: 2
template_type: composed
base_key_type: aplane.ed25519.v1
template_mode: strict
publisher: test
family: unsupported-admin-fixture
version: 1
display_name: Unsupported Admin Fixture
max_opcode_cost: 20000
bounded:
  contract: bounded1
  spend_effects: [pay]
  max_fee: 10000
  admin_operations:
    - kind: rekey
      authorization: admin_key
      policy_gate: none
teal: |
  int 1
  assert
`
)

// A template admitted by an earlier build stays usable even if generation would
// now refuse its profile. Refusing it here would turn one template into a content
// defect, sending unlock to recovery mode and blocking every store commit.
func TestInstalledTemplateOutsideGenerationSupportKeepsTheStoreUsable(t *testing.T) {
	clientreg.RegisterClient()
	root := t.TempDir()
	paths := storepaths.NewPaths(root)
	passphrase := []byte("storevalidate-test-passphrase")
	if _, err := storeinit.Initialize(passphrase, storeinit.Options{ValidateCandidate: storevalidate.FirstGeneration,
		DataDir: root, Paths: paths, Role: noderole.RoleSigner,
	}); err != nil {
		t.Fatal(err)
	}
	active, kr, err := genstore.ResolveStoreRoot(paths, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()
	if _, err := templatestore.SaveTemplateActive(active, []byte(unsupportedTemplateYAML), unsupportedTemplateKeyType,
		templatestore.TemplateTypeComposed, kr); err != nil {
		t.Fatal(err)
	}
	if err := keytypestate.PutActive(active, keytypestate.Record{
		KeyType: unsupportedTemplateKeyType, Source: keytypestate.SourceYAMLComposed,
		State: keytypestate.StateEnabled, Fingerprint: unsupportedTemplateFingerprint,
	}); err != nil {
		t.Fatal(err)
	}

	manager := signertemplates.NewManager(paths)
	manager.ActivePaths = active
	t.Cleanup(func() { signertemplates.UnregisterProductProvider(unsupportedTemplateKeyType) })
	report, err := manager.RegisterKeystoreTemplates(kr)
	if err != nil {
		t.Fatalf("RegisterKeystoreTemplates() error = %v", err)
	}
	// Reload fails closed on any entry here.
	if defects := report.ContentDefectKeyTypes(); len(defects) != 0 {
		t.Fatalf("ContentDefectKeyTypes() = %v, want none", defects)
	}
	if !slices.Contains(report.ComposedActivatedKeyTypes, unsupportedTemplateKeyType) {
		t.Fatalf("ComposedActivatedKeyTypes = %v, want %s", report.ComposedActivatedKeyTypes, unsupportedTemplateKeyType)
	}
	provider := lsigprovider.Get(unsupportedTemplateKeyType)
	if provider == nil {
		t.Fatal("installed template was not registered")
	}
	if got, ok := lsigprovider.CompatibilityFingerprintOf(provider); !ok || got != unsupportedTemplateFingerprint {
		t.Fatalf("fingerprint = %q, %v, want %s", got, ok, unsupportedTemplateFingerprint)
	}

	// Generation support is not an import rule, so parsing still accepts it.
	if _, err := templatelibrary.ParseYAML("fixture.yaml", []byte(unsupportedTemplateYAML)); err != nil {
		t.Fatalf("ParseYAML() error = %v", err)
	}

	// Every store commit runs this gate, so an unrelated commit still succeeds.
	if err := storevalidate.Candidate(storevalidate.Options{
		Paths: paths, Candidate: active, Keyring: kr,
		ExpectedRole: noderole.RoleSigner, DataDir: root,
		Config: &serverconfig.ServerConfig{},
	}); err != nil {
		t.Fatalf("Candidate() error = %v", err)
	}
}
