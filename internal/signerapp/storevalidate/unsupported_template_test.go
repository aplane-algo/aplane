// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storevalidate_test

import (
	"slices"
	"strings"
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
	"github.com/aplane-algo/aplane/lsig/composeddsa"
)

// The fixture is a structurally valid template that generation support refuses.
// Every production base is supported for what structural validation admits, so the
// fixture uses a base registered under a name outside the construction catalog,
// with Falcon's ops: it loads, but bounded_support.go has no entry for it.
const (
	unsupportedTemplateBase    = "test.uncataloged-base.v1"
	unsupportedTemplateKeyType = "test.unsupported-base-fixture.v1"
	// The stored record carries the fingerprint, so a changed one reads as an
	// external edit. Generation support must never reach it.
	unsupportedTemplateFingerprint = "1:830f3656cbdb79b0b46ca7c7644df26fa62d6a91fbe851ed15d39b5e0c74febf"
	unsupportedTemplateYAML        = `
schema_version: 2
template_type: composed
base_key_type: test.uncataloged-base.v1
template_mode: strict
publisher: test
family: unsupported-base-fixture
version: 1
display_name: Unsupported Base Fixture
valid_rekey_target: true
max_opcode_cost: 20000
bounded:
  contract: bounded2
  spend_effects: [pay]
  max_fee: 10000
  rekey: refused
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
	falconBase, ok := composeddsa.LookupBase("aplane.falcon1024.v1")
	if !ok {
		t.Fatal("Falcon base is not registered")
	}
	composeddsa.RegisterBase(composeddsa.BaseRegistration{
		BaseKeyType: unsupportedTemplateBase, FamilyName: "uncataloged-base", Version: 1,
		Ops: falconBase.Ops, NewAddressDeriver: falconBase.NewAddressDeriver,
	})
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
	// The fixture must really be outside generation support, or this proves nothing.
	generator, ok := provider.(interface {
		GenerateTEAL([]byte, map[string]string) (string, error)
	})
	if !ok {
		t.Fatalf("provider %T cannot generate", provider)
	}
	if _, err := generator.GenerateTEAL(make([]byte, 1793), nil); err == nil || !strings.Contains(err.Error(), "cannot be generated on base key type") {
		t.Fatalf("GenerateTEAL() error = %v, want the generation support refusal", err)
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
