// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storevalidate_test

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
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
	"github.com/aplane-algo/aplane/lsig/generictemplate"
)

// Templates an install refuses. Each stands for one installed by a build that
// had no such check, so each must keep loading.
const (
	admissionGenericOversizedYAML = `schema_version: 1
derivation_version: 3
template_type: generic
template_mode: generated
publisher: test
family: admission-generic-oversized
version: 1
display_name: "Admission Generic Oversized"
valid_rekey_target: false
max_opcode_cost: 20000
runtime_args:
  - name: blob
    type: bytes
    max_size: 5000
teal: |
  arg 0
  len
  return
`
	admissionComposedOversizedYAML = `schema_version: 1
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: generated
publisher: test
family: admission-composed-oversized
version: 1
display_name: "Admission Composed Oversized"
valid_rekey_target: true
max_opcode_cost: 20000
runtime_args:
  - name: blob
    type: bytes
    max_size: 5000
teal: |
  int 1
  assert
`
	admissionBoundedHeader = `schema_version: 2
derivation_version: 3
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: strict
publisher: test
`
	admissionBoundedOversizedYAML = admissionBoundedHeader + `family: admission-bounded-oversized
version: 1
display_name: "Admission Bounded Oversized"
valid_rekey_target: true
max_opcode_cost: 20000
bounded:
  contract: bounded2
  spend_effects: [pay]
  max_fee: 10000
  rekey: refused
  runtime_args:
    - name: blob
      type: bytes
      max_size: 5000
      required_on: [spend]
teal: |
  int 1
  assert
`
	admissionBoundedReservedYAML = admissionBoundedHeader + `family: admission-bounded-reserved
version: 1
display_name: "Admission Bounded Reserved"
valid_rekey_target: false
max_opcode_cost: 20000
bounded:
  contract: bounded2
  spend_effects: [pay]
  max_fee: 10000
  rekey: spending_key
parameters:
  - name: bounded_example_key
    type: bytes
    required: true
    max_length: 3586
teal: |
  int 1
  assert
`
	admissionBoundedRekeyToYAML = admissionBoundedHeader + `family: admission-bounded-rekey-to
version: 1
display_name: "Admission Bounded Rekey To"
valid_rekey_target: false
max_opcode_cost: 20000
bounded:
  contract: bounded2
  spend_effects: [pay, axfer, asset_opt_in]
  max_fee: 10000
  rekey: only_these
parameters:
  - name: rekey_to
    type: address[]
    required: true
    min_items: 1
    max_items: 3
teal: |
  pushint 1
  assert
`
)

func admissionGenericTooManyYAML() string {
	var args strings.Builder
	for i := range 256 {
		fmt.Fprintf(&args, "  - name: arg%d\n    type: bytes\n", i)
	}
	return `schema_version: 1
derivation_version: 3
template_type: generic
template_mode: generated
publisher: test
family: admission-generic-too-many
version: 1
display_name: "Admission Generic Too Many"
valid_rekey_target: false
max_opcode_cost: 20000
runtime_args:
` + args.String() + `teal: |
  arg 0
  len
  return
`
}

// A check added for new templates is an admission check: it refuses an install
// and never a load. Reload and every store commit fail closed on a template
// content defect, so a limit applied at load would let one template installed
// by an earlier build take the whole store down.
//
// Each template here is refused by both install paths (an imported YAML and a
// library file). Written straight into the store, as an earlier build would have
// left it, it validates, registers, and passes the store-commit gate.
func TestInstalledTemplateRefusedAtAdmissionStillLoads(t *testing.T) {
	clientreg.RegisterClient()
	cases := []struct {
		name         string
		keyType      string
		templateType templatestore.TemplateType
		yaml         string
		wantInstall  string
		// The refusal is the bounded template-level contract's.
		contract bool
	}{
		{
			name: "generic runtime argument over the size limit", keyType: "test.admission-generic-oversized.v1",
			templateType: templatestore.TemplateTypeGeneric, yaml: admissionGenericOversizedYAML,
			wantInstall: "invalid generic template: runtime_arg blob is 5000 bytes: a LogicSig argument is at most 4096",
		},
		{
			name: "generic with too many runtime arguments", keyType: "test.admission-generic-too-many.v1",
			templateType: templatestore.TemplateTypeGeneric, yaml: admissionGenericTooManyYAML(),
			wantInstall: "invalid generic template: 256 runtime_args: a LogicSig carries at most 255 arguments",
		},
		{
			name: "schema 1 composed runtime argument over the size limit", keyType: "test.admission-composed-oversized.v1",
			templateType: templatestore.TemplateTypeComposed, yaml: admissionComposedOversizedYAML,
			wantInstall: "invalid composed template: runtime_arg blob is 5000 bytes: a LogicSig argument is at most 4096",
		},
		{
			name: "bounded runtime argument over the size limit", keyType: "test.admission-bounded-oversized.v1",
			templateType: templatestore.TemplateTypeComposed, yaml: admissionBoundedOversizedYAML,
			wantInstall: "invalid composed template: runtime_arg blob is 5000 bytes: a LogicSig argument is at most 4096",
		},
		{
			name: "bounded parameter with the reserved prefix", keyType: "test.admission-bounded-reserved.v1",
			templateType: templatestore.TemplateTypeComposed, yaml: admissionBoundedReservedYAML,
			wantInstall: "reserved bounded_ prefix", contract: true,
		},
		{
			name: "bounded rekey_to that is not the framework's", keyType: "test.admission-bounded-rekey-to.v1",
			templateType: templatestore.TemplateTypeComposed, yaml: admissionBoundedRekeyToYAML,
			wantInstall: "framework-injected contract", contract: true,
		},
	}

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
	// The library calls resolve the active generation from the paths.
	bound := genstoretest.BindActive(t, paths, active)
	if err := templatelibrary.EnsureLibraryDir(bound); err != nil {
		t.Fatal(err)
	}

	// Admission: neither install path lets the template into the store.
	for _, tc := range cases {
		t.Run("install refuses "+tc.name, func(t *testing.T) {
			_, err := templatelibrary.ParseYAML("imported.yaml", []byte(tc.yaml))
			if err == nil || !strings.Contains(err.Error(), tc.wantInstall) {
				t.Fatalf("ParseYAML() error = %v, want %q", err, tc.wantInstall)
			}
			if tc.contract && !strings.Contains(err.Error(), "invalid composed template: invalid bounded template contract: ") {
				t.Fatalf("ParseYAML() error = %v, want the bounded template contract refusal", err)
			}
			if _, err := templatelibrary.ParseYAMLAs("imported.yaml", []byte(tc.yaml), tc.templateType); err == nil || !strings.Contains(err.Error(), tc.wantInstall) {
				t.Fatalf("ParseYAMLAs() error = %v, want %q", err, tc.wantInstall)
			}
			file := strings.TrimPrefix(tc.keyType, "test.") + ".yaml"
			if err := os.WriteFile(filepath.Join(bound.TemplateLibraryDir(), file), []byte(tc.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			ref := templatelibrary.TemplateRef{KeyType: tc.keyType, TemplateType: tc.templateType}
			if _, err := templatelibrary.InstallFromLibrary(bound, ref, kr); err == nil || !strings.Contains(err.Error(), "not found in library") {
				t.Fatalf("InstallFromLibrary() error = %v, want the template refused as a library entry", err)
			}
			items, err := templatelibrary.List(bound)
			if err != nil {
				t.Fatal(err)
			}
			listed := false
			for _, item := range items {
				if item.FileName == file {
					listed = true
					if !strings.Contains(item.Invalid, tc.wantInstall) || item.Installed {
						t.Fatalf("library entry: invalid = %q, installed = %v, want invalid %q", item.Invalid, item.Installed, tc.wantInstall)
					}
				}
			}
			if !listed {
				t.Fatalf("library listing has no entry for %s", file)
			}
			if templatestore.TemplateExistsActive(active, tc.keyType, tc.templateType) {
				t.Fatal("a refused install left a template in the store")
			}
		})
	}

	// The same templates as an earlier build's install left them: the template
	// file and an enabled state record carrying its fingerprint.
	for _, tc := range cases {
		source, fingerprintOf := keytypestate.SourceYAMLGeneric, generictemplate.SemanticFingerprint
		if tc.templateType == templatestore.TemplateTypeComposed {
			source, fingerprintOf = keytypestate.SourceYAMLComposed, composeddsa.SemanticFingerprint
		}
		// The fingerprint an install records, and compares on a reinstall, is
		// load-path code too.
		fingerprint, err := fingerprintOf([]byte(tc.yaml))
		if err != nil {
			t.Fatalf("%s: SemanticFingerprint() error = %v", tc.name, err)
		}
		if _, err := templatestore.SaveTemplateActive(active, []byte(tc.yaml), tc.keyType, tc.templateType, kr); err != nil {
			t.Fatal(err)
		}
		if err := keytypestate.PutActive(active, keytypestate.Record{
			KeyType: tc.keyType, Source: source, State: keytypestate.StateEnabled, Fingerprint: fingerprint,
		}); err != nil {
			t.Fatal(err)
		}
		keyType := tc.keyType
		t.Cleanup(func() { signertemplates.UnregisterProductProvider(keyType) })
	}

	manager := signertemplates.NewManager(paths)
	manager.ActivePaths = active
	activated := func(report signertemplates.RegistrationReport, templateType templatestore.TemplateType) []string {
		if templateType == templatestore.TemplateTypeComposed {
			return report.ComposedActivatedKeyTypes
		}
		return report.GenericActivatedKeyTypes
	}

	// The gate every store commit runs, which registers nothing.
	validated, err := manager.ValidateKeystoreTemplates(kr)
	if err != nil {
		t.Fatalf("ValidateKeystoreTemplates() error = %v", err)
	}
	if defects := validated.ContentDefectKeyTypes(); len(defects) != 0 {
		t.Fatalf("ValidateKeystoreTemplates(): content defects %v (warnings %v), want none", defects, validated.Warnings())
	}
	for _, tc := range cases {
		if !slices.Contains(activated(validated, tc.templateType), tc.keyType) {
			t.Fatalf("ValidateKeystoreTemplates(): %s not accepted; warnings %v", tc.keyType, validated.Warnings())
		}
	}
	if err := storevalidate.Candidate(storevalidate.Options{
		Paths: paths, Candidate: active, Keyring: kr,
		ExpectedRole: noderole.RoleSigner, DataDir: root,
		Config: &serverconfig.ServerConfig{},
	}); err != nil {
		t.Fatalf("Candidate() error = %v", err)
	}

	// What a reload runs. It fails closed on any content defect.
	report, err := manager.RegisterKeystoreTemplates(kr)
	if err != nil {
		t.Fatalf("RegisterKeystoreTemplates() error = %v", err)
	}
	if defects := report.ContentDefectKeyTypes(); len(defects) != 0 {
		t.Fatalf("RegisterKeystoreTemplates(): content defects %v (warnings %v), want none", defects, report.Warnings())
	}
	if warnings := report.Warnings(); len(warnings) != 0 {
		t.Fatalf("RegisterKeystoreTemplates(): warnings %v, want none", warnings)
	}
	for _, tc := range cases {
		if !slices.Contains(activated(report, tc.templateType), tc.keyType) {
			t.Fatalf("RegisterKeystoreTemplates(): %s not activated", tc.keyType)
		}
		if lsigprovider.Get(tc.keyType) == nil {
			t.Fatalf("%s was not registered", tc.keyType)
		}
	}
}
