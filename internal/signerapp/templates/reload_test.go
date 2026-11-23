// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package templates

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"

	"github.com/aplane-algo/aplane/internal/lsigprovider"
	utilkeys "github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatelibrary"
	"github.com/aplane-algo/aplane/internal/templatestore"
	"github.com/aplane-algo/aplane/lsig/clientreg"
)

// A reload is fail-closed on a template content defect, so it never applies a
// check that only a new template must pass. A template whose runtime argument is
// larger than the network allows can't be installed any more; one already in the
// store, from a build without that check, still loads on the real registrars.
func TestReloadLoadsInstalledTemplatesAnInstallNowRefuses(t *testing.T) {
	clientreg.RegisterClient()
	const genericKeyType, composedKeyType, boundedKeyType = "test.reload-generic-oversized.v1", "test.reload-composed-oversized.v1", "test.reload-bounded-oversized.v1"
	generic := []byte(`schema_version: 1
derivation_version: 3
template_type: generic
template_mode: generated
publisher: test
family: reload-generic-oversized
version: 1
display_name: "Reload Generic Oversized"
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
`)
	composed := []byte(`schema_version: 1
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: generated
publisher: test
family: reload-composed-oversized
version: 1
display_name: "Reload Composed Oversized"
valid_rekey_target: true
max_opcode_cost: 20000
runtime_args:
  - name: blob
    type: bytes
    max_size: 5000
teal: |
  int 1
  assert
`)
	bounded := []byte(`schema_version: 2
derivation_version: 3
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: strict
publisher: test
family: reload-bounded-oversized
version: 1
display_name: "Reload Bounded Oversized"
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
`)
	// The fixtures are ones an install refuses.
	for _, data := range [][]byte{generic, composed, bounded} {
		if _, err := templatelibrary.ParseYAML("fixture.yaml", data); err == nil || !strings.Contains(err.Error(), "runtime_arg blob is 5000 bytes: a LogicSig argument is at most 4096") {
			t.Fatalf("ParseYAML() error = %v, want the argument size refusal", err)
		}
	}

	paths := mintedPathsForReloadTest(t)
	masterKey := testTemplateMasterKey()
	saveTemplateYAML(t, paths, genericKeyType, templatestore.TemplateTypeGeneric, generic, masterKey)
	saveTemplateYAML(t, paths, composedKeyType, templatestore.TemplateTypeComposed, composed, masterKey)
	saveTemplateYAML(t, paths, boundedKeyType, templatestore.TemplateTypeComposed, bounded, masterKey)
	t.Cleanup(func() {
		lsigprovider.Unregister(genericKeyType)
		lsigprovider.Unregister(composedKeyType)
		lsigprovider.Unregister(boundedKeyType)
	})

	report, defects := reloadTemplatesForTest(t, paths)
	if len(defects) != 0 {
		t.Fatalf("the reload found defects %v, want the store to load", defects)
	}
	if warnings := report.Warnings(); len(warnings) != 0 {
		t.Fatalf("Warnings() = %v, want none", warnings)
	}
	if !containsString(report.GenericActivatedKeyTypes, genericKeyType) {
		t.Fatalf("GenericActivatedKeyTypes = %v, want %s", report.GenericActivatedKeyTypes, genericKeyType)
	}
	for _, keyType := range []string{composedKeyType, boundedKeyType} {
		if !containsString(report.ComposedActivatedKeyTypes, keyType) {
			t.Fatalf("ComposedActivatedKeyTypes = %v, want %s", report.ComposedActivatedKeyTypes, keyType)
		}
	}
	for _, keyType := range []string{genericKeyType, composedKeyType, boundedKeyType} {
		if lsigprovider.Get(keyType) == nil {
			t.Fatalf("%s was not registered", keyType)
		}
	}
}

func mintedPathsForReloadTest(t *testing.T) utilkeys.Paths {
	t.Helper()
	paths := utilkeys.NewPaths(t.TempDir())
	paths = genstoretest.MintFirst(t, paths)
	return paths
}
