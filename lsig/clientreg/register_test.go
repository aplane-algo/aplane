// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientreg

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/boundary"
	"github.com/aplane-algo/aplane/internal/keymgmt"
	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

func TestCanonicalCompiledLogicSigInventory(t *testing.T) {
	RegisterClient()

	// The general bounded type is the one LogicSig type enabled by default. The
	// protocol-native types are too, but they register outside lsig. The plain
	// LogicSig types are plain hosts, and they and the other compiled types are
	// opt-in through the library.
	defaultEnabled := catalogKeyTypes(keytypecatalog.DefaultEnabled())
	if !reflect.DeepEqual(defaultEnabled, []string{boundary.KeyTypeV1}) {
		t.Fatalf("default-enabled compiled LogicSig inventory = %v, want %s only", defaultEnabled, boundary.KeyTypeV1)
	}

	libraryVisible := catalogKeyTypes(keytypecatalog.LibraryVisible())
	wantLibraryVisible := []string{
		"aplane.ed25519.v1",
		"aplane.falcon1024.v1",
		"aplane.rotating-triple-slhdsa.v1",
		"aplane.rotating-triple-wotsc.v1",
		"aplane.rotating-triple-xmss.v1",
	}
	if !reflect.DeepEqual(libraryVisible, wantLibraryVisible) {
		t.Fatalf("library-visible compiled LogicSig inventory = %v, want %v", libraryVisible, wantLibraryVisible)
	}

	if witness.Falcon1024V1 != "aplane.witness-falcon1024.v1" {
		t.Fatalf("cosigner component key type = %q", witness.Falcon1024V1)
	}
}

// The retired bounded templates were deleted with bounded1, so the HTLC is the
// only bundled template and no retired-template directory ships beside it.
func TestCanonicalBundledTemplateInventory(t *testing.T) {
	if _, err := os.Stat(filepath.Join("..", "..", "library", "retired")); !os.IsNotExist(err) {
		t.Fatalf("a retired-template directory exists or cannot be checked: %v", err)
	}
	for _, test := range []struct {
		dir  string
		want []string
	}{
		{dir: "templates", want: []string{"aplane.htlc.v1.yaml"}},
	} {
		entries, err := os.ReadDir(filepath.Join("..", "..", "library", test.dir))
		if err != nil {
			t.Fatalf("ReadDir(library/%s) error = %v", test.dir, err)
		}
		var got []string
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".yaml") {
				got = append(got, entry.Name())
			}
		}
		sort.Strings(got)
		if !reflect.DeepEqual(got, test.want) {
			t.Fatalf("library/%s inventory = %v, want %v", test.dir, got, test.want)
		}
	}
}

func catalogKeyTypes(entries []keytypecatalog.Entry) []string {
	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		result = append(result, entry.KeyType)
	}
	return result
}

func TestRegisterClientLeavesLibraryTemplatesOptional(t *testing.T) {
	RegisterClient()

	for _, keyType := range []string{
		"aplane.htlc.v1",
	} {
		if lsigprovider.Has(keyType) {
			t.Fatalf("RegisterClient() registered %s; it should remain an optional template", keyType)
		}
	}
}

// TestRegisterClientMarksLibraryVisible pins the "compiled in but gated behind
// per-store activation" contract for every library-availability DSA
// provider. Adding a new library-gated provider without a row here is a
// reviewer-visible omission.
func TestRegisterClientMarksLibraryVisible(t *testing.T) {
	RegisterClient()

	libraryGatedKeyTypes := []string{
		"aplane.falcon1024.v1",
		"aplane.ed25519.v1",
	}

	for _, keyType := range libraryGatedKeyTypes {
		t.Run(keyType, func(t *testing.T) {
			if !lsigprovider.Has(keyType) {
				t.Fatalf("RegisterClient() did not register %s as binary capability", keyType)
			}
			if keytypecatalog.IsDefaultEnabled(keyType) {
				t.Fatalf("%s should not be default-enabled", keyType)
			}
			if !keytypecatalog.IsLibraryVisible(keyType) {
				t.Fatalf("%s should be library-visible", keyType)
			}
			for _, validType := range keymgmt.GetValidKeyTypes() {
				if validType == keyType {
					t.Fatalf("%s should not be in default generation key types", keyType)
				}
			}
			if !containsKeyType(keymgmt.GetValidKeyTypesWithActivated([]string{keyType}), keyType) {
				t.Fatalf("%s should be in generation key types after activation", keyType)
			}
		})
	}
}

func containsKeyType(types []string, want string) bool {
	for _, got := range types {
		if got == want {
			return true
		}
	}
	return false
}

// composedFixtureTemplate is a bounded template on the registered Falcon base.
// policy is the bounded block's tail after the rekey setting; tail follows bounded.
func composedFixtureTemplate(family, policy, tail string) string {
	return `schema_version: 2
derivation_version: 3
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: strict
publisher: test
family: ` + family + `
version: 1
display_name: "Composed Fixture"
max_opcode_cost: 20000

bounded:
  contract: bounded2
  spend_effects: [pay, axfer, asset_opt_in]
  max_fee: 10000
  rekey: refused
` + policy + `
` + tail
}

// TestComposedTemplatesBindTxIDBeforeSuffix pins the cross-component
// invariant that composed templates on the Falcon base rely on for rekey/close
// binding: when the registered aplane.falcon1024.v1 base is composed with a
// template, the produced TEAL emits `txn TxID` in the verifier section, follows
// it with `assert`, and only then runs the Layer 3 suffix, whether the author or
// the framework wrote it. This catches regressions in either the base (e.g.,
// switching to a non-txid signature scheme) or the composer wrap (moving the
// suffix above the assert), both of which would silently break the rekey-guard
// property templates depend on for transaction-shape safety.
func TestComposedTemplatesBindTxIDBeforeSuffix(t *testing.T) {
	RegisterClient()

	recipientsParameter := `parameters:
  - name: recipients
    type: address[]
    required: true
    min_items: 1
    max_items: 30
`
	cases := []struct {
		name         string
		yaml         string
		params       map[string]string
		suffixMarker string // a substring unique to that template's suffix
	}{
		{
			name: "author timelock",
			yaml: composedFixtureTemplate("author-timelock-fixture", "", `parameters:
  - name: unlock_round
    type: uint64
    required: true
    min: 1

template_variables:
  - name: unlock_round
    source: parameter
    parameter: unlock_round
    type: uint64
    constant: int

teal: |
  // Timelock check: FirstValid >= unlock_round
  txn FirstValid
  $unlock_round
  >=
  assert
`),
			params:       map[string]string{"unlock_round": "1"},
			suffixMarker: "FirstValid",
		},
		{
			name:         "fixed allowlist",
			yaml:         composedFixtureTemplate("fixed-allowlist-fixture", "  layer3:\n    policy: fixed_allowlist\n    recipients_parameter: recipients", recipientsParameter),
			params:       map[string]string{"recipients": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"},
			suffixMarker: "framework-owned fixed allowlist",
		},
		{
			name: "merkle allowlist",
			yaml: composedFixtureTemplate("merkle-allowlist-fixture", `  layer3:
    policy: merkle_allowlist
    recipients_parameter: recipients
  derived_args:
    - name: merkle_proof
      kind: merkle_allowlist_proof
      parameter: recipients
      max_size: 512`, strings.Replace(recipientsParameter, "max_items: 30", "max_items: 65536", 1)),
			params:       map[string]string{"recipients": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"},
			suffixMarker: "framework-owned Merkle allowlist",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec, err := composeddsa.ParseTemplateSpec([]byte(c.yaml))
			if err != nil {
				t.Fatalf("ParseTemplateSpec: %v", err)
			}
			provider, err := composeddsa.NewProviderFromTemplateSpec(spec)
			if err != nil {
				t.Fatalf("NewProviderFromTemplateSpec: %v", err)
			}

			// Use a dummy public key. GenerateTEAL only embeds it in the
			// verifier; correctness of the produced signature is not in
			// scope here, only the wrap shape.
			teal, err := provider.GenerateTEAL(make([]byte, family.PublicKeySize), c.params)
			if err != nil {
				t.Fatalf("GenerateTEAL: %v", err)
			}

			txidIdx := strings.Index(teal, "txn TxID")
			if txidIdx < 0 {
				t.Fatalf("verifier did not emit `txn TxID` — base no longer binds txid; produced TEAL:\n%s", teal)
			}
			suffixIdx := strings.Index(teal, c.suffixMarker)
			if suffixIdx < 0 {
				t.Fatalf("user suffix marker %q not found in produced TEAL:\n%s", c.suffixMarker, teal)
			}
			if txidIdx >= suffixIdx {
				t.Fatalf("`txn TxID` must precede user suffix; got txid@%d suffix@%d:\n%s",
					txidIdx, suffixIdx, teal)
			}

			between := teal[txidIdx:suffixIdx]
			if !strings.Contains(between, "falcon_verify") {
				t.Fatalf("verifier section must include %q between txid and suffix:\n%s", "falcon_verify", between)
			}
			if !strings.Contains(between, "assert") {
				t.Fatalf("`assert` must appear between verifier output and user suffix:\n%s", between)
			}
		})
	}
}

// The plain LogicSig types stay the composable bases every bounded account
// names, and are plain hosts: opt-in through the library, and created only with
// a cosigner, which the signer checks when it resolves the request.
func TestPlainHostsRemainComposableAndAreOptIn(t *testing.T) {
	RegisterClient()
	for _, keyType := range []string{"aplane.falcon1024.v1", "aplane.ed25519.v1"} {
		t.Run(keyType, func(t *testing.T) {
			if !keytypecatalog.IsLibraryVisible(keyType) || !lsigprovider.Has(keyType) || !composeddsa.IsBaseRegistered(keyType) {
				t.Fatalf("%s must stay registered as a composable base and be library-visible", keyType)
			}
			if containsKeyType(keymgmt.GetValidKeyTypesWithActivated(nil), keyType) {
				t.Fatalf("%s is enabled without activation", keyType)
			}
			if !containsKeyType(keymgmt.GetValidKeyTypesWithActivated([]string{keyType}), keyType) {
				t.Fatalf("activation does not enable %s", keyType)
			}
			if keymgmt.SupportsMnemonicImport(keyType) {
				t.Fatalf("%s exposed user mnemonic import", keyType)
			}
			instance, err := lsigprovider.ResolveInstance(lsigprovider.Get(keyType), nil)
			if err != nil || instance.Unavailable == "" {
				t.Fatalf("%s without overlays: instance %+v, %v; want unavailable", keyType, instance, err)
			}
		})
	}
}
