// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package lsig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/keymgmt"
	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	"github.com/aplane-algo/aplane/lsig/ecdsak1"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	falcon1024attested "github.com/aplane-algo/aplane/lsig/falcon1024_attested"
	falcon1024ed25519 "github.com/aplane-algo/aplane/lsig/falcon1024_ed25519"
)

func TestRegisterClientLeavesLibraryTemplatesOptional(t *testing.T) {
	RegisterClient()

	for _, keyType := range []string{
		"aplane.timed-whitelist.v1",
		"aplane.whitelist.v1",
		"aplane.htlc.v1",
		"aplane.falcon1024-whitelist.v1",
		"aplane.falcon1024-hashlock.v1",
		"aplane.falcon1024-timelock.v1",
	} {
		if lsigprovider.Has(keyType) {
			t.Fatalf("RegisterClient() registered %s; it should remain an optional template", keyType)
		}
	}
}

// TestRegisterClientMarksLibraryVisible pins the "compiled in but gated behind
// per-identity activation" contract for every library-availability DSA
// provider. Adding a new library-gated provider without a row here is a
// reviewer-visible omission.
func TestRegisterClientMarksLibraryVisible(t *testing.T) {
	RegisterClient()

	libraryGatedKeyTypes := []string{
		falcon1024attested.KeyTypeV1,
		falcon1024attested.KeyTypeFalcon1024V1,
		falcon1024ed25519.KeyTypeV1,
		ecdsak1.KeyTypeV1,
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

// TestBundledComposedTemplatesBindTxIDBeforeSuffix pins the cross-component
// invariant that the bundled aplane.falcon1024-* composed templates rely on
// for rekey/close binding: when the registered aplane.falcon1024.v1 base
// is composed with each bundled template, the produced TEAL emits
// `txn TxID` in the verifier section, follows it with `assert`, and only
// then runs the user suffix. This catches regressions in either the base
// (e.g., switching to a non-txid signature scheme) or the composer wrap
// (moving user TEAL above the assert), both of which would silently break
// the rekey-guard property the templates depend on for transaction-shape
// safety.
func TestBundledComposedTemplatesBindTxIDBeforeSuffix(t *testing.T) {
	RegisterClient()

	cases := []struct {
		file         string
		suffixMarker string // a substring unique to that template's user suffix
	}{
		{"aplane.falcon1024-hashlock.v1.yaml", "sha256"},
		{"aplane.falcon1024-timelock.v1.yaml", "FirstValid"},
		{"aplane.falcon1024-whitelist.v1.yaml", "Only pay/axfer"},
	}

	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "library", "templates", c.file))
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}
			spec, err := composeddsa.ParseTemplateSpec(data)
			if err != nil {
				t.Fatalf("ParseTemplateSpec: %v", err)
			}
			provider, err := composeddsa.NewProviderFromTemplateSpec(spec)
			if err != nil {
				t.Fatalf("NewProviderFromTemplateSpec: %v", err)
			}

			// Use a dummy Falcon-1024-sized public key. GenerateTEAL only
			// embeds it in the verifier; correctness of the produced
			// signature is not in scope here, only the wrap shape.
			pubKey := make([]byte, family.PublicKeySize)
			params := bundledTemplateTestParams(c.file)
			teal, err := provider.GenerateTEAL(pubKey, params)
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
				t.Fatalf("verifier section must include `falcon_verify` between txid and suffix:\n%s", between)
			}
			if !strings.Contains(between, "assert") {
				t.Fatalf("`assert` must appear between verifier output and user suffix:\n%s", between)
			}
		})
	}
}

// bundledTemplateTestParams returns the minimum parameters needed to
// successfully render each bundled composed template's TEAL. Values are
// shape-correct placeholders; this test does not exercise their semantics.
func bundledTemplateTestParams(file string) map[string]string {
	switch file {
	case "aplane.falcon1024-hashlock.v1.yaml":
		return map[string]string{
			"hash": strings.Repeat("00", 32),
		}
	case "aplane.falcon1024-timelock.v1.yaml":
		return map[string]string{
			"unlock_round": "1",
		}
	case "aplane.falcon1024-whitelist.v1.yaml":
		return map[string]string{
			"recipients": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
		}
	default:
		return nil
	}
}
