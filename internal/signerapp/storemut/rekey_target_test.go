// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storemut

import (
	"fmt"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
)

func registerRekeyTargetTemplate(t *testing.T, family string, valid bool) string {
	t.Helper()
	yaml := fmt.Sprintf(`schema_version: 1
template_type: generic
template_mode: generated
publisher: test
family: %s
version: 1
display_name: "Rekey Target Template"
max_opcode_cost: 20000
valid_rekey_target: %t
teal: |
  int 1
  return
`, family, valid)
	keyType := "test." + family + ".v1"
	prepared, err := generictemplate.PrepareKeystoreTemplateRegistration(keyType, []byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	lsigprovider.Unregister(keyType)
	if !prepared.Register() {
		t.Fatalf("%s did not register", keyType)
	}
	t.Cleanup(func() { lsigprovider.Unregister(keyType) })
	return keyType
}

// A generic LogicSig aplane key records its template's valid_rekey_target as
// declared when the key is created. Whatever the registry later holds for the
// key type, another declaration or no template at all, the key keeps it.
func TestGenericLogicSigKeyRecordsValidRekeyTarget(t *testing.T) {
	for i, declared := range []bool{false, true} {
		t.Run(fmt.Sprint(declared), func(t *testing.T) {
			paths, kr, cleanup := setupKeystore(t)
			defer cleanup()
			family := fmt.Sprintf("rekey-target-%d", i)
			keyType := registerRekeyTargetTemplate(t, family, declared)
			salted, err := lsigsalt.FindOffCurveAtOffset([]byte{0x06, 0x81, 0x01, 0x00, byte(i)}, 3)
			if err != nil {
				t.Fatal(err)
			}
			if err := New(paths).SaveGenericLSig(keyType, nil, salted.Bytecode, salted.Counter, false, "int 1", nil,
				lsigresource.DefaultOpcodeProfile(lsigresource.SingleTransactionOpcodeCeiling), kr); err != nil {
				t.Fatalf("SaveGenericLSig() error = %v", err)
			}
			address := salted.Address.String()
			recorded := func(label string) {
				t.Helper()
				scanned, err := keys.ScanKeysDirectoryWithKeyring(paths, kr)
				if err != nil {
					t.Fatal(err)
				}
				info, ok := scanned[address]
				if !ok || info.ValidRekeyTarget != declared {
					t.Fatalf("%s: scanned key %+v, want valid_rekey_target %v", label, info, declared)
				}
			}
			recorded("after creation")
			// The template now declares the opposite; the key keeps its value.
			registerRekeyTargetTemplate(t, family, !declared)
			recorded("after the declaration changed")
			// With the template gone, the key still carries its value.
			lsigprovider.Unregister(keyType)
			recorded("with the template absent")
		})
	}
}

// Creating a key fails, and writes nothing, when its key type's
// valid_rekey_target does not resolve: an unregistered key type, or a
// template loaded without the field (load does not require it). The key never
// records a guess.
func TestGenericLogicSigCreationFailsWithoutAResolvedDeclaration(t *testing.T) {
	undeclared := "test.rekey-target-undeclared.v1"
	prepared, err := generictemplate.PrepareKeystoreTemplateRegistration(undeclared, []byte(`schema_version: 1
template_type: generic
template_mode: generated
publisher: test
family: rekey-target-undeclared
version: 1
display_name: "Undeclared"
max_opcode_cost: 20000
teal: |
  int 1
  return
`))
	if err != nil {
		t.Fatal(err)
	}
	lsigprovider.Unregister(undeclared)
	if !prepared.Register() {
		t.Fatalf("%s did not register", undeclared)
	}
	t.Cleanup(func() { lsigprovider.Unregister(undeclared) })

	for i, keyType := range []string{"test.rekey-target-unregistered.v1", undeclared} {
		t.Run(keyType, func(t *testing.T) {
			paths, kr, cleanup := setupKeystore(t)
			defer cleanup()
			salted, err := lsigsalt.FindOffCurveAtOffset([]byte{0x06, 0x81, 0x01, 0x00, byte(0x40 + i)}, 3)
			if err != nil {
				t.Fatal(err)
			}
			err = New(paths).SaveGenericLSig(keyType, nil, salted.Bytecode, salted.Counter, false, "int 1", nil,
				lsigresource.DefaultOpcodeProfile(lsigresource.SingleTransactionOpcodeCeiling), kr)
			if err == nil || !strings.Contains(err.Error(), "valid_rekey_target declaration does not resolve") {
				t.Fatalf("SaveGenericLSig() error = %v, want an unresolved declaration", err)
			}
			scanned, err := keys.ScanKeysDirectoryWithKeyring(paths, kr)
			if err != nil {
				t.Fatal(err)
			}
			if len(scanned) != 0 {
				t.Fatalf("keys written: %v, want none", scanned)
			}
		})
	}
}
