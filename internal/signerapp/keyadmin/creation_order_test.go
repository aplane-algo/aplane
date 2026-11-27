// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"context"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/hostmeta"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/noderole"
)

// Import refuses every LogicSig key type, whatever parameters come with it:
// an enabled one as unsupported, a disabled one as not enabled.
func TestImportKeyRefusesALogicSigTypeWhateverItsParameters(t *testing.T) {
	const keyType = "aplane.ed25519.v1"
	ir := setupProductRuntime(t)
	svc := Service{Runtime: ir}
	bad := map[string]string{hostmeta.CosignerPublicKeyParameter: "not hex"}
	for state, want := range map[keytypestate.State]string{
		keytypestate.StateEnabled:  "mnemonic import not supported",
		keytypestate.StateDisabled: "not enabled on this node",
	} {
		if err := keytypestate.Put(ir.KeyPaths(), keytypestate.Record{KeyType: keyType, Source: keytypestate.SourceCompiled, State: state}); err != nil {
			t.Fatal(err)
		}
		result, err := svc.ImportKey(context.Background(), keyType, []byte("invalid phrase"), bad)
		if result != nil || err == nil || err.Kind != ErrorInvalidInput || !strings.Contains(err.Message, want) {
			t.Fatalf("ImportKey(%s, %s, bad parameters) = %v, %#v, want %q", keyType, state, result, err, want)
		}
	}
}

// A creation request on a locked signer is refused as locked before its
// input is judged: the request is resolved under the mutation lock, after
// the unlocked check.
func TestCreationOnALockedSignerIsRefusedFirst(t *testing.T) {
	for _, test := range []struct {
		name    string
		role    noderole.Role
		keyType string
	}{
		{name: "no key type", role: noderole.RoleSigner},
		{name: "key type the node role refuses", role: noderole.RoleCosigner, keyType: "ed25519"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ir := setupProductRuntimeWithRole(t, test.role)
			ir.Lock()
			svc := Service{Runtime: ir}
			if _, err := svc.GenerateKey(context.Background(), test.keyType, nil); err == nil || err.Kind != ErrorLocked || !strings.Contains(err.Message, "signer is not unlocked") {
				t.Fatalf("GenerateKey() error = %#v, want %q", err, "signer is not unlocked")
			}
			if _, err := svc.PrepareGenerateKey(test.keyType, nil); err == nil || err.Kind != ErrorLocked || !strings.Contains(err.Message, "signer is not unlocked") {
				t.Fatalf("PrepareGenerateKey() error = %#v, want %q", err, "signer is not unlocked")
			}
		})
	}
}
