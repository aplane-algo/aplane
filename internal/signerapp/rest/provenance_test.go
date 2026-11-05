// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"errors"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigresource"
)

type perKeyRESTProvider struct {
	keyType string
}

func (p perKeyRESTProvider) KeyType() string       { return p.keyType }
func (p perKeyRESTProvider) RoutingFamily() string { return p.keyType }
func (p perKeyRESTProvider) Version() int          { return 1 }
func (p perKeyRESTProvider) Category() string      { return lsigprovider.CategoryGenericLsig }
func (p perKeyRESTProvider) DisplayName() string   { return p.keyType }
func (p perKeyRESTProvider) Description() string   { return "per-key provenance test provider" }
func (p perKeyRESTProvider) DisplayColor() string  { return "" }
func (p perKeyRESTProvider) CreationParams() []lsigprovider.ParameterDef {
	return nil
}
func (p perKeyRESTProvider) ValidateCreationParams(map[string]string) error { return nil }
func (p perKeyRESTProvider) RuntimeArgs() []lsigprovider.RuntimeArgDef      { return nil }
func (p perKeyRESTProvider) BuildArgs([]byte, map[string][]byte) ([][]byte, error) {
	return nil, nil
}

// The type-wide fingerprint matches no stored account, as after a shape is added.
func (p perKeyRESTProvider) CompatibilityFingerprint() string {
	return "1:" + strings.Repeat("c", 64)
}
func (p perKeyRESTProvider) CosignerComponentKeyType(map[string]string) (string, bool) {
	return "", false
}
func (p perKeyRESTProvider) ResolveInstance(map[string]string) (*lsigprovider.Instance, error) {
	return nil, errors.New("not used by inventory")
}
func (p perKeyRESTProvider) StoredFingerprint(parameters map[string]string, _ *boundedmeta.Metadata) (string, error) {
	if parameters["shape"] != "list" {
		return "", errors.New("unknown shape")
	}
	return "1:" + strings.Repeat("a", 64), nil
}

func TestKeysComparesAccountDefinition(t *testing.T) {
	for _, test := range []struct {
		name       string
		stored     string
		wantStatus string
	}{
		{name: "shape-unchanged", stored: "1:" + strings.Repeat("a", 64)},
		{name: "shape-changed", stored: "1:" + strings.Repeat("b", 64), wantStatus: lsigprovider.TemplateProvenanceStatusConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			keyType := "test.rest-instance-" + test.name + ".v1"
			lsigprovider.Register(perKeyRESTProvider{keyType: keyType})
			t.Cleanup(func() { lsigprovider.Unregister(keyType) })

			ir := setupProductRuntime(t, true)
			bytecode := []byte{0x26, 0x01, 0x01, 0x05, 0x81, 0x01}
			payload := keys.NewGenericLSigPayload(keyType, map[string]string{"shape": "list"}, bytecode, 5, "", nil, test.stored)
			if err := payload.SetLogicSigOpcodeProfile(lsigresource.DefaultOpcodeProfile(lsigresource.SingleTransactionOpcodeCeiling), false); err != nil {
				t.Fatal(err)
			}
			if err := ir.WithKeyring(func(mk *crypto.Keyring) error {
				_, err := keys.SavePayload(ir.KeyPaths(), payload, mk)
				return err
			}); err != nil {
				t.Fatalf("write key file: %v", err)
			}
			if _, err := ir.Reload(); err != nil {
				t.Fatalf("Reload() error = %v", err)
			}

			response, svcErr := (Service{}).Keys(ir)
			if svcErr != nil {
				t.Fatalf("Keys() error = %v", svcErr)
			}
			if len(response.Keys) != 1 {
				t.Fatalf("Keys() returned %d keys, want 1", len(response.Keys))
			}
			if got := response.Keys[0].TemplateProvenanceStatus; got != test.wantStatus {
				t.Fatalf("status = %q, want %q", got, test.wantStatus)
			}
		})
	}
}
