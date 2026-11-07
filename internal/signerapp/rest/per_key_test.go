// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"encoding/hex"
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundary"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/cosigner/cosignerrefs"
	"github.com/aplane-algo/aplane/internal/cosigner/keytypes"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/lsig/boundedaccount"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	lsigsignerreg "github.com/aplane-algo/aplane/lsig/signerreg"
)

// A per-key type has no contract of its own to report, and its cosigner is
// optional, so a store with references must not turn the field into a required
// selector with a default: that would add a cosigner to every account.
func TestPerKeyTypeKeepsItsCosignerOptional(t *testing.T) {
	boundedaccount.RegisterClient()
	ir := setupProductRuntime(t, false)
	publicKey := strings.Repeat("61", 1793)
	raw, err := hex.DecodeString(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := witness.ID(witness.Falcon1024V1, raw)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := cosignerrefs.NewExportEnvelope(keyID, witness.Falcon1024V1, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cosignerrefs.Import(ir.KeyPaths(), "ops", data); err != nil {
		t.Fatal(err)
	}

	infos := Service{}.buildKeyTypes([]string{boundedaccount.KeyTypeV1}, nil)
	applyCosignerReferenceParams(ir, infos)
	if len(infos) != 1 {
		t.Fatalf("buildKeyTypes() = %+v", infos)
	}
	info := infos[0]
	if !info.PerKeyContract || info.SigningFlow != "" || info.BoundedAuthorization != nil {
		t.Fatalf("per-key type reports a fixed contract: %+v", info)
	}
	if info.CosignerComponentKeyType != witness.Falcon1024V1 {
		t.Fatalf("cosigner component = %q", info.CosignerComponentKeyType)
	}
	for _, param := range info.CreationParams {
		if param.Name == cosignerrefs.ParamCosignerName {
			t.Fatalf("the cosigner became a selector: %+v", param)
		}
		if param.Name == keytypes.ParameterCosignerPublicKey && param.Required {
			t.Fatal("the cosigner became required")
		}
	}
}

// per_key_contract means a contract varies by account, and clients take it to mean the
// boundary workflow works. This pins that assumption across every production provider,
// including those not enabled by default. A new per-key provider that can't use the
// workflow must fail here and get narrower discovery, not an exclusion.
func TestEveryPerKeyProviderSupportsTheBoundaryWorkflow(t *testing.T) {
	lsigsignerreg.RegisterSigner()
	adminKey := strings.Repeat("31", composeddsa.BoundedAdminPublicKeySize)
	cosignerKey := strings.Repeat("41", boundedmeta.CosignerPublicKeySizeV1)
	recipient := types.Address{1}.String()
	field := map[string][2]string{
		boundary.ParameterRecipients:        {boundary.ParameterRecipients, recipient},
		boundary.ParameterUnlockRound:       {boundary.ParameterUnlockRound, "100"},
		boundedmeta.AdminPublicKeyParameter: {boundedmeta.AdminPublicKeyParameter, adminKey},
		boundary.ParameterCosigner:          {boundedmeta.CosignerPublicKeyParameter, cosignerKey},
	}

	perKey := 0
	for _, provider := range lsigprovider.GetAll() {
		infos := Service{}.buildKeyTypes([]string{provider.KeyType()}, nil)
		if len(infos) != 1 {
			t.Fatalf("%s: buildKeyTypes() = %+v", provider.KeyType(), infos)
		}
		if !infos[0].PerKeyContract {
			continue
		}
		perKey++
		for _, param := range infos[0].CreationParams {
			if param.Name == "boundary" || param.Name == "result" {
				t.Errorf("%s declares %q, which apshell reads itself", provider.KeyType(), param.Name)
			}
		}
		resolver, ok := provider.(lsigprovider.InstanceResolver)
		if !ok {
			t.Fatalf("%s reports per_key_contract without resolving instances", provider.KeyType())
		}
		for _, preset := range boundary.Presets() {
			values := maps.Clone(preset.Fixed)
			for _, name := range preset.Fields {
				parameter, known := field[name]
				if !known {
					t.Fatalf("preset %s has field %q with no test value", preset.Name, name)
				}
				values[parameter[0]] = parameter[1]
			}
			instance, err := resolver.ResolveInstance(values)
			if err != nil {
				t.Errorf("%s: preset %s: %v", provider.KeyType(), preset.Name, err)
				continue
			}
			metadata := instance.Bounded
			if metadata == nil {
				t.Errorf("%s: preset %s resolved no contract", provider.KeyType(), preset.Name)
				continue
			}
			if got := strings.Join(metadata.SpendEffects, ","); got != preset.Fixed[boundary.ParameterSpendEffects] {
				t.Errorf("%s: preset %s spends %q", provider.KeyType(), preset.Name, got)
			}
			if got, want := metadata.RequiresAdminKey(), preset.Fixed[boundary.ParameterRekeyAuthority] == boundary.RekeyAdminKey; got != want {
				t.Errorf("%s: preset %s admin key = %v, want %v", provider.KeyType(), preset.Name, got, want)
			}
			if got, want := metadata.Cosigner != nil, slices.Contains(preset.Fields, boundary.ParameterCosigner); got != want {
				t.Errorf("%s: preset %s cosigner = %v, want %v", provider.KeyType(), preset.Name, got, want)
			}
		}
	}
	if perKey == 0 {
		t.Fatal("no production provider reports per_key_contract")
	}
}
