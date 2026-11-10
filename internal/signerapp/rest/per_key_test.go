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
	falcon "github.com/aplane-algo/aplane/lsig/falcon1024"
	lsigsignerreg "github.com/aplane-algo/aplane/lsig/signerreg"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// A per-key type has no contract of its own to report, and its cosigner is
// optional, so a store with references must not turn the field into a required
// selector with a default: that would add a cosigner to every account.
func TestPerKeyTypeKeepsItsCosignerOptional(t *testing.T) {
	falcon.RegisterClient()
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

	infos := Service{}.buildKeyTypes([]string{"aplane.falcon1024.v1"}, nil)
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
		if param.Name == cosignerrefs.ParamCosignerName && (param.Required || param.Default != "" || len(param.Options) > 0) {
			t.Fatalf("the cosigner became a selector: %+v", param)
		}
		if param.Name == keytypes.ParameterCosignerPublicKey && param.Required {
			t.Fatal("the cosigner became required")
		}
	}
}

// boundary_schema names the grammar a per-key type takes, and clients take it to mean
// the boundary workflow works. This pins that across every production provider that
// declares it, including those not enabled by default. A per-key type that declares
// none, such as a plain host, takes its parameters directly and is checked apart.
func TestEveryBoundaryProviderSupportsTheBoundaryWorkflow(t *testing.T) {
	lsigsignerreg.RegisterSigner()
	cosignerKey := strings.Repeat("41", boundedmeta.CosignerPublicKeySizeV1)
	recipient := types.Address{1}.String()
	field := map[string][2]string{
		boundary.ParameterRecipients: {boundary.ParameterRecipients, recipient},
		boundary.ParameterRekeyTo:    {boundary.ParameterRekeyTo, types.Address{2}.String()},
		boundary.ParameterCosigner:   {boundedmeta.CosignerPublicKeyParameter, cosignerKey},
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
		if infos[0].BoundarySchema == "" {
			continue
		}
		if infos[0].BoundarySchema != boundary.SchemaV1 {
			t.Fatalf("%s declares boundary schema %q", provider.KeyType(), infos[0].BoundarySchema)
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
			// "Only these" is stored as rekey refused plus the rekey-to list.
			got := string(metadata.Rekey)
			if metadata.RekeyList != nil && metadata.Rekey == boundedmeta.RekeyRefused {
				got = boundary.RekeyOnlyThese
			}
			if want := preset.Fixed[boundary.ParameterRekeyAuthority]; got != want {
				t.Errorf("%s: preset %s rekey = %q, want %q", provider.KeyType(), preset.Name, got, want)
			}
			if got, want := metadata.Cosigner != nil, slices.Contains(preset.Fields, boundary.ParameterCosigner); got != want {
				t.Errorf("%s: preset %s cosigner = %v, want %v", provider.KeyType(), preset.Name, got, want)
			}
		}
	}
	if perKey == 0 {
		t.Fatal("no production provider declares the boundary schema")
	}
}

// The wire's contract names are the durable record's.
func TestWireBoundedContractsMatchTheRecord(t *testing.T) {
	if signerapi.BoundedContractBounded2 != boundedmeta.Contract || signerapi.BoundedContractPlain1 != boundedmeta.PlainContract {
		t.Fatalf("wire contracts %q, %q; record %q, %q", signerapi.BoundedContractBounded2, signerapi.BoundedContractPlain1, boundedmeta.Contract, boundedmeta.PlainContract)
	}
}
