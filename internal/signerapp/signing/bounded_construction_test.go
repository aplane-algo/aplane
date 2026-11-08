// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/sigconstruction"
	"github.com/aplane-algo/aplane/internal/txeffects"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	ed25519v1 "github.com/aplane-algo/aplane/lsig/ed25519lsig/v1"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
	falconv1 "github.com/aplane-algo/aplane/lsig/falcon1024/v1"
)

// The plain LogicSig bases a bounded account can be composed over.
const (
	plainFalcon1024LsigKeyType = "aplane.falcon1024.v1"
	plainEd25519LsigKeyType    = "aplane.ed25519.v1"
)

func TestBoundedSpendingConstructionResolvesFromTheDurableBase(t *testing.T) {
	for _, workflow := range []boundedSigningWorkflow{boundedWorkflowCosigner} {
		construction, ok := boundedSpendingConstruction(boundedmeta.Contract, plainFalcon1024LsigKeyType, workflow)
		if !ok || construction.ID() != sigconstruction.Falcon1024().ID() {
			t.Fatalf("workflow %d on Falcon = %q, %v", workflow, construction.ID(), ok)
		}
		for name, refused := range map[string][2]string{
			"Ed25519":           {boundedmeta.Contract, plainEd25519LsigKeyType},
			"no base":           {boundedmeta.Contract, ""},
			"witness as a base": {boundedmeta.Contract, witness.Falcon1024V1},
			"unknown contract":  {"bounded-unknown", plainFalcon1024LsigKeyType},
		} {
			if _, ok := boundedSpendingConstruction(refused[0], refused[1], workflow); ok {
				t.Fatalf("workflow %d accepted %s", workflow, name)
			}
		}
	}
	if _, ok := boundedSpendingConstruction(boundedmeta.Contract, plainFalcon1024LsigKeyType, 0); ok {
		t.Fatal("an unnamed workflow has a construction")
	}
	// The plain host's cosigned flow completes both of its bases.
	for keyType, want := range map[string]sigconstruction.ConstructionID{
		plainFalcon1024LsigKeyType: sigconstruction.Falcon1024().ID(),
		plainEd25519LsigKeyType:    sigconstruction.Ed25519().ID(),
	} {
		construction, ok := boundedSpendingConstruction(boundedmeta.PlainContract, keyType, boundedWorkflowCosigner)
		if !ok || construction.ID() != want {
			t.Fatalf("plain host on %s = %q, %v", keyType, construction.ID(), ok)
		}
	}
}

// Generation admission must stay within what signing completes, or it would create
// accounts the signer then refuses to finish, which is the gap #202 closed. Each
// catalog base is composed directly, without the provider registry, under every
// bounded workflow profile. Wherever generation admits one, the signer must have a
// construction for each workflow the profile uses.
func TestBoundedGenerationAdmitsOnlySignableWorkflows(t *testing.T) {
	bases := []struct {
		keyType, family string
		ops             composeddsa.DSAOps
		publicKeySize   int
	}{
		{plainFalcon1024LsigKeyType, "aplane.falcon1024", falconv1.NewFalconOps(falconfamily.FalconBase), falconfamily.PublicKeySize},
		{plainEd25519LsigKeyType, "aplane.ed25519", ed25519v1.NewOps(), ed25519.PublicKeySize},
	}
	cosigner := &boundedmeta.CosignerAuthorization{
		Contract: boundedmeta.CosignerContractV1, ComponentKeyType: boundedmeta.CosignerComponentKeyTypeV1,
		SignatureMaxSize: boundedmeta.CosignerSignatureMaxSizeV1, RequiredOn: []string{boundedmeta.PathSpend},
	}
	profiles := []struct {
		name      string
		contract  string
		rekey     boundedmeta.RekeySetting
		cosigner  *boundedmeta.CosignerAuthorization
		workflows []boundedSigningWorkflow
	}{
		{"cosigner", boundedmeta.Contract, boundedmeta.RekeyRefused, cosigner, []boundedSigningWorkflow{boundedWorkflowCosigner}},
		{"plain host", boundedmeta.PlainContract, boundedmeta.RekeyRefused, cosigner, []boundedSigningWorkflow{boundedWorkflowCosigner}},
	}

	for _, base := range bases {
		for _, profile := range profiles {
			t.Run(base.keyType+"/"+profile.name, func(t *testing.T) {
				var profileCosigner *boundedmeta.CosignerAuthorization
				if profile.cosigner != nil {
					copied := *profile.cosigner
					profileCosigner = &copied
				}
				config := composeddsa.Config{
					KeyType: "test.admission-cross-check.v1", BaseKeyType: base.keyType, FamilyName: base.family,
					Version: 1, Ops: base.ops, TEALSuffix: "int 1\nassert",
					Bounded: &composeddsa.BoundedAuthorizationProfile{
						Contract:     profile.contract,
						SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay},
						MaxFee:       new(uint64(10_000)),
						Rekey:        profile.rekey,
						Cosigner:     profileCosigner,
					},
				}
				if profile.contract == boundedmeta.PlainContract {
					config.TEALSuffix = ""
					config.Bounded.SpendEffects, config.Bounded.MaxFee = nil, nil
					config.Layer3 = &composeddsa.Layer3Policy{Policy: composeddsa.Layer3PolicyNone}
				}
				composer := composeddsa.NewComposedDSA(config)
				// A profile takes only the keys its authorities declare.
				params := map[string]string{}
				if profile.cosigner != nil {
					params[composeddsa.BoundedCosignerPublicKeyParameter] = hex.EncodeToString(bytes.Repeat([]byte{0x44}, boundedmeta.CosignerPublicKeySizeV1))
				}
				spendingKey := bytes.Repeat([]byte{0x22}, base.publicKeySize)
				_, err := composer.GenerateTEAL(spendingKey, params)
				// Falcon is admitted for every profile, and the plain host on both
				// bases, so a refusal there means the fixture is broken and the
				// check below would prove nothing.
				if (base.keyType == plainFalcon1024LsigKeyType || profile.contract == boundedmeta.PlainContract) && err != nil {
					t.Fatalf("GenerateTEAL() on %s error = %v", base.keyType, err)
				}
				if err != nil {
					t.Logf("generation refuses it: %v", err)
					return
				}
				for _, workflow := range profile.workflows {
					if _, ok := boundedSpendingConstruction(profile.contract, base.keyType, workflow); !ok {
						t.Errorf("generation admits %s on %s, but signing has no construction for workflow %d", profile.name, base.keyType, workflow)
					}
				}
			})
		}
	}
}
