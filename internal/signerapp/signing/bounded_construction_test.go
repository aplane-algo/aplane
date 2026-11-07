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

func TestBoundedSpendingConstructionResolvesFromTheDurableBase(t *testing.T) {
	for _, workflow := range []boundedSigningWorkflow{boundedWorkflowCosigner, boundedWorkflowExternalAdmin} {
		construction, ok := boundedSpendingConstruction(boundedmeta.ContractV1, plainFalcon1024LsigKeyType, workflow)
		if !ok || construction.ID() != sigconstruction.Falcon1024().ID() {
			t.Fatalf("workflow %d on Falcon = %q, %v", workflow, construction.ID(), ok)
		}
		for name, refused := range map[string][2]string{
			"Ed25519":           {boundedmeta.ContractV1, plainEd25519LsigKeyType},
			"no base":           {boundedmeta.ContractV1, ""},
			"witness as a base": {boundedmeta.ContractV1, witness.Falcon1024V1},
			"unknown contract":  {"bounded-unknown", plainFalcon1024LsigKeyType},
		} {
			if _, ok := boundedSpendingConstruction(refused[0], refused[1], workflow); ok {
				t.Fatalf("workflow %d accepted %s", workflow, name)
			}
		}
	}
	if _, ok := boundedSpendingConstruction(boundedmeta.ContractV1, plainFalcon1024LsigKeyType, 0); ok {
		t.Fatal("an unnamed workflow has a construction")
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
	adminKeyRekey := composeddsa.AdminOperationSpec{
		Kind: composeddsa.AdminOperationRekey, Authorization: composeddsa.AdminAuthorizationAdminKey, PolicyGate: composeddsa.AdminPolicyGateNone,
	}
	cosigner := &boundedmeta.CosignerAuthorization{
		Contract: boundedmeta.CosignerContractV1, ComponentKeyType: boundedmeta.CosignerComponentKeyTypeV1,
		SignatureMaxSize: boundedmeta.CosignerSignatureMaxSizeV1, RequiredOn: []string{boundedmeta.PathSpend},
	}
	profiles := []struct {
		name      string
		rekey     []composeddsa.AdminOperationSpec
		cosigner  *boundedmeta.CosignerAuthorization
		workflows []boundedSigningWorkflow
	}{
		{"external admin", []composeddsa.AdminOperationSpec{adminKeyRekey}, nil, []boundedSigningWorkflow{boundedWorkflowExternalAdmin}},
		// A cosigner profile can't take a spending-key rekey, so this one has none.
		{"cosigner", nil, cosigner, []boundedSigningWorkflow{boundedWorkflowCosigner}},
		{"cosigner and external admin", []composeddsa.AdminOperationSpec{adminKeyRekey}, cosigner, []boundedSigningWorkflow{boundedWorkflowCosigner, boundedWorkflowExternalAdmin}},
	}

	for _, base := range bases {
		for _, profile := range profiles {
			t.Run(base.keyType+"/"+profile.name, func(t *testing.T) {
				var profileCosigner *boundedmeta.CosignerAuthorization
				if profile.cosigner != nil {
					copied := *profile.cosigner
					profileCosigner = &copied
				}
				composer := composeddsa.NewComposedDSA(composeddsa.Config{
					KeyType: "test.admission-cross-check.v1", BaseKeyType: base.keyType, FamilyName: base.family,
					Version: 1, Ops: base.ops, TEALSuffix: "int 1\nassert",
					Bounded: &composeddsa.BoundedAuthorizationProfile{
						Contract:        composeddsa.BoundedContractV1,
						SpendEffects:    []txeffects.SpendEffect{txeffects.SpendEffectPay},
						MaxFee:          10_000,
						AdminOperations: profile.rekey,
						Cosigner:        profileCosigner,
					},
				})
				// A profile takes only the keys its authorities declare.
				params := map[string]string{}
				if len(profile.rekey) > 0 {
					params[composeddsa.BoundedAdminPublicKeyParameter] = hex.EncodeToString(bytes.Repeat([]byte{0x33}, composeddsa.BoundedAdminPublicKeySize))
				}
				if profile.cosigner != nil {
					params[composeddsa.BoundedCosignerPublicKeyParameter] = hex.EncodeToString(bytes.Repeat([]byte{0x44}, boundedmeta.CosignerPublicKeySizeV1))
				}
				spendingKey := bytes.Repeat([]byte{0x22}, base.publicKeySize)
				_, err := composer.GenerateTEAL(spendingKey, params)
				if base.keyType == plainFalcon1024LsigKeyType && err != nil {
					// Falcon is admitted for every profile, so a refusal here means the
					// fixture is broken and the check below would prove nothing.
					t.Fatalf("GenerateTEAL() on Falcon error = %v", err)
				}
				if err != nil {
					t.Logf("generation refuses it: %v", err)
					return
				}
				for _, workflow := range profile.workflows {
					if _, ok := boundedSpendingConstruction(boundedmeta.ContractV1, base.keyType, workflow); !ok {
						t.Errorf("generation admits %s on %s, but signing has no construction for workflow %d", profile.name, base.keyType, workflow)
					}
				}
			})
		}
	}
}
