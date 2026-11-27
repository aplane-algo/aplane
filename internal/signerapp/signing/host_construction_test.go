// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/aplane-algo/aplane/internal/hostmeta"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
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

func TestHostSpendingConstructionResolvesFromTheDurableBase(t *testing.T) {
	for _, workflow := range []hostSigningWorkflow{hostWorkflowCosigner} {
		// A bounded host is cosigned on either base (account overlays phase 6.5).
		for keyType, want := range map[string]sigconstruction.ConstructionID{
			plainFalcon1024LsigKeyType: sigconstruction.Falcon1024().ID(),
			plainEd25519LsigKeyType:    sigconstruction.Ed25519().ID(),
		} {
			construction, ok := hostSpendingConstruction(hostmeta.BoundedContract, keyType, workflow)
			if !ok || construction.ID() != want {
				t.Fatalf("workflow %d on %s = %q, %v", workflow, keyType, construction.ID(), ok)
			}
		}
		for name, refused := range map[string][2]string{
			"no base":           {hostmeta.BoundedContract, ""},
			"witness as a base": {hostmeta.BoundedContract, witness.Falcon1024V1},
			"unknown contract":  {"bounded-unknown", plainFalcon1024LsigKeyType},
		} {
			if _, ok := hostSpendingConstruction(refused[0], refused[1], workflow); ok {
				t.Fatalf("workflow %d accepted %s", workflow, name)
			}
		}
	}
	if _, ok := hostSpendingConstruction(hostmeta.BoundedContract, plainFalcon1024LsigKeyType, 0); ok {
		t.Fatal("an unnamed workflow has a construction")
	}
	// The plain host's cosigned flow completes both of its bases.
	for keyType, want := range map[string]sigconstruction.ConstructionID{
		plainFalcon1024LsigKeyType: sigconstruction.Falcon1024().ID(),
		plainEd25519LsigKeyType:    sigconstruction.Ed25519().ID(),
	} {
		construction, ok := hostSpendingConstruction(hostmeta.PlainContract, keyType, hostWorkflowCosigner)
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
		{plainFalcon1024LsigKeyType, "aplane.falcon1024", falconv1.NewFalconOps(), falconfamily.PublicKeySize},
		{plainEd25519LsigKeyType, "aplane.ed25519", ed25519v1.NewOps(), ed25519.PublicKeySize},
	}
	cosigner := &hostmeta.CosignerAuthorization{
		Contract: hostmeta.CosignerContractV1, ComponentKeyType: hostmeta.DefaultCosignerComponentKeyType,
		SignatureMaxSize: hostmeta.DefaultCosignerSignatureMaxSize, RequiredOn: []string{hostmeta.PathSpend},
	}
	profiles := []struct {
		name      string
		contract  string
		rekey     hostmeta.RekeySetting
		cosigner  *hostmeta.CosignerAuthorization
		workflows []hostSigningWorkflow
	}{
		{"cosigner", hostmeta.BoundedContract, hostmeta.RekeyRefused, cosigner, []hostSigningWorkflow{hostWorkflowCosigner}},
		{"plain host", hostmeta.PlainContract, hostmeta.RekeyRefused, cosigner, []hostSigningWorkflow{hostWorkflowCosigner}},
	}

	for _, base := range bases {
		for _, profile := range profiles {
			t.Run(base.keyType+"/"+profile.name, func(t *testing.T) {
				var profileCosigner *hostmeta.CosignerAuthorization
				if profile.cosigner != nil {
					copied := *profile.cosigner
					profileCosigner = &copied
				}
				config := composeddsa.Config{
					KeyType: "test.admission-cross-check.v1", BaseKeyType: base.keyType, FamilyName: base.family,
					Version: 1, Ops: base.ops, SaltStyle: lsigsalt.StyleAlgodAutoSalt, TemplateMode: "generated", TEALSuffix: "int 1\nassert",
					Host: &composeddsa.HostProfile{
						Contract: profile.contract,
						Bounds:   &composeddsa.ProfileBounds{SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: new(uint64(10_000))},
						Rekey:    profile.rekey,
						Cosigner: profileCosigner,
					},
				}
				if profile.contract == hostmeta.PlainContract {
					config.TEALSuffix = ""
					config.Host.Bounds = nil
					config.Layer3 = &composeddsa.Layer3Policy{Policy: composeddsa.Layer3PolicyNone}
				}
				composer := composeddsa.NewComposedDSA(config)
				// A profile takes only the keys its authorities declare.
				params := map[string]string{}
				if profile.cosigner != nil {
					params[composeddsa.CosignerPublicKeyParameter] = hex.EncodeToString(bytes.Repeat([]byte{0x44}, hostmeta.DefaultCosignerPublicKeySize))
				}
				spendingKey := bytes.Repeat([]byte{0x22}, base.publicKeySize)
				_, err := composer.GenerateTEAL(spendingKey, params)
				// Falcon is admitted for every profile, and the plain host on both
				// bases, so a refusal there means the fixture is broken and the
				// check below would prove nothing.
				if (base.keyType == plainFalcon1024LsigKeyType || profile.contract == hostmeta.PlainContract) && err != nil {
					t.Fatalf("GenerateTEAL() on %s error = %v", base.keyType, err)
				}
				if err != nil {
					t.Logf("generation refuses it: %v", err)
					return
				}
				for _, workflow := range profile.workflows {
					if _, ok := hostSpendingConstruction(profile.contract, base.keyType, workflow); !ok {
						t.Errorf("generation admits %s on %s, but signing has no construction for workflow %d", profile.name, base.keyType, workflow)
					}
				}
			})
		}
	}
}
