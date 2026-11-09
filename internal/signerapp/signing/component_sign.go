// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/internal/cosigner/message"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
)

type componentKeyGetter interface {
	GetKeyWithContext(context.Context, string) (*coresigning.KeyMaterial, error)
}

// signPreparedCosignerComponents is the narrow private-key operation for
// cosigner-role component signatures. Callers must run deterministic
// cosigner policy before invoking it.
func signPreparedCosignerComponents(ctx context.Context, plan *ComponentSignPlan, session componentKeyGetter) (*ComponentSignResult, *ServiceError) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, canceledSignRequest(err)
	}
	if plan == nil {
		return nil, internal("component sign plan is nil")
	}
	if plan.MessageRole != message.RoleCosigner {
		return nil, badRequest("cosigner component signing requires cosigner role")
	}
	if plan.ComponentKey == "" {
		return nil, badRequest("component_key is required for cosigner component signing")
	}
	if session == nil {
		return nil, internal("key session is nil")
	}

	keyMaterial, componentKey, err := loadCosignerComponentKey(ctx, session, plan.ComponentKey)
	if err != nil {
		return nil, err
	}
	defer zeroLoadedKeyMaterial(keyMaterial)

	signatures := make([]ComponentSignature, len(plan.Targets))
	for i, target := range plan.Targets {
		signature, signErr := signCosignerComponentMessage(keyMaterial.Type, componentKey.PrivateKey, target.Message[:])
		if signErr != nil {
			return nil, signErr
		}
		signatures[i] = ComponentSignature{
			TargetIndex:     target.TargetIndex,
			Signature:       hex.EncodeToString(signature),
			SignatureScheme: keyMaterial.Type,
		}
		crypto.ZeroBytes(signature)
	}

	return &ComponentSignResult{
		RequestID:    plan.RequestID,
		ComponentKey: componentKey.WitnessKeyID,
		Signatures:   signatures,
	}, nil
}

func loadCosignerComponentKey(ctx context.Context, session componentKeyGetter, componentKeySelector string) (*coresigning.KeyMaterial, *coresigning.WitnessKeyMaterial, *ServiceError) {
	componentKeySelector, normalizeErr := witness.NormalizeID(componentKeySelector)
	if normalizeErr != nil {
		return nil, nil, badRequest(normalizeErr.Error())
	}

	keyMaterial, err := session.GetKeyWithContext(ctx, componentKeySelector)
	if err != nil {
		switch {
		case errors.Is(err, keystore.ErrStoreLocked):
			return nil, nil, lockedError()
		case errors.Is(err, keystore.ErrKeyNotFound):
			return nil, nil, badRequest(fmt.Sprintf("Witness Key ID %q not found", componentKeySelector))
		default:
			return nil, nil, internal(fmt.Sprintf("failed to load cosigner key: %v", err))
		}
	}
	if keyMaterial == nil {
		return nil, nil, internal("loaded cosigner key material is nil")
	}
	if !witness.IsKeyType(keyMaterial.Type) {
		gotType := keyMaterial.Type
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, nil, badRequest(fmt.Sprintf("key %q is %s, not a cosigner key", componentKeySelector, gotType))
	}
	if keyMaterial.Category != "" && keyMaterial.Category != keys.CategoryWitness {
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, nil, badRequest(fmt.Sprintf("key %q is not a cosigner key", componentKeySelector))
	}
	componentKey, ok := keyMaterial.Value.(*coresigning.WitnessKeyMaterial)
	if !ok || componentKey == nil {
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, nil, internal("loaded cosigner key has invalid material")
	}
	if componentKey.WitnessKeyID != componentKeySelector {
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, nil, internal("loaded Witness Key ID does not match requested Witness Key ID")
	}
	publicKeySize, publicOK := witness.PublicKeySize(keyMaterial.Type)
	privateKeySize, privateOK := witness.PrivateKeySize(keyMaterial.Type)
	if !publicOK || !privateOK {
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, nil, internal(fmt.Sprintf("loaded cosigner key has unsupported witness key type %q", keyMaterial.Type))
	}
	if len(componentKey.PrivateKey) != privateKeySize {
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, nil, internal(fmt.Sprintf("loaded cosigner key has private key length %d", len(componentKey.PrivateKey)))
	}
	if len(componentKey.PublicKey) != publicKeySize {
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, nil, internal(fmt.Sprintf("loaded cosigner key has public key length %d", len(componentKey.PublicKey)))
	}
	if err := validateLoadedCosignerComponentPair(keyMaterial.Type, componentKey.PublicKey, componentKey.PrivateKey); err != nil {
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, nil, internal(err.Error())
	}
	return keyMaterial, componentKey, nil
}

func signCosignerComponentMessage(keyType string, privateKey, msg []byte) ([]byte, *ServiceError) {
	if err := witness.RequireCapability(witness.CustodianNetworkedSigner, witness.DomainCosignerComponent); err != nil {
		return nil, internal(err.Error())
	}
	switch keyType {
	case witness.Falcon1024V1:
		signature, err := signerops.New(nil).Sign(privateKey, msg)
		if err != nil {
			return nil, internal(fmt.Sprintf("failed to sign Falcon cosigner component message: %v", err))
		}
		return signature, nil
	default:
		return nil, badRequest(fmt.Sprintf("key type %q is not a cosigner key", keyType))
	}
}

func validateLoadedCosignerComponentPair(keyType string, publicKey, privateKey []byte) error {
	if err := witness.ValidatePair(keyType, publicKey, privateKey); err != nil {
		return fmt.Errorf("loaded cosigner key validation failed: %w", err)
	}
	return nil
}
