// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
	"github.com/aplane-algo/aplane/internal/attestor/message"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/signerapi"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
)

type componentKeyGetter interface {
	GetKeyWithContext(context.Context, string) (*coresigning.KeyMaterial, error)
}

// signPreparedAttestorComponents is the narrow private-key operation for
// attestor-role component signatures. Callers must run deterministic
// attestation policy before invoking it.
func signPreparedAttestorComponents(ctx context.Context, plan *ComponentSignPlan, session componentKeyGetter) (*ComponentSignResult, *ServiceError) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, canceledSignRequest(err)
	}
	if plan == nil {
		return nil, internal("component sign plan is nil")
	}
	if plan.MessageRole != message.RoleAttestor {
		return nil, badRequest("attestor component signing requires attestor role")
	}
	if plan.ComponentKey == "" {
		return nil, badRequest("component_key is required for attestor component signing")
	}
	if session == nil {
		return nil, internal("key session is nil")
	}

	keyMaterial, componentKey, err := loadAttestorComponentKey(ctx, session, plan.ComponentKey)
	if err != nil {
		return nil, err
	}
	defer zeroLoadedKeyMaterial(keyMaterial)

	signatures := make([]signerapi.ComponentSignature, len(plan.Targets))
	for i, target := range plan.Targets {
		signature := ed25519.Sign(ed25519.PrivateKey(componentKey.PrivateKey), target.Message[:])
		signatures[i] = signerapi.ComponentSignature{
			TargetIndex:     target.TargetIndex,
			Signature:       hex.EncodeToString(signature),
			SignatureScheme: keytypes.AttestorComponentEd25519V1,
		}
	}

	return &ComponentSignResult{
		RequestID:    plan.RequestID,
		ComponentKey: componentKey.ComponentKeyID,
		Signatures:   signatures,
	}, nil
}

func loadAttestorComponentKey(ctx context.Context, session componentKeyGetter, componentKeyID string) (*coresigning.KeyMaterial, *coresigning.ComponentKeyMaterial, *ServiceError) {
	keyMaterial, err := session.GetKeyWithContext(ctx, componentKeyID)
	if err != nil {
		switch {
		case errors.Is(err, keystore.ErrStoreLocked):
			return nil, nil, forbidden("signer is locked")
		case errors.Is(err, keystore.ErrKeyNotFound):
			return nil, nil, badRequest(fmt.Sprintf("component key %q not found", componentKeyID))
		default:
			return nil, nil, internal(fmt.Sprintf("failed to load component key: %v", err))
		}
	}
	if keyMaterial == nil {
		return nil, nil, internal("loaded component key material is nil")
	}
	if keyMaterial.Type != keytypes.AttestorComponentEd25519V1 {
		gotType := keyMaterial.Type
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, nil, badRequest(fmt.Sprintf("key %q is %s, not %s", componentKeyID, gotType, keytypes.AttestorComponentEd25519V1))
	}
	if keyMaterial.Category != "" && keyMaterial.Category != keys.CategoryComponent {
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, nil, badRequest(fmt.Sprintf("key %q is not a component key", componentKeyID))
	}
	componentKey, ok := keyMaterial.Value.(*coresigning.ComponentKeyMaterial)
	if !ok || componentKey == nil {
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, nil, internal("loaded attestor component key has invalid material")
	}
	if componentKey.ComponentKeyID != componentKeyID {
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, nil, internal("loaded component key handle does not match requested component key")
	}
	if len(componentKey.PrivateKey) != ed25519.PrivateKeySize {
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, nil, internal(fmt.Sprintf("loaded attestor component key has private key length %d", len(componentKey.PrivateKey)))
	}
	if len(componentKey.PublicKey) != ed25519.PublicKeySize {
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, nil, internal(fmt.Sprintf("loaded attestor component key has public key length %d", len(componentKey.PublicKey)))
	}
	derivedPublicKey, ok := ed25519.PrivateKey(componentKey.PrivateKey).Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(derivedPublicKey, componentKey.PublicKey) {
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, nil, internal("loaded attestor component key public key does not match private key")
	}
	return keyMaterial, componentKey, nil
}
