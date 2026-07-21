// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package helpersign owns cryptographic operations used only by apbounded-admin.
package helpersign

import (
	"encoding/hex"
	"fmt"

	"github.com/algorandfoundation/falcon-signatures/falcongo"
	boundedauthorization "github.com/aplane-algo/aplane/internal/boundedadmin/authorization"
	boundedprotocol "github.com/aplane-algo/aplane/internal/boundedadmin/protocol"
	apcrypto "github.com/aplane-algo/aplane/internal/crypto"
	sentryverify "github.com/aplane-algo/aplane/internal/sentry/verify"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/internal/witness/artifact"
)

const falcon1024PrivateKeySize = 2305

// Sign validates the signer partial inside the helper process and returns only
// the external Falcon contract-admin signature.
func Sign(request boundedprotocol.Request, credential *artifact.Credential) (boundedprotocol.Response, *boundedauthorization.ValidatedRequest, error) {
	validated, err := boundedauthorization.ValidateRequest(request)
	if err != nil {
		return boundedprotocol.Response{}, nil, err
	}
	if credential == nil {
		return boundedprotocol.Response{}, nil, fmt.Errorf("contract-admin credential is required")
	}
	metadata := request.Payload.Partial.Authorization
	if credential.WitnessKeyID != metadata.ContractAdminKeyID || credential.PublicKeyHex != metadata.PublicKeyHex {
		return boundedprotocol.Response{}, nil, fmt.Errorf("contract-admin artifact does not match bounded authorization account")
	}
	if err := witness.RequireCapability(witness.CustodianOfflineCeremony, witness.DomainBoundedAdmin); err != nil {
		return boundedprotocol.Response{}, nil, err
	}

	signature, err := signMessage(credential, validated.Message[:])
	if err != nil {
		return boundedprotocol.Response{}, nil, err
	}
	defer apcrypto.ZeroBytes(signature)
	if err := sentryverify.VerifyFalcon1024(validated.PublicKey, validated.Message[:], signature); err != nil {
		return boundedprotocol.Response{}, nil, fmt.Errorf("verify generated contract-admin signature: %w", err)
	}
	return boundedprotocol.Response{
		Schema: boundedprotocol.ResponseSchemaV1, RequestHashHex: request.RequestHashHex,
		ContractAdminKeyID: metadata.ContractAdminKeyID,
		SignatureHex:       hex.EncodeToString(signature),
	}, validated, nil
}

func signMessage(credential *artifact.Credential, message []byte) ([]byte, error) {
	if len(credential.PrivateMaterial) != falcon1024PrivateKeySize {
		return nil, fmt.Errorf("Falcon-1024 private material length %d invalid", len(credential.PrivateMaterial))
	}
	var privateKey falcongo.PrivateKey
	copy(privateKey[:], credential.PrivateMaterial)
	defer apcrypto.ZeroBytes(privateKey[:])
	keyPair := falcongo.KeyPair{PrivateKey: privateKey}
	defer apcrypto.ZeroBytes(keyPair.PrivateKey[:])
	signature, err := keyPair.Sign(message)
	if err != nil {
		return nil, fmt.Errorf("Falcon-1024 signing failed: %w", err)
	}
	return signature, nil
}
