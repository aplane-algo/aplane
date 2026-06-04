// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
	"github.com/aplane-algo/aplane/internal/attestor/message"
	attestorverify "github.com/aplane-algo/aplane/internal/attestor/verify"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	falcon1024attested "github.com/aplane-algo/aplane/lsig/falcon1024_attested"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func assembleDecodedAttested(ctx context.Context, req signerapi.AttestedAssemblyRequest, group *attestorverify.CanonicalGroup, session componentKeyGetter) (*AttestedAssemblyResult, *ServiceError) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, canceledSignRequest(err)
	}
	if group == nil {
		return nil, internal("attested assembly group is nil")
	}
	if err := req.Validate(); err != nil {
		return nil, badRequest(err.Error())
	}
	if len(group.Entries) != len(req.GroupBytesHex) {
		return nil, internal("attested assembly group length does not match request")
	}
	if session == nil {
		return nil, internal("key session is nil")
	}

	signedGroup := make([]string, len(group.Entries))
	for _, target := range req.Targets {
		signedTxnHex, err := assembleAttestedTarget(ctx, target, group.Entries[target.TargetIndex], session)
		if err != nil {
			return nil, err
		}
		signedGroup[target.TargetIndex] = signedTxnHex
	}
	for _, passthrough := range req.Passthrough {
		signedTxnHex, err := validateAttestedPassthrough(passthrough, group.Entries[passthrough.TargetIndex])
		if err != nil {
			return nil, err
		}
		signedGroup[passthrough.TargetIndex] = signedTxnHex
	}

	return &AttestedAssemblyResult{
		RequestID:   req.RequestID,
		SignedGroup: signedGroup,
	}, nil
}

func assembleAttestedTarget(ctx context.Context, target signerapi.AttestedAssemblyTarget, entry attestorverify.CanonicalTxn, session componentKeyGetter) (string, *ServiceError) {
	if entry.Txn.Sender.String() != target.AttestedAccount {
		return "", badRequest(fmt.Sprintf(
			"target index %d sender %q does not match attested_account %q",
			target.TargetIndex,
			entry.Txn.Sender.String(),
			target.AttestedAccount,
		))
	}

	keyMaterial, err := loadAttestedAccountKeyMaterial(ctx, session, target.AttestedAccount)
	if err != nil {
		return "", err
	}
	defer zeroLoadedKeyMaterial(keyMaterial)

	if keyMaterial.SigningMetadataVersion == 0 {
		return "", missingLogicSigSigningMetadata(keyMaterial.Type)
	}
	if len(keyMaterial.Bytecode) == 0 {
		return "", internal("loaded attested account key is missing LogicSig bytecode")
	}
	if len(keyMaterial.PublicKey) != family.PublicKeySize {
		return "", internal(fmt.Sprintf("loaded attested account key has public key length %d", len(keyMaterial.PublicKey)))
	}
	attestorComponentKeyType, ok := keytypes.AttestorComponentKeyTypeForAttestedAccount(keyMaterial.Type)
	if !ok {
		return "", internal(fmt.Sprintf("loaded attested account key type %s has no attestor component key type", keyMaterial.Type))
	}
	attestorPublicKey, err := attestedAccountAttestorPublicKey(keyMaterial.Parameters, attestorComponentKeyType)
	if err != nil {
		return "", err
	}

	userSignature, err := decodeAssemblySignatureHex(target.UserSignature, "user_signature")
	if err != nil {
		return "", err
	}
	defer crypto.ZeroBytes(userSignature)
	attestorSignature, err := decodeAssemblySignatureHex(target.AttestorSignature, "attestor_signature")
	if err != nil {
		return "", err
	}
	defer crypto.ZeroBytes(attestorSignature)

	userMessage := message.ComponentMessage(message.RoleUser, entry.TxID)
	if verifyErr := attestorverify.VerifyFalcon1024(keyMaterial.PublicKey, userMessage[:], userSignature); verifyErr != nil {
		return "", badRequest(fmt.Sprintf("target index %d user_signature invalid: %v", target.TargetIndex, verifyErr))
	}
	attestorMessage := message.ComponentMessage(message.RoleAttestor, entry.TxID)
	if verifyErr := verifyAttestorAssemblySignature(attestorComponentKeyType, attestorPublicKey, attestorMessage[:], attestorSignature); verifyErr != nil {
		return "", badRequest(fmt.Sprintf("target index %d attestor_signature invalid: %v", target.TargetIndex, verifyErr))
	}

	packedSignature, packErr := falcon1024attested.PackComponentSignaturesForKeyType(keyMaterial.Type, userSignature, attestorSignature)
	if packErr != nil {
		return "", badRequest(fmt.Sprintf("target index %d signatures invalid: %v", target.TargetIndex, packErr))
	}
	defer crypto.ZeroBytes(packedSignature)

	signatureProvider := lsigprovider.Get(keyMaterial.Type)
	if signatureProvider == nil {
		return "", internal(fmt.Sprintf("provider not found for attested account key type %s", keyMaterial.Type))
	}
	signatureArgs, buildErr := signatureProvider.BuildArgs(packedSignature, nil)
	if buildErr != nil {
		return "", badRequest(fmt.Sprintf("target index %d signatures invalid: %v", target.TargetIndex, buildErr))
	}
	runtimeArgs, err := orderedAssemblyRuntimeArgs(target, keyMaterial.SigningArgs)
	if err != nil {
		return "", err
	}

	lsigArgs := make([][]byte, 0, len(signatureArgs)+len(runtimeArgs))
	lsigArgs = append(lsigArgs, signatureArgs...)
	lsigArgs = append(lsigArgs, runtimeArgs...)
	lsigAcct := algocrypto.LogicSigAccount{
		Lsig: types.LogicSig{
			Logic: keyMaterial.Bytecode,
			Args:  lsigArgs,
		},
	}
	lsigAddress, addressErr := lsigAcct.Address()
	if addressErr != nil {
		return "", internal(fmt.Sprintf("failed to derive attested LogicSig address: %v", addressErr))
	}
	if lsigAddress.String() != target.AttestedAccount {
		return "", internal(fmt.Sprintf("loaded attested account bytecode address %s does not match key %s", lsigAddress.String(), target.AttestedAccount))
	}

	_, signedTxnBytes, signErr := algocrypto.SignLogicSigAccountTransaction(lsigAcct, entry.Txn)
	if signErr != nil {
		return "", internal(fmt.Sprintf("failed to assemble attested LogicSig transaction: %v", signErr))
	}
	return hex.EncodeToString(signedTxnBytes), nil
}

func validateAttestedPassthrough(passthrough signerapi.AttestedPassthroughItem, entry attestorverify.CanonicalTxn) (string, *ServiceError) {
	signedTxnBytes, err := decodeAssemblySignatureHex(passthrough.SignedTxnHex, "signed_txn_hex")
	if err != nil {
		return "", err
	}

	var stxn types.SignedTxn
	if err := msgpack.Decode(signedTxnBytes, &stxn); err != nil {
		return "", badRequest(fmt.Sprintf("passthrough index %d: invalid signed transaction msgpack: %v", passthrough.TargetIndex, err))
	}
	txID := algocrypto.TransactionID(stxn.Txn)
	if !bytes.Equal(txID[:], entry.TxID[:]) {
		return "", badRequest(fmt.Sprintf("passthrough index %d signed transaction does not match group transaction", passthrough.TargetIndex))
	}
	return hex.EncodeToString(signedTxnBytes), nil
}

func verifyAttestorAssemblySignature(componentKeyType string, publicKey, msg, signature []byte) error {
	switch componentKeyType {
	case keytypes.AttestorComponentEd25519V1:
		return attestorverify.VerifyEd25519(publicKey, msg, signature)
	case keytypes.AttestorComponentFalcon1024V1:
		return attestorverify.VerifyFalcon1024(publicKey, msg, signature)
	default:
		return fmt.Errorf("key type %q is not an attestor component key type", componentKeyType)
	}
}

func attestedAccountAttestorPublicKey(parameters map[string]string, componentKeyType string) ([]byte, *ServiceError) {
	if parameters == nil {
		return nil, internal("loaded attested account key is missing creation parameters")
	}
	value := parameters[keytypes.ParameterAttestorPublicKey]
	if strings.TrimSpace(value) == "" {
		return nil, internal("loaded attested account key is missing attestor_public_key parameter")
	}
	publicKeySize, ok := keytypes.ComponentPublicKeySize(componentKeyType)
	if !ok {
		return nil, internal(fmt.Sprintf("key type %q is not an attestor component key type", componentKeyType))
	}
	publicKey, err := decodeHexBytes(value, publicKeySize, keytypes.ParameterAttestorPublicKey)
	if err != nil {
		return nil, internal(err.Error())
	}
	return publicKey, nil
}

func orderedAssemblyRuntimeArgs(target signerapi.AttestedAssemblyTarget, signingArgs []lsigprovider.RuntimeArgDef) ([][]byte, *ServiceError) {
	if len(target.RuntimeArgs) != len(signingArgs) {
		return nil, badRequest(fmt.Sprintf(
			"target index %d runtime_args length %d does not match stored signing arg count %d",
			target.TargetIndex,
			len(target.RuntimeArgs),
			len(signingArgs),
		))
	}
	if len(signingArgs) == 0 {
		return nil, nil
	}

	decodedArgs := make(map[string][]byte, len(signingArgs))
	for i, hexValue := range target.RuntimeArgs {
		value, err := decodeHexBytes(hexValue, -1, fmt.Sprintf("runtime_args[%d]", i))
		if err != nil {
			return nil, badRequest(fmt.Sprintf("target index %d %v", target.TargetIndex, err))
		}
		decodedArgs[signingArgs[i].Name] = value
	}
	ordered, err := lsigprovider.ValidateAndOrderArgs(signingArgs, decodedArgs)
	if err != nil {
		return nil, badRequest(fmt.Sprintf("target index %d runtime_args invalid: %v", target.TargetIndex, err))
	}
	return ordered, nil
}

func decodeAssemblySignatureHex(value, field string) ([]byte, *ServiceError) {
	decoded, err := decodeHexBytes(value, -1, field)
	if err != nil {
		return nil, badRequest(err.Error())
	}
	return decoded, nil
}

func decodeHexBytes(value string, wantLen int, field string) ([]byte, error) {
	raw := strings.TrimSpace(value)
	raw = strings.TrimPrefix(strings.TrimPrefix(raw, "0x"), "0X")
	decoded, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("%s must be hex: %w", field, err)
	}
	if wantLen >= 0 && len(decoded) != wantLen {
		return nil, fmt.Errorf("%s length %d invalid (expected %d bytes)", field, len(decoded), wantLen)
	}
	return decoded, nil
}
