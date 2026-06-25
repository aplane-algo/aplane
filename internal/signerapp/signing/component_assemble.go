// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/merklewhitelist"
	"github.com/aplane-algo/aplane/internal/sentry/canonical"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/sentry/message"
	sentryverify "github.com/aplane-algo/aplane/internal/sentry/verify"
	"github.com/aplane-algo/aplane/internal/signerapi"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/lsig/corridor"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	falcon1024guarded "github.com/aplane-algo/aplane/lsig/falcon1024_guarded"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func assembleDecodedGuarded(ctx context.Context, req signerapi.GuardedAssemblyRequest, group *canonical.Group, session componentKeyGetter) (*GuardedAssemblyResult, *ServiceError) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, canceledSignRequest(err)
	}
	if group == nil {
		return nil, internal("guarded assembly group is nil")
	}
	if err := req.Validate(); err != nil {
		return nil, badRequest(err.Error())
	}
	req.RequestID = guardedRequestID("asm", req.RequestID)
	if len(group.Entries) != len(req.GroupBytesHex) {
		return nil, internal("guarded assembly group length does not match request")
	}
	if session == nil {
		return nil, internal("key session is nil")
	}

	signedGroup := make([]string, len(group.Entries))
	for _, target := range req.Targets {
		signedTxnHex, err := assembleGuardedTarget(ctx, target, group.Entries[target.TargetIndex], session)
		if err != nil {
			return nil, err
		}
		signedGroup[target.TargetIndex] = signedTxnHex
	}
	for _, passthrough := range req.Passthrough {
		signedTxnHex, err := validateGuardedPassthrough(ctx, passthrough, group.Entries[passthrough.TargetIndex], session)
		if err != nil {
			return nil, err
		}
		signedGroup[passthrough.TargetIndex] = signedTxnHex
	}

	return &GuardedAssemblyResult{
		RequestID:   req.RequestID,
		SignedGroup: signedGroup,
	}, nil
}

func assembleGuardedTarget(ctx context.Context, target signerapi.GuardedAssemblyTarget, entry canonical.Txn, session componentKeyGetter) (string, *ServiceError) {
	keyMaterial, err := loadGuardedAccountKeyMaterial(ctx, session, target.GuardedAccount)
	if err != nil {
		return "", err
	}
	defer zeroLoadedKeyMaterial(keyMaterial)

	if keyMaterial.SigningMetadataVersion == 0 {
		return "", missingLogicSigSigningMetadata(keyMaterial.Type)
	}
	if len(keyMaterial.Bytecode) == 0 {
		return "", internal("loaded guarded account key is missing LogicSig bytecode")
	}
	if len(keyMaterial.PublicKey) != family.PublicKeySize {
		return "", internal(fmt.Sprintf("loaded guarded account key has public key length %d", len(keyMaterial.PublicKey)))
	}
	sentryComponentKeyType, ok := keytypes.SentryComponentKeyTypeForGuardedAccount(keyMaterial.Type)
	if !ok {
		return "", internal(fmt.Sprintf("loaded guarded account key type %s has no sentry key type", keyMaterial.Type))
	}
	sentryPublicKey, err := guardedAccountSentryPublicKey(keyMaterial.Parameters, sentryComponentKeyType)
	if err != nil {
		return "", err
	}

	userSignature, err := decodeAssemblySignatureHex(target.UserSignature, "user_signature")
	if err != nil {
		return "", err
	}
	defer crypto.ZeroBytes(userSignature)
	sentrySignature, err := decodeAssemblySignatureHex(target.SentrySignature, "sentry_signature")
	if err != nil {
		return "", err
	}
	defer crypto.ZeroBytes(sentrySignature)

	userMessage := message.ComponentMessage(message.RoleUser, entry.TxID)
	if verifyErr := sentryverify.VerifyFalcon1024(keyMaterial.PublicKey, userMessage[:], userSignature); verifyErr != nil {
		return "", badRequest(fmt.Sprintf("target index %d user_signature invalid: %v", target.TargetIndex, verifyErr))
	}
	sentryMessage := message.ComponentMessage(message.RoleSentry, entry.TxID)
	if verifyErr := verifySentryAssemblySignature(sentryComponentKeyType, sentryPublicKey, sentryMessage[:], sentrySignature); verifyErr != nil {
		return "", badRequest(fmt.Sprintf("target index %d sentry_signature invalid: %v", target.TargetIndex, verifyErr))
	}

	packedSignature, packErr := packGuardedComponentSignatures(keyMaterial.Type, userSignature, sentrySignature)
	if packErr != nil {
		return "", badRequest(fmt.Sprintf("target index %d signatures invalid: %v", target.TargetIndex, packErr))
	}
	defer crypto.ZeroBytes(packedSignature)

	signatureProvider := lsigprovider.Get(keyMaterial.Type)
	if signatureProvider == nil {
		return "", internal(fmt.Sprintf("provider not found for guarded account key type %s", keyMaterial.Type))
	}
	signatureArgs, buildErr := signatureProvider.BuildArgs(packedSignature, nil)
	if buildErr != nil {
		return "", badRequest(fmt.Sprintf("target index %d signatures invalid: %v", target.TargetIndex, buildErr))
	}
	providerArgs, err := guardedAssemblyProviderArgs(target, entry, keyMaterial)
	if err != nil {
		return "", err
	}
	runtimeArgs, err := orderedAssemblyRuntimeArgs(target, keyMaterial.SigningArgs)
	if err != nil {
		return "", err
	}

	lsigArgs := make([][]byte, 0, len(signatureArgs)+len(providerArgs)+len(runtimeArgs))
	lsigArgs = append(lsigArgs, signatureArgs...)
	lsigArgs = append(lsigArgs, providerArgs...)
	lsigArgs = append(lsigArgs, runtimeArgs...)
	lsigAcct := algocrypto.LogicSigAccount{
		Lsig: types.LogicSig{
			Logic: keyMaterial.Bytecode,
			Args:  lsigArgs,
		},
	}
	lsigAddress, addressErr := lsigAcct.Address()
	if addressErr != nil {
		return "", internal(fmt.Sprintf("failed to derive guarded LogicSig address: %v", addressErr))
	}
	if lsigAddress.String() != target.GuardedAccount {
		return "", internal(fmt.Sprintf("loaded guarded account bytecode address %s does not match key %s", lsigAddress.String(), target.GuardedAccount))
	}

	_, signedTxnBytes, signErr := algocrypto.SignLogicSigAccountTransaction(lsigAcct, entry.Txn)
	if signErr != nil {
		return "", internal(fmt.Sprintf("failed to assemble guarded LogicSig transaction: %v", signErr))
	}
	if err := validateAssembledGuardedTarget(target, entry, signedTxnBytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(signedTxnBytes), nil
}

func validateAssembledGuardedTarget(target signerapi.GuardedAssemblyTarget, entry canonical.Txn, signedTxnBytes []byte) *ServiceError {
	var stxn types.SignedTxn
	if err := msgpack.Decode(signedTxnBytes, &stxn); err != nil {
		return internal(fmt.Sprintf("failed to decode assembled guarded transaction: %v", err))
	}
	txID := algocrypto.TransactionID(stxn.Txn)
	if !bytes.Equal(txID, entry.TxID[:]) {
		return internal(fmt.Sprintf("assembled guarded transaction at index %d does not match canonical transaction", target.TargetIndex))
	}
	if entry.Txn.Sender.String() != target.GuardedAccount && stxn.AuthAddr.String() != target.GuardedAccount {
		return internal(fmt.Sprintf(
			"assembled guarded transaction at index %d auth address %q does not match guarded_account %q",
			target.TargetIndex,
			stxn.AuthAddr.String(),
			target.GuardedAccount,
		))
	}
	return nil
}

func packGuardedComponentSignatures(keyType string, userSignature, sentrySignature []byte) ([]byte, error) {
	if keyType == keytypes.CorridorV1 {
		return corridor.PackComponentSignatures(userSignature, sentrySignature)
	}
	return falcon1024guarded.PackComponentSignaturesForKeyType(keyType, userSignature, sentrySignature)
}

func guardedAssemblyProviderArgs(target signerapi.GuardedAssemblyTarget, entry canonical.Txn, keyMaterial *coresigning.KeyMaterial) ([][]byte, *ServiceError) {
	if keyMaterial == nil || keyMaterial.Type != keytypes.CorridorV1 {
		return nil, nil
	}
	proof, err := corridorProofArg(entry.Txn, keyMaterial.Parameters)
	if err != nil {
		return nil, badRequest(fmt.Sprintf("target index %d corridor proof generation failed: %v", target.TargetIndex, err))
	}
	if len(proof) == 0 {
		return nil, nil
	}
	return [][]byte{proof}, nil
}

func corridorProofArg(txn types.Transaction, params map[string]string) ([]byte, error) {
	if params == nil || strings.TrimSpace(params[corridor.ParamRecipients]) == "" {
		return nil, fmt.Errorf("corridor key file missing recipients parameter")
	}
	if !txn.RekeyTo.IsZero() {
		return corridorRekeyProofArg(txn)
	}

	var receiver types.Address
	switch txn.Type {
	case types.PaymentTx:
		receiver = txn.Receiver
	case types.AssetTransferTx:
		receiver = txn.AssetReceiver
	default:
		return nil, fmt.Errorf("corridor only supports pay and axfer targets, got %s", txn.Type)
	}
	if receiver == txn.Sender {
		return nil, nil
	}
	return merklewhitelist.ProofForAddressParam(params[corridor.ParamRecipients], receiver)
}

func corridorRekeyProofArg(txn types.Transaction) ([]byte, error) {
	if txn.Type != types.PaymentTx {
		return nil, fmt.Errorf("corridor rekey targets must be payment transactions")
	}
	if txn.Amount != 0 {
		return nil, fmt.Errorf("corridor rekey targets must transfer 0 microalgos")
	}
	if txn.Receiver != txn.Sender {
		return nil, fmt.Errorf("corridor rekey targets must be self-payments")
	}
	if !txn.CloseRemainderTo.IsZero() {
		return nil, fmt.Errorf("corridor rekey targets must not close remainder")
	}
	return nil, nil
}

func validateGuardedPassthrough(ctx context.Context, passthrough signerapi.GuardedPassthroughItem, entry canonical.Txn, session componentKeyGetter) (string, *ServiceError) {
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
	// A guarded account this signer holds must be authorized through the
	// component+assembly flow (user + sentry signatures), never slipped in as a
	// passthrough that bypasses that verification. Reject if the passthrough's
	// effective signer is a locally-held guarded account.
	if err := rejectLocalGuardedPassthrough(ctx, stxn, passthrough.TargetIndex, session); err != nil {
		return "", err
	}
	// A passthrough slot must carry a real signature: the signer contributes no
	// authority of its own, so an unsigned SignedTxn{Txn:...} would assemble a
	// group leg nobody authorized. Reject any blank-signature passthrough.
	if !signedTxnHasSignature(stxn) {
		return "", badRequest(fmt.Sprintf("passthrough index %d signed transaction carries no signature", passthrough.TargetIndex))
	}
	// Enforce canonical encoding on the forwarded bytes, matching the canonical
	// round-trip the transport already applies to component targets. Re-encode
	// and require equality so a non-canonical SignedTxn cannot be submitted, and
	// return the canonical bytes.
	reencoded := msgpack.Encode(stxn)
	if !bytes.Equal(reencoded, signedTxnBytes) {
		return "", badRequest(fmt.Sprintf("passthrough index %d signed transaction bytes are not canonical", passthrough.TargetIndex))
	}
	return hex.EncodeToString(reencoded), nil
}

// rejectLocalGuardedPassthrough rejects a passthrough whose effective signer
// (sender, or AuthAddr when rekeyed) is a guarded account this signer holds:
// such an account must be authorized through component signing and assembly,
// not forwarded as an already-signed passthrough. Accounts this signer does
// not hold (the common passthrough case) are left alone.
func rejectLocalGuardedPassthrough(ctx context.Context, stxn types.SignedTxn, targetIndex int, session componentKeyGetter) *ServiceError {
	var zero types.Address
	candidates := []types.Address{stxn.Txn.Sender}
	if stxn.AuthAddr != zero {
		candidates = append(candidates, stxn.AuthAddr)
	}
	for _, addr := range candidates {
		if addr == zero {
			continue
		}
		km, err := session.GetKeyWithContext(ctx, addr.String())
		if err != nil {
			// Only a genuine not-found means this is a foreign passthrough. Any
			// other error (locked session, decrypt/storage failure) must fail
			// closed: treating it as "not held" would let a guarded account slip
			// through as passthrough during exactly the conditions this check
			// guards against.
			if errors.Is(err, keystore.ErrKeyNotFound) {
				continue
			}
			return internal(fmt.Sprintf("passthrough index %d: failed to resolve key for %s: %v", targetIndex, addr.String(), err))
		}
		if km == nil {
			continue // not held by this signer — a legitimate foreign passthrough
		}
		if keytypes.IsGuardedAccountKeyType(km.Type) {
			return badRequest(fmt.Sprintf("passthrough index %d is a guarded account; it must be signed through component assembly, not passthrough", targetIndex))
		}
	}
	return nil
}

// signedTxnHasSignature reports whether a SignedTxn carries any signature: a
// bare ed25519 signature, a LogicSig, or a multisig. An unsigned
// SignedTxn{Txn:...} has all three blank.
func signedTxnHasSignature(stxn types.SignedTxn) bool {
	if stxn.Sig != (types.Signature{}) {
		return true
	}
	if len(stxn.Lsig.Logic) > 0 {
		return true
	}
	if !stxn.Msig.Blank() {
		return true
	}
	return false
}

func verifySentryAssemblySignature(componentKeyType string, publicKey, msg, signature []byte) error {
	switch componentKeyType {
	case keytypes.SentryComponentEd25519V1:
		return sentryverify.VerifyEd25519(publicKey, msg, signature)
	case keytypes.SentryComponentFalcon1024V1:
		return sentryverify.VerifyFalcon1024(publicKey, msg, signature)
	default:
		return fmt.Errorf("key type %q is not a sentry key type", componentKeyType)
	}
}

func guardedAccountSentryPublicKey(parameters map[string]string, componentKeyType string) ([]byte, *ServiceError) {
	if parameters == nil {
		return nil, internal("loaded guarded account key is missing creation parameters")
	}
	value := parameters[keytypes.ParameterSentryPublicKey]
	if strings.TrimSpace(value) == "" {
		return nil, internal("loaded guarded account key is missing sentry_public_key parameter")
	}
	publicKeySize, ok := keytypes.ComponentPublicKeySize(componentKeyType)
	if !ok {
		return nil, internal(fmt.Sprintf("key type %q is not a sentry key type", componentKeyType))
	}
	publicKey, err := decodeHexBytes(value, publicKeySize, keytypes.ParameterSentryPublicKey)
	if err != nil {
		return nil, internal(err.Error())
	}
	return publicKey, nil
}

func orderedAssemblyRuntimeArgs(target signerapi.GuardedAssemblyTarget, signingArgs []lsigprovider.RuntimeArgDef) ([][]byte, *ServiceError) {
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
