// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	algocrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/lsig"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/merklewhitelist"
	"github.com/aplane-algo/aplane/internal/signerapi"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

type AuditFailLogger interface {
	LogSignFailed(identityID, authAddress, txnSender, reason string)
}

type DecodeRuntimeArgsFunc func(lsigArgs map[string]string) (map[string][]byte, error)

func DecodeHexRuntimeArgs(lsigArgs map[string]string) (map[string][]byte, error) {
	if len(lsigArgs) == 0 {
		return nil, nil
	}
	decoded := make(map[string][]byte, len(lsigArgs))
	for name, hexValue := range lsigArgs {
		bytes, err := hex.DecodeString(hexValue)
		if err != nil {
			return nil, fmt.Errorf("invalid hex for arg %s: %w", name, err)
		}
		decoded[name] = bytes
	}
	return decoded, nil
}

type Executor struct {
	AuditLog          AuditFailLogger
	Console           Console
	DecodeRuntimeArgs DecodeRuntimeArgsFunc
}

type ExecuteResult struct {
	SignedTxns []string
}

func (e *Executor) ExecuteGroupSigning(ctx context.Context, plan *PlanResult, req signerapi.GroupSignRequest, identityID string, session *keystore.KeySession) (*ExecuteResult, *ServiceError) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, canceledSignRequest(err)
	}
	console := consoleOf(e.Console)
	allTxns := plan.AllTxns
	txns := allTxns[:len(req.Requests)]
	signedTxns := make([]string, len(allTxns))

	for i := 0; i < len(txns); i++ {
		if err := ctx.Err(); err != nil {
			return nil, canceledSignRequest(err)
		}
		if plan.PassthroughIndices[i] {
			signedTxns[i] = hex.EncodeToString(plan.PassthroughSignedTxns[i])
			console.Printf("  [%d] passthrough (included as-is)\n", i+1)
			continue
		}
		if plan.ForeignIndices[i] {
			signedTxns[i] = ""
			console.Printf("  [%d] foreign (not signed)\n", i+1)
			continue
		}

		txnSender := txns[i].Sender.String()
		if i < len(plan.AuthKeyTypes) {
			if msg, ok := sentrySignRejectMessage(plan.AuthKeyTypes[i]); ok {
				return nil, badRequest(fmt.Sprintf("transaction %d: %s", i+1, msg))
			}
		}
		signedBytes, keyType, signErr := e.signSingleTransaction(
			allTxns[i], req.Requests[i].AuthAddress, txnSender,
			req.Requests[i].LsigArgs, session, identityID, ctx,
		)
		if signErr != nil {
			// Forbidden and locked describe the whole request, not one slot,
			// so they keep their message without a per-transaction prefix.
			if signErr.Kind == ErrorForbidden || signErr.Kind == ErrorLocked {
				return nil, signErr
			}
			return nil, &ServiceError{Kind: signErr.Kind, Message: fmt.Sprintf("transaction %d: %s", i+1, signErr.Message)}
		}
		signedTxns[i] = hex.EncodeToString(signedBytes)
		console.Printf("  [%d] signed (%s)\n", i+1, keyType)
	}

	if len(plan.DummyTxns) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, canceledSignRequest(err)
		}
		signedDummyBytes, err := lsig.SignDummyTransactions(allTxns[len(txns):])
		if err != nil {
			return nil, internal(fmt.Sprintf("failed to sign dummy transactions: %v", err))
		}
		for i, stxnBytes := range signedDummyBytes {
			signedTxns[len(txns)+i] = hex.EncodeToString(stxnBytes)
			console.Printf("  [%d] signed (dummy)\n", len(txns)+i+1)
		}
	}

	return &ExecuteResult{SignedTxns: signedTxns}, nil
}

func (e *Executor) signSingleTransaction(txn types.Transaction, authAddr, txnSender string, lsigArgs map[string]string, session *keystore.KeySession, identityID string, ctx context.Context) (signedBytes []byte, keyType string, err *ServiceError) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, "", canceledSignRequest(err)
	}
	keyMaterial, loadErr := session.GetKey(authAddr)
	if loadErr != nil {
		if e.AuditLog != nil {
			e.AuditLog.LogSignFailed(identityID, authAddr, txnSender, fmt.Sprintf("failed to load key: %v", loadErr))
		}
		if errors.Is(loadErr, keystore.ErrStoreLocked) {
			return nil, "", lockedError()
		}
		return nil, "", internal(fmt.Sprintf("failed to load key: %v", loadErr))
	}
	if err := ctx.Err(); err != nil {
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, "", canceledSignRequest(err)
	}
	if err := rejectSentrySignKeyType(keyMaterial.Type); err != nil {
		keyType := keyMaterial.Type
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, keyType, err
	}

	if isGenericKeyMaterial(keyMaterial) {
		return e.signGenericLSig(txn, authAddr, txnSender, lsigArgs, keyMaterial, identityID)
	}

	return e.signCryptoKey(txn, authAddr, txnSender, lsigArgs, keyMaterial, identityID)
}

func canceledSignRequest(err error) *ServiceError {
	return unavailable(fmt.Sprintf("sign request canceled: %v", err))
}

func (e *Executor) signGenericLSig(txn types.Transaction, authAddr, txnSender string, lsigArgs map[string]string, keyMaterial *coresigning.KeyMaterial, identityID string) ([]byte, string, *ServiceError) {
	keyType := keyMaterial.Type
	defer algocrypto.ZeroBytes(keyMaterial.Bytecode)

	if keyMaterial.SigningMetadataVersion == 0 {
		return nil, keyType, missingLogicSigSigningMetadata(keyType)
	}

	decodedArgs, err := e.DecodeRuntimeArgs(lsigArgs)
	if err != nil {
		return nil, keyType, badRequest(err.Error())
	}

	orderedArgsBytes, err := lsigprovider.ValidateAndOrderArgs(keyMaterial.SigningArgs, decodedArgs)
	if err != nil {
		return nil, keyType, badRequest(err.Error())
	}

	lsigAcct := crypto.LogicSigAccount{
		Lsig: types.LogicSig{
			Logic: keyMaterial.Bytecode,
			Args:  orderedArgsBytes,
		},
	}
	_, signedTxnBytes, err := crypto.SignLogicSigAccountTransaction(lsigAcct, txn)
	if err != nil {
		if e.AuditLog != nil {
			e.AuditLog.LogSignFailed(identityID, authAddr, txnSender, fmt.Sprintf("generic lsig sign failed: %v", err))
		}
		return nil, keyType, internal(fmt.Sprintf("failed to sign: %v", err))
	}

	return signedTxnBytes, keyType, nil
}

func (e *Executor) signCryptoKey(txn types.Transaction, authAddr, txnSender string, lsigArgs map[string]string, keyMaterial *coresigning.KeyMaterial, identityID string) ([]byte, string, *ServiceError) {
	keyType := keyMaterial.Type

	if err := rejectSentrySignKeyType(keyType); err != nil {
		defer zeroLoadedKeyMaterial(keyMaterial)
		return nil, keyType, err
	}

	provider := coresigning.GetProvider(keyType)
	if provider == nil && keyMaterial.BaseKeyType != "" {
		provider = coresigning.GetProvider(keyMaterial.BaseKeyType)
	}
	defer zeroLoadedKeyMaterial(keyMaterial)
	if provider == nil {
		return nil, keyType, internal(fmt.Sprintf("unsupported key type: %s", keyType))
	}

	var messageBytes []byte
	if keyMaterial.Bytecode != nil {
		txnID := crypto.TransactionID(txn)
		messageBytes = txnID[:]
	} else {
		messageBytes = txnutil.EncodeWithPrefix(txn)
	}

	sig, err := provider.SignMessage(keyMaterial, messageBytes)
	if err != nil {
		if e.AuditLog != nil {
			e.AuditLog.LogSignFailed(identityID, authAddr, txnSender, fmt.Sprintf("sign failed: %v", err))
		}
		return nil, keyType, internal(fmt.Sprintf("failed to sign: %v", err))
	}

	if keyMaterial.Bytecode != nil {
		return e.assembleDSALogicSig(txn, authAddr, txnSender, lsigArgs, keyMaterial, sig, keyType, identityID)
	}

	var sigArr types.Signature
	copy(sigArr[:], sig)
	stxn := types.SignedTxn{
		Txn: txn,
		Sig: sigArr,
	}
	if authAddr != txnSender && txnSender != "" {
		authAddrDecoded, err := types.DecodeAddress(authAddr)
		if err != nil {
			if e.AuditLog != nil {
				e.AuditLog.LogSignFailed(identityID, authAddr, txnSender, fmt.Sprintf("invalid auth address: %v", err))
			}
			return nil, keyType, badRequest(fmt.Sprintf("invalid auth address %q: %v", authAddr, err))
		}
		stxn.AuthAddr = authAddrDecoded
	}
	return msgpack.Encode(stxn), keyType, nil
}

func zeroLoadedKeyMaterial(key *coresigning.KeyMaterial) {
	if key == nil {
		return
	}
	provider := coresigning.GetProvider(key.Type)
	if provider == nil && key.BaseKeyType != "" {
		provider = coresigning.GetProvider(key.BaseKeyType)
	}
	if provider != nil {
		provider.ZeroKey(key)
	} else {
		zeroKeyMaterialFallback(key)
	}
	if key.Bytecode != nil {
		algocrypto.ZeroBytes(key.Bytecode)
		key.Bytecode = nil
	}
	if key.PublicKey != nil {
		algocrypto.ZeroBytes(key.PublicKey)
		key.PublicKey = nil
	}
	key.Parameters = nil
	key.SigningArgs = nil
}

func zeroKeyMaterialFallback(key *coresigning.KeyMaterial) {
	if key == nil {
		return
	}
	switch value := key.Value.(type) {
	case []byte:
		algocrypto.ZeroBytes(value)
	case *coresigning.LsigKeyMaterial:
		if value != nil {
			algocrypto.ZeroBytes(value.PrivateKey)
			value.PrivateKey = nil
		}
	case *coresigning.ComponentKeyMaterial:
		if value != nil {
			algocrypto.ZeroBytes(value.PrivateKey)
			algocrypto.ZeroBytes(value.PublicKey)
			value.PrivateKey = nil
			value.PublicKey = nil
		}
	case crypto.Account:
		algocrypto.ZeroBytes(value.PrivateKey[:])
		algocrypto.ZeroBytes(value.PublicKey[:])
	}
	key.Type = ""
	key.Value = nil
}

func (e *Executor) assembleDSALogicSig(txn types.Transaction, authAddr, txnSender string, lsigArgs map[string]string, keyMaterial *coresigning.KeyMaterial, sig []byte, keyType, identityID string) ([]byte, string, *ServiceError) {
	if keyMaterial.SigningMetadataVersion == 0 {
		return nil, keyType, missingLogicSigSigningMetadata(keyType)
	}

	return e.assembleDSALogicSigFromKeyMetadata(txn, authAddr, txnSender, lsigArgs, keyMaterial, sig, keyType, identityID)
}

func missingLogicSigSigningMetadata(keyType string) *ServiceError {
	return internal(fmt.Sprintf("logic sig key %s is missing signing metadata; regenerate the key or restore from a current-format backup", keyType))
}

func (e *Executor) assembleDSALogicSigFromKeyMetadata(txn types.Transaction, authAddr, txnSender string, lsigArgs map[string]string, keyMaterial *coresigning.KeyMaterial, sig []byte, keyType, identityID string) ([]byte, string, *ServiceError) {
	baseKeyType := keyMaterial.BaseKeyType
	if baseKeyType == "" {
		baseKeyType = keyType
	}

	decodedArgs, err := e.DecodeRuntimeArgs(lsigArgs)
	if err != nil {
		return nil, keyType, badRequest(err.Error())
	}

	signatureProvider := lsigprovider.Get(baseKeyType)
	if signatureProvider == nil {
		return nil, keyType, internal(fmt.Sprintf("provider not found for base key type %s", baseKeyType))
	}

	signatureArgs, err := signatureProvider.BuildArgs(sig, nil)
	if err != nil {
		return nil, keyType, badRequest(err.Error())
	}
	providerArgs, signArgErr := signerGeneratedDSAArgs(txn, keyMaterial)
	if signArgErr != nil {
		return nil, keyType, signArgErr
	}
	runtimeArgs, err := lsigprovider.ValidateAndOrderArgs(keyMaterial.SigningArgs, decodedArgs)
	if err != nil {
		return nil, keyType, badRequest(err.Error())
	}

	lsigArgBytes := make([][]byte, 0, len(signatureArgs)+len(providerArgs)+len(runtimeArgs))
	lsigArgBytes = append(lsigArgBytes, signatureArgs...)
	lsigArgBytes = append(lsigArgBytes, providerArgs...)
	lsigArgBytes = append(lsigArgBytes, runtimeArgs...)

	lsigAcct := crypto.LogicSigAccount{
		Lsig: types.LogicSig{
			Logic: keyMaterial.Bytecode,
			Args:  lsigArgBytes,
		},
	}
	_, signedTxnBytes, err := crypto.SignLogicSigAccountTransaction(lsigAcct, txn)
	if err != nil {
		if e.AuditLog != nil {
			e.AuditLog.LogSignFailed(identityID, authAddr, txnSender, fmt.Sprintf("lsig assembly failed: %v", err))
		}
		return nil, keyType, internal(fmt.Sprintf("failed to assemble lsig txn: %v", err))
	}

	return signedTxnBytes, keyType, nil
}

const falcon1024WhitelistV2KeyType = "aplane.falcon1024-whitelist.v2"

func signerGeneratedDSAArgs(txn types.Transaction, keyMaterial *coresigning.KeyMaterial) ([][]byte, *ServiceError) {
	if keyMaterial == nil || keyMaterial.Type != falcon1024WhitelistV2KeyType {
		return nil, nil
	}

	recipients := keyMaterial.Parameters["recipients"]
	if recipients == "" {
		return nil, internal("falcon1024-whitelist.v2 key file missing recipients parameter")
	}

	var receiver types.Address
	switch txn.Type {
	case types.PaymentTx:
		receiver = txn.Receiver
	case types.AssetTransferTx:
		receiver = txn.AssetReceiver
	default:
		return nil, nil
	}
	if receiver == txn.Sender {
		return nil, nil
	}

	proof, err := merklewhitelist.ProofForAddressParam(recipients, receiver)
	if err != nil {
		return nil, badRequest(fmt.Sprintf("falcon1024-whitelist.v2 proof generation failed: %v", err))
	}
	return [][]byte{proof}, nil
}

func isGenericKeyMaterial(keyMaterial *coresigning.KeyMaterial) bool {
	if keyMaterial == nil {
		return false
	}
	return keys.IsGenericKey(keyMaterial.Category, keyMaterial.Type)
}
