// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	algocrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/merkleallowlist"
	"github.com/aplane-algo/aplane/internal/signerapi"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
	falconsignerops "github.com/aplane-algo/aplane/internal/signing/falcon1024/signerops"
	"github.com/aplane-algo/aplane/internal/txnutil"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/aplane-algo/aplane/internal/productmode"
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

func (e *Executor) ExecuteGroupSigning(ctx context.Context, plan *PlanResult, req signerapi.GroupSignRequest, session *keystore.KeySession) (*ExecuteResult, *ServiceError) {
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
			req.Requests[i].LsigArgs, planBoundedItem(plan, i), session, ctx,
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
		signedDummyBytes, err := coresigning.SignDummyTransactions(allTxns[len(txns):])
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

func (e *Executor) signSingleTransaction(txn types.Transaction, authAddr, txnSender string, lsigArgs map[string]string, boundedItem *boundedPlanItem, session *keystore.KeySession, ctx context.Context) (signedBytes []byte, keyType string, err *ServiceError) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, "", canceledSignRequest(err)
	}
	keyMaterial, loadErr := session.GetKeyWithContext(ctx, authAddr)
	if loadErr != nil {
		if e.AuditLog != nil {
			e.AuditLog.LogSignFailed(productmode.IdentityID, authAddr, txnSender, fmt.Sprintf("failed to load key: %v", loadErr))
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
	if err := verifyBoundedPlanIntegrity(boundedItem, keyMaterial); err != nil {
		keyType := keyMaterial.Type
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, keyType, err
	}
	if keyMaterial.BoundedAuthorization != nil && keyMaterial.BoundedAuthorization.Sentry != nil {
		keyType := keyMaterial.Type
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, keyType, boundedSentryRequired()
	}

	if isGenericKeyMaterial(keyMaterial) {
		return e.signGenericLSig(txn, authAddr, txnSender, lsigArgs, keyMaterial)
	}

	return e.signCryptoKey(txn, authAddr, txnSender, lsigArgs, boundedItem, keyMaterial)
}

// planBoundedItem returns the planner's bounded classification for request slot
// i, or nil for non-bounded slots.
func planBoundedItem(plan *PlanResult, i int) *boundedPlanItem {
	if plan == nil || i < 0 || i >= len(plan.BoundedItems) {
		return nil
	}
	return plan.BoundedItems[i]
}

// verifyBoundedPlanIntegrity is the executor's single bounded recheck. The
// authoritative classification ran once at the plan boundary against snapshot
// metadata and the finalized transactions; the executor signs those same
// transaction objects, so the only state that can drift before signing is the
// key file reloaded here. Requiring the loaded metadata to equal the planned
// metadata makes re-deriving the classification unnecessary: equal inputs
// give an equal path.
func verifyBoundedPlanIntegrity(item *boundedPlanItem, keyMaterial *coresigning.KeyMaterial) *ServiceError {
	metadata := keyMaterial.BoundedAuthorization
	if item == nil {
		if metadata != nil {
			return internal("key gained bounded metadata after planning; retry the request")
		}
		return nil
	}
	if metadata == nil {
		return internal("key lost bounded metadata after planning; retry the request")
	}
	if keyMaterial.SigningMetadataVersion != keys.BoundedSigningMetadataVersion {
		return internal(fmt.Sprintf("bounded1 key requires signing metadata version %d", keys.BoundedSigningMetadataVersion))
	}
	if !item.Metadata.Equal(metadata) {
		return internal("bounded metadata changed after planning; retry the request")
	}
	return nil
}

func canceledSignRequest(err error) *ServiceError {
	return unavailable(fmt.Sprintf("sign request canceled: %v", err))
}

func (e *Executor) signGenericLSig(txn types.Transaction, authAddr, txnSender string, lsigArgs map[string]string, keyMaterial *coresigning.KeyMaterial) ([]byte, string, *ServiceError) {
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
			e.AuditLog.LogSignFailed(productmode.IdentityID, authAddr, txnSender, fmt.Sprintf("generic lsig sign failed: %v", err))
		}
		return nil, keyType, internal(fmt.Sprintf("failed to sign: %v", err))
	}

	return signedTxnBytes, keyType, nil
}

func (e *Executor) signCryptoKey(txn types.Transaction, authAddr, txnSender string, lsigArgs map[string]string, boundedItem *boundedPlanItem, keyMaterial *coresigning.KeyMaterial) ([]byte, string, *ServiceError) {
	keyType := keyMaterial.Type

	if err := rejectSentrySignKeyType(keyType); err != nil {
		defer zeroLoadedKeyMaterial(keyMaterial)
		return nil, keyType, err
	}
	// Plan integrity was verified by the caller; the plan item's path is the
	// authoritative classification. Admin-key rekeys never sign here.
	if boundedItem != nil && boundedItem.Path == boundedPathAdminKeyRekey {
		defer zeroLoadedKeyMaterial(keyMaterial)
		return nil, keyType, boundedAdminRequired()
	}

	provider := coresigning.GetProviderForKey(keyType, keyMaterial.BaseKeyType)
	defer zeroLoadedKeyMaterial(keyMaterial)
	if provider == nil {
		return nil, keyType, internal(fmt.Sprintf("unsupported key type: %s", keyType))
	}

	if keyMaterial.Bytecode == nil {
		if transactionAuthorizer, ok := provider.(coresigning.TransactionAuthorizer); ok {
			if keyType != nativefalcon.KeyType {
				return nil, keyType, internal(fmt.Sprintf("key type %s unexpectedly implements structured transaction authorization", keyType))
			}
			authorizer, err := types.DecodeAddress(authAddr)
			if err != nil {
				if e.AuditLog != nil {
					e.AuditLog.LogSignFailed(productmode.IdentityID, authAddr, txnSender, fmt.Sprintf("invalid auth address: %v", err))
				}
				return nil, keyType, badRequest(fmt.Sprintf("invalid auth address %q: %v", authAddr, err))
			}
			stxn, err := transactionAuthorizer.AuthorizeTransaction(keyMaterial, txn, authorizer)
			if err != nil {
				if e.AuditLog != nil {
					e.AuditLog.LogSignFailed(productmode.IdentityID, authAddr, txnSender, fmt.Sprintf("structured sign failed: %v", err))
				}
				return nil, keyType, internal(fmt.Sprintf("failed to sign: %v", err))
			}
			if err := falconsignerops.ValidateTransaction(stxn, txn, authorizer); err != nil {
				return nil, keyType, internal(fmt.Sprintf("provider returned invalid authorization: %v", err))
			}
			encoded := msgpack.Encode(stxn)
			var decoded types.SignedTxn
			if err := msgpack.Decode(encoded, &decoded); err != nil {
				return nil, keyType, internal(fmt.Sprintf("failed to decode assembled authorization: %v", err))
			}
			if reencoded := msgpack.Encode(decoded); !bytes.Equal(reencoded, encoded) {
				return nil, keyType, internal("assembled authorization is not canonically encoded")
			}
			return encoded, keyType, nil
		}
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
			e.AuditLog.LogSignFailed(productmode.IdentityID, authAddr, txnSender, fmt.Sprintf("sign failed: %v", err))
		}
		return nil, keyType, internal(fmt.Sprintf("failed to sign: %v", err))
	}

	if keyMaterial.Bytecode != nil {
		return e.assembleDSALogicSig(txn, authAddr, txnSender, lsigArgs, boundedItem, keyMaterial, sig, keyType)
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
				e.AuditLog.LogSignFailed(productmode.IdentityID, authAddr, txnSender, fmt.Sprintf("invalid auth address: %v", err))
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
	provider := coresigning.GetProviderForKey(key.Type, key.BaseKeyType)
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
	key.BoundedAuthorization = nil
}

func zeroGeneratedArgs(args [][]byte) {
	for _, arg := range args {
		algocrypto.ZeroBytes(arg)
	}
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
	case *coresigning.WitnessKeyMaterial:
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

func (e *Executor) assembleDSALogicSig(txn types.Transaction, authAddr, txnSender string, lsigArgs map[string]string, boundedItem *boundedPlanItem, keyMaterial *coresigning.KeyMaterial, sig []byte, keyType string) ([]byte, string, *ServiceError) {
	if keyMaterial.SigningMetadataVersion == 0 {
		return nil, keyType, missingLogicSigSigningMetadata(keyType)
	}

	return e.assembleDSALogicSigFromKeyMetadata(txn, authAddr, txnSender, lsigArgs, boundedItem, keyMaterial, sig, keyType)
}

func missingLogicSigSigningMetadata(keyType string) *ServiceError {
	return internal(fmt.Sprintf("logic sig key %s is missing signing metadata; regenerate the key or restore from a current-format backup", keyType))
}

func (e *Executor) assembleDSALogicSigFromKeyMetadata(txn types.Transaction, authAddr, txnSender string, lsigArgs map[string]string, boundedItem *boundedPlanItem, keyMaterial *coresigning.KeyMaterial, sig []byte, keyType string) ([]byte, string, *ServiceError) {
	baseKeyType := keyMaterial.BaseKeyType
	if baseKeyType == "" {
		baseKeyType = keyType
	}

	signatureProvider := lsigprovider.Get(baseKeyType)
	if signatureProvider == nil {
		return nil, keyType, internal(fmt.Sprintf("provider not found for base key type %s", baseKeyType))
	}

	signatureArgs, err := signatureProvider.BuildArgs(sig, nil)
	if err != nil {
		return nil, keyType, badRequest(err.Error())
	}
	if keyMaterial.BoundedAuthorization != nil {
		return e.assembleBoundedLogicSig(txn, authAddr, txnSender, boundedItem, keyMaterial, signatureArgs, keyType)
	}

	decodedArgs, err := e.DecodeRuntimeArgs(lsigArgs)
	if err != nil {
		return nil, keyType, badRequest(err.Error())
	}
	runtimeArgs, err := lsigprovider.ValidateAndOrderArgs(keyMaterial.SigningArgs, decodedArgs)
	if err != nil {
		return nil, keyType, badRequest(err.Error())
	}

	lsigArgBytes := make([][]byte, 0, len(signatureArgs)+len(runtimeArgs))
	lsigArgBytes = append(lsigArgBytes, signatureArgs...)
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
			e.AuditLog.LogSignFailed(productmode.IdentityID, authAddr, txnSender, fmt.Sprintf("lsig assembly failed: %v", err))
		}
		return nil, keyType, internal(fmt.Sprintf("failed to assemble lsig txn: %v", err))
	}

	return signedTxnBytes, keyType, nil
}

// assembleBoundedLogicSig assembles the spend-path bounded LogicSig. Policy
// checks (classification, fee ceiling, caller-args validation, admin-path
// routing) ran at the plan boundary and were rechecked against the loaded key
// via verifyBoundedPlanIntegrity; only assembly-shape enforcement remains here.
func (e *Executor) assembleBoundedLogicSig(txn types.Transaction, authAddr, txnSender string, item *boundedPlanItem, keyMaterial *coresigning.KeyMaterial, signatureArgs [][]byte, keyType string) ([]byte, string, *ServiceError) {
	metadata := keyMaterial.BoundedAuthorization
	if item == nil {
		return nil, keyType, internal("bounded LogicSig assembly is missing its planned path")
	}
	layout := metadata.BaseSignatureArgLayout
	if len(signatureArgs) != layout.Count {
		return nil, keyType, internal(fmt.Sprintf("base provider emitted %d signature args, stored bounded layout requires %d", len(signatureArgs), layout.Count))
	}
	for i, arg := range signatureArgs {
		if len(arg) == 0 || len(arg) > layout.MaxSizes[i] {
			return nil, keyType, internal(fmt.Sprintf("base signature arg %d length %d violates stored bounded maximum %d", i, len(arg), layout.MaxSizes[i]))
		}
	}

	derivedArgs, deriveErr := boundedDerivedArgs(txn, keyMaterial, metadata, item.Path)
	if deriveErr != nil {
		return nil, keyType, deriveErr
	}
	defer zeroGeneratedArgs(derivedArgs)
	args, assemblyErr := assembleBoundedArgs(metadata, item, signatureArgs, derivedArgs)
	if assemblyErr != nil {
		return nil, keyType, assemblyErr
	}

	lsigAcct := crypto.LogicSigAccount{
		Lsig: types.LogicSig{Logic: keyMaterial.Bytecode, Args: args},
	}
	_, signedTxnBytes, err := crypto.SignLogicSigAccountTransaction(lsigAcct, txn)
	if err != nil {
		if e.AuditLog != nil {
			e.AuditLog.LogSignFailed(productmode.IdentityID, authAddr, txnSender, fmt.Sprintf("bounded lsig assembly failed: %v", err))
		}
		return nil, keyType, internal(fmt.Sprintf("failed to assemble bounded lsig txn: %v", err))
	}
	return signedTxnBytes, keyType, nil
}

func boundedDerivedArgs(txn types.Transaction, keyMaterial *coresigning.KeyMaterial, metadata *boundedmeta.Metadata, path boundedPath) ([][]byte, *ServiceError) {
	values := make([][]byte, len(metadata.DerivedArgs))
	if path != boundedPathPureSpend {
		return values, nil
	}
	for i, arg := range metadata.DerivedArgs {
		if arg.Kind != boundedmeta.DerivedArgMerkleProof {
			return nil, internal(fmt.Sprintf("unsupported bounded derived argument kind %q", arg.Kind))
		}
		var receiver types.Address
		switch txn.Type {
		case types.PaymentTx:
			receiver = txn.Receiver
		case types.AssetTransferTx:
			receiver = txn.AssetReceiver
		default:
			return nil, internal(fmt.Sprintf("bounded Merkle proof requested for transaction type %q", txn.Type))
		}
		if receiver == txn.Sender {
			continue
		}
		recipients := keyMaterial.Parameters[arg.Parameter]
		if recipients == "" {
			return nil, internal(fmt.Sprintf("bounded key file is missing derived argument parameter %q", arg.Parameter))
		}
		proof, err := merkleallowlist.ProofForAddressParam(recipients, receiver)
		if err != nil {
			return nil, badRequest(fmt.Sprintf("bounded Merkle proof generation failed: %v", err))
		}
		values[i] = proof
	}
	return values, nil
}

func assembleBoundedArgs(metadata *boundedmeta.Metadata, item *boundedPlanItem, baseArgs, derivedArgs [][]byte) ([][]byte, *ServiceError) {
	return assembleBoundedArgsWithSentry(metadata, item, baseArgs, derivedArgs, nil)
}

func assembleBoundedArgsWithSentry(metadata *boundedmeta.Metadata, item *boundedPlanItem, baseArgs, derivedArgs [][]byte, sentrySignature []byte) ([][]byte, *ServiceError) {
	args := make([][]byte, len(metadata.ArgumentLayout))
	baseIndex, derivedIndex := 0, 0
	for _, slot := range metadata.ArgumentLayout {
		var value []byte
		switch slot.Source {
		case boundedmeta.ArgSourceBaseSignature:
			if baseIndex >= len(baseArgs) {
				return nil, internal("bounded base signature slot count changed during assembly")
			}
			value = baseArgs[baseIndex]
			baseIndex++
		case boundedmeta.ArgSourceDerived:
			if derivedIndex >= len(derivedArgs) {
				return nil, internal("bounded derived slot count changed during assembly")
			}
			value = derivedArgs[derivedIndex]
			derivedIndex++
		case boundedmeta.ArgSourceRuntime:
			value = item.RuntimeArgs[slot.Name]
		case boundedmeta.ArgSourceSentry:
			value = sentrySignature
		case boundedmeta.ArgSourceAdmin:
			value = nil
		default:
			return nil, internal(fmt.Sprintf("unsupported bounded argument source %q", slot.Source))
		}
		rule := boundedSlotRule(slot, item.Path)
		if rule == boundedmeta.ArgRequired && len(value) == 0 {
			return nil, internal(fmt.Sprintf("required bounded argument slot %q is empty during assembly", slot.Name))
		}
		if rule == boundedmeta.ArgForbidden && len(value) != 0 {
			return nil, internal(fmt.Sprintf("forbidden bounded argument slot %q is populated during assembly", slot.Name))
		}
		if len(value) > slot.MaxSize {
			return nil, internal(fmt.Sprintf("bounded argument slot %q exceeds its stored maximum", slot.Name))
		}
		if value == nil {
			value = []byte{}
		}
		args[slot.Index] = value
	}
	if baseIndex != len(baseArgs) {
		return nil, internal("bounded base signature arguments were not fully consumed during assembly")
	}
	if derivedIndex != len(derivedArgs) {
		return nil, internal("bounded derived arguments were not fully consumed during assembly")
	}
	for len(args) > 0 && len(args[len(args)-1]) == 0 {
		args = args[:len(args)-1]
	}
	return args, nil
}

func isGenericKeyMaterial(keyMaterial *coresigning.KeyMaterial) bool {
	if keyMaterial == nil {
		return false
	}
	return keys.IsGenericKey(keyMaterial.Category)
}
