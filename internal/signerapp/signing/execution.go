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
	"github.com/aplane-algo/aplane/internal/rekeylist"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
	falconsignerops "github.com/aplane-algo/aplane/internal/signing/falcon1024/signerops"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/pkg/signerapi"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

type AuditFailLogger interface {
	LogSignFailed(authAddress, txnSender, reason string)
}

type signFailureEntry struct {
	authAddress string
	txnSender   string
	reason      string
}

type bufferedFailLogger struct {
	entries []signFailureEntry
}

func (b *bufferedFailLogger) LogSignFailed(authAddress, txnSender, reason string) {
	b.entries = append(b.entries, signFailureEntry{
		authAddress: authAddress,
		txnSender:   txnSender,
		reason:      reason,
	})
}

func (b *bufferedFailLogger) flush(dst AuditFailLogger) {
	if b == nil || dst == nil {
		return
	}
	for _, entry := range b.entries {
		dst.LogSignFailed(entry.authAddress, entry.txnSender, entry.reason)
	}
}

// decodeHexRuntimeArgs decodes a request's hex runtime arguments by name.
func decodeHexRuntimeArgs(lsigArgs map[string]string) (map[string][]byte, error) {
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
	AuditLog AuditFailLogger
	Console  Console
}

type ExecuteResult struct {
	SignedTxns []string
}

func (e *Executor) ExecuteGroupSigning(ctx context.Context, plan *PlanResult, req signerapi.GroupSignRequest, session *keystore.KeySession) (*ExecuteResult, *ServiceError) {
	res, failures, err := e.executeGroupSigning(ctx, plan, req, session)
	failures.flush(e.AuditLog)
	return res, err
}

// executeGroupSigning runs group signing without writing to e.AuditLog while
// loaded key material or a caller's key-use window is active; callers flush
// the returned failures only after releasing their key use.
func (e *Executor) executeGroupSigning(ctx context.Context, plan *PlanResult, req signerapi.GroupSignRequest, session *keystore.KeySession) (*ExecuteResult, *bufferedFailLogger, *ServiceError) {
	failures := &bufferedFailLogger{}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, failures, canceledSignRequest(err)
	}
	console := consoleOf(e.Console)
	inner := &Executor{AuditLog: failures, Console: e.Console}
	allTxns := plan.AllTxns
	txns := allTxns[:len(req.Requests)]
	signedTxns := make([]string, len(allTxns))

	for i := 0; i < len(txns); i++ {
		if err := ctx.Err(); err != nil {
			return nil, failures, canceledSignRequest(err)
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
		// Layered on purpose. The planner refuses these key types, but the
		// frozen-component and rotating plans are built by hand, and this is
		// the last refusal before a key loads should one ever reach here.
		if i < len(plan.AuthKeyTypes) {
			if msg, ok := cosignerSignRejectMessage(plan.AuthKeyTypes[i]); ok {
				return nil, failures, badRequest(fmt.Sprintf("transaction %d: %s", i+1, msg))
			}
			if err := rejectRotatingKeyType(i, plan.AuthKeyTypes[i]); err != nil {
				return nil, failures, err
			}
		}
		signedBytes, keyType, signErr := inner.signSingleTransaction(
			allTxns[i], req.Requests[i].AuthAddress, txnSender,
			req.Requests[i].LsigArgs, plan.boundedItem(i), session, ctx,
		)
		if signErr != nil {
			// Forbidden and locked describe the whole request, not one slot,
			// so they keep their message without a per-transaction prefix.
			if signErr.Kind == ErrorForbidden || signErr.Kind == ErrorLocked {
				return nil, failures, signErr
			}
			return nil, failures, &ServiceError{Kind: signErr.Kind, Message: fmt.Sprintf("transaction %d: %s", i+1, signErr.Message)}
		}
		signedTxns[i] = hex.EncodeToString(signedBytes)
		console.Printf("  [%d] signed (%s)\n", i+1, keyType)
	}

	if len(plan.DummyTxns) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, failures, canceledSignRequest(err)
		}
		signedDummyBytes, err := coresigning.SignDummyTransactions(allTxns[len(txns):])
		if err != nil {
			return nil, failures, internal(fmt.Sprintf("failed to sign dummy transactions: %v", err))
		}
		for i, stxnBytes := range signedDummyBytes {
			signedTxns[len(txns)+i] = hex.EncodeToString(stxnBytes)
			console.Printf("  [%d] signed (dummy)\n", len(txns)+i+1)
		}
	}

	return &ExecuteResult{SignedTxns: signedTxns}, failures, nil
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
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, "", canceledSignRequest(ctxErr)
		}
		if e.AuditLog != nil {
			e.AuditLog.LogSignFailed(authAddr, txnSender, fmt.Sprintf("failed to load key: %v", loadErr))
		}
		if errors.Is(loadErr, keystore.ErrStoreLocked) {
			return nil, "", lockedError()
		}
		return nil, "", internal(fmt.Sprintf("failed to load key: %v", loadErr))
	}
	// Every exit from here zeroes the loaded key. The results are set before
	// a deferred call runs, so the key type returned is the loaded key's.
	defer zeroLoadedKeyMaterial(keyMaterial)
	if err := ctx.Err(); err != nil {
		return nil, "", canceledSignRequest(err)
	}
	if err := rejectCosignerSignKeyType(keyMaterial.Type); err != nil {
		return nil, keyMaterial.Type, err
	}
	if rotatingkey.IsRotatingKeyType(keyMaterial.Type) {
		return nil, keyMaterial.Type, rotatingSigningRequired()
	}
	if err := verifyBoundedPlanIntegrity(boundedItem, keyMaterial); err != nil {
		return nil, keyMaterial.Type, err
	}
	if keyMaterial.BoundedAuthorization != nil && keyMaterial.BoundedAuthorization.Cosigner != nil {
		return nil, keyMaterial.Type, boundedCosignerRequired()
	}

	if isGenericKeyMaterial(keyMaterial) {
		return e.signGenericLSig(txn, authAddr, txnSender, lsigArgs, keyMaterial)
	}

	return e.signCryptoKey(txn, authAddr, txnSender, lsigArgs, boundedItem, keyMaterial)
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
	decodedArgs, err := decodeHexRuntimeArgs(lsigArgs)
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
			e.AuditLog.LogSignFailed(authAddr, txnSender, fmt.Sprintf("generic lsig sign failed: %v", err))
		}
		return nil, keyType, internal(fmt.Sprintf("failed to sign: %v", err))
	}

	return signedTxnBytes, keyType, nil
}

func (e *Executor) signCryptoKey(txn types.Transaction, authAddr, txnSender string, lsigArgs map[string]string, boundedItem *boundedPlanItem, keyMaterial *coresigning.KeyMaterial) ([]byte, string, *ServiceError) {
	keyType := keyMaterial.Type
	provider := coresigning.GetProviderForKey(keyType, keyMaterial.BaseKeyType)
	if provider == nil {
		return nil, keyType, internal(fmt.Sprintf("unsupported key type: %s", keyType))
	}

	if keyMaterial.Bytecode == nil {
		if transactionAuthorizer, ok := provider.(coresigning.TransactionAuthorizer); ok {
			return e.authorizeStructured(transactionAuthorizer, txn, authAddr, txnSender, keyMaterial)
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
			e.AuditLog.LogSignFailed(authAddr, txnSender, fmt.Sprintf("sign failed: %v", err))
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
				e.AuditLog.LogSignFailed(authAddr, txnSender, fmt.Sprintf("invalid auth address: %v", err))
			}
			return nil, keyType, badRequest(fmt.Sprintf("invalid auth address %q: %v", authAddr, err))
		}
		stxn.AuthAddr = authAddrDecoded
	}
	return msgpack.Encode(stxn), keyType, nil
}

// authorizeStructured signs with a provider that returns the whole signed
// transaction, which only native Falcon does, and checks what came back: it
// must authorize this transaction for this authorizer and be canonically
// encoded.
func (e *Executor) authorizeStructured(
	transactionAuthorizer coresigning.TransactionAuthorizer,
	txn types.Transaction,
	authAddr, txnSender string,
	keyMaterial *coresigning.KeyMaterial,
) ([]byte, string, *ServiceError) {
	keyType := keyMaterial.Type
	if keyType != nativefalcon.KeyType {
		return nil, keyType, internal(fmt.Sprintf("key type %s unexpectedly implements structured transaction authorization", keyType))
	}
	authorizer, err := types.DecodeAddress(authAddr)
	if err != nil {
		if e.AuditLog != nil {
			e.AuditLog.LogSignFailed(authAddr, txnSender, fmt.Sprintf("invalid auth address: %v", err))
		}
		return nil, keyType, badRequest(fmt.Sprintf("invalid auth address %q: %v", authAddr, err))
	}
	stxn, err := transactionAuthorizer.AuthorizeTransaction(keyMaterial, txn, authorizer)
	if err != nil {
		if e.AuditLog != nil {
			e.AuditLog.LogSignFailed(authAddr, txnSender, fmt.Sprintf("structured sign failed: %v", err))
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
	case *coresigning.RotatingKeyMaterial:
		value.Zero()
	case crypto.Account:
		algocrypto.ZeroBytes(value.PrivateKey[:])
		algocrypto.ZeroBytes(value.PublicKey[:])
	}
	key.Type = ""
	key.Value = nil
}

// assembleDSALogicSig attaches a DSA LogicSig key's signature to its program,
// through the key's base signature provider, with the key's runtime arguments
// or, for a bounded key, its stored argument layout. The key parser has
// checked the key's signing metadata version and that it names its base key
// type (keys.validateLogicSigFields).
func (e *Executor) assembleDSALogicSig(txn types.Transaction, authAddr, txnSender string, lsigArgs map[string]string, boundedItem *boundedPlanItem, keyMaterial *coresigning.KeyMaterial, sig []byte, keyType string) ([]byte, string, *ServiceError) {
	signatureProvider := lsigprovider.Get(keyMaterial.BaseKeyType)
	if signatureProvider == nil {
		return nil, keyType, internal(fmt.Sprintf("provider not found for base key type %s", keyMaterial.BaseKeyType))
	}

	signatureArgs, err := signatureProvider.BuildArgs(sig, nil)
	if err != nil {
		return nil, keyType, badRequest(err.Error())
	}
	if keyMaterial.BoundedAuthorization != nil {
		return e.assembleBoundedLogicSig(txn, authAddr, txnSender, boundedItem, keyMaterial, signatureArgs, keyType)
	}

	decodedArgs, err := decodeHexRuntimeArgs(lsigArgs)
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
			e.AuditLog.LogSignFailed(authAddr, txnSender, fmt.Sprintf("lsig assembly failed: %v", err))
		}
		return nil, keyType, internal(fmt.Sprintf("failed to assemble lsig txn: %v", err))
	}

	return signedTxnBytes, keyType, nil
}

// assembleBoundedLogicSig assembles the spend-path bounded LogicSig. Policy
// checks (classification, fee ceiling, caller-args validation) ran at the plan
// boundary and were rechecked against the loaded key via
// verifyBoundedPlanIntegrity; only assembly-shape enforcement remains here.
func (e *Executor) assembleBoundedLogicSig(txn types.Transaction, authAddr, txnSender string, item *boundedPlanItem, keyMaterial *coresigning.KeyMaterial, signatureArgs [][]byte, keyType string) ([]byte, string, *ServiceError) {
	// verifyBoundedPlanIntegrity refused a bounded key without a planned item.
	metadata := keyMaterial.BoundedAuthorization
	if err := checkBaseSignatureLayout(metadata.BaseSignatureArgLayout, signatureArgs); err != nil {
		return nil, keyType, err
	}

	derivedArgs, deriveErr := boundedDerivedArgs(txn, keyMaterial, metadata, item.Path)
	if deriveErr != nil {
		return nil, keyType, deriveErr
	}
	defer zeroDerivedArgs(derivedArgs)
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
			e.AuditLog.LogSignFailed(authAddr, txnSender, fmt.Sprintf("bounded lsig assembly failed: %v", err))
		}
		return nil, keyType, internal(fmt.Sprintf("failed to assemble bounded lsig txn: %v", err))
	}
	return signedTxnBytes, keyType, nil
}

// checkBaseSignatureLayout checks base signature arguments against a bounded
// key's stored layout: its count, and each argument non-empty and within its
// stored maximum. The slot checks at assembly do not cover this: they test
// emptiness only where a slot is required, and read the slot's own maximum.
func checkBaseSignatureLayout(layout boundedmeta.SignatureArgLayout, args [][]byte) *ServiceError {
	if len(args) != layout.Count {
		return internal(fmt.Sprintf("base provider emitted %d signature args, stored bounded layout requires %d", len(args), layout.Count))
	}
	for i, arg := range args {
		if len(arg) == 0 || len(arg) > layout.MaxSizes[i] {
			return internal(fmt.Sprintf("base signature arg %d length %d violates stored bounded maximum %d", i, len(arg), layout.MaxSizes[i]))
		}
	}
	return nil
}

// boundedDerivedArgs returns the value of every declared derived argument by
// name, empty where the path or transaction takes none. Assembly places each
// in the layout slot of the same name, so the order of the declarations and
// the layout's slots never has to agree.
func boundedDerivedArgs(txn types.Transaction, keyMaterial *coresigning.KeyMaterial, metadata *boundedmeta.Metadata, path boundedPath) (map[string][]byte, *ServiceError) {
	values := make(map[string][]byte, len(metadata.DerivedArgs))
	for _, arg := range metadata.DerivedArgs {
		values[arg.Name] = nil
	}
	if path == boundedPathListedRekey {
		return listedRekeyDerivedArgs(txn, keyMaterial, metadata, values)
	}
	if path != boundedPathPureSpend {
		return values, nil
	}
	for _, arg := range metadata.DerivedArgs {
		if arg.Kind == boundedmeta.DerivedArgRekeyListProof {
			continue
		}
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
		values[arg.Name] = proof
	}
	return values, nil
}

func zeroDerivedArgs(args map[string][]byte) {
	for _, arg := range args {
		algocrypto.ZeroBytes(arg)
	}
}

func assembleBoundedArgs(metadata *boundedmeta.Metadata, item *boundedPlanItem, baseArgs [][]byte, derivedArgs map[string][]byte) ([][]byte, *ServiceError) {
	return assembleBoundedArgsWithCosigner(metadata, item, baseArgs, derivedArgs, nil)
}

func assembleBoundedArgsWithCosigner(metadata *boundedmeta.Metadata, item *boundedPlanItem, baseArgs [][]byte, derivedArgs map[string][]byte, cosignerSignature []byte) ([][]byte, *ServiceError) {
	args := make([][]byte, len(metadata.ArgumentLayout))
	baseIndex, derivedUsed := 0, 0
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
			derived, ok := derivedArgs[slot.Name]
			if !ok {
				return nil, internal(fmt.Sprintf("bounded derived slot %q has no derived argument during assembly", slot.Name))
			}
			value = derived
			derivedUsed++
		case boundedmeta.ArgSourceRuntime:
			value = item.RuntimeArgs[slot.Name]
		case boundedmeta.ArgSourceCosigner:
			value = cosignerSignature
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
	if derivedUsed != len(derivedArgs) {
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

// listedRekeyDerivedArgs fills the list proof for a listed rekey. The proof's
// salt comes from a seed derived from the spending private key, so only the
// account's own signer can build it; the recipient proofs stay empty, since no
// rekey reaches Layer 3.
func listedRekeyDerivedArgs(txn types.Transaction, keyMaterial *coresigning.KeyMaterial, metadata *boundedmeta.Metadata, values map[string][]byte) (map[string][]byte, *ServiceError) {
	lsigKey, ok := keyMaterial.Value.(*coresigning.LsigKeyMaterial)
	if !ok || len(lsigKey.PrivateKey) == 0 {
		return nil, internal("bounded listed rekey needs the spending private key")
	}
	for _, arg := range metadata.DerivedArgs {
		if arg.Kind != boundedmeta.DerivedArgRekeyListProof {
			continue
		}
		entries, err := rekeylist.ParseEntries(keyMaterial.Parameters[arg.Parameter])
		if err != nil {
			return nil, internal(fmt.Sprintf("stored rekey-to list is invalid: %v", err))
		}
		list, err := rekeylist.FromSpendingKey(lsigKey.PrivateKey, entries)
		if err != nil {
			return nil, internal(fmt.Sprintf("rebuild rekey-to list: %v", err))
		}
		root := list.Root()
		proof, listed := list.Proof(txn.RekeyTo)
		list.Zero()
		// The proof is good only against the root the program compiled.
		if metadata.RekeyList == nil || metadata.RekeyList.RootHex != hex.EncodeToString(root[:]) {
			return nil, internal("the rebuilt rekey-to list does not match the account's stored root")
		}
		if !listed {
			return nil, &ServiceError{Kind: ErrorBoundedRekeyNotListed, Message: fmt.Sprintf("%s is not on this account's rekey-to list", txn.RekeyTo)}
		}
		values[arg.Name] = proof
	}
	return values, nil
}
