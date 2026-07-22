// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	boundedmessage "github.com/aplane-algo/aplane/internal/boundedadmin/message"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/sentry/verify"
	"github.com/aplane-algo/aplane/internal/signerapi"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
)

type BoundedAdminResult struct {
	Operation     string
	Transactions  []string
	PartialSigned []string
	TargetIndex   int
	Authorization signerapi.BoundedAdminMetadata
	Mutations     *signerapi.MutationReport
}

func validateBoundedAdminPlan(request signerapi.BoundedAdminRequest, plan *PlanResult) (int, *boundedPlanItem, *ServiceError) {
	if request.Operation != signerapi.BoundedAdminOperationRekey {
		return 0, nil, badRequest(fmt.Sprintf("unsupported bounded-admin operation %q", request.Operation))
	}
	if len(request.Requests) != 1 {
		return 0, nil, badRequest("bounded-admin v1 requires exactly one transaction")
	}
	mode, err := request.Requests[0].Mode()
	if err != nil {
		return 0, nil, badRequest(err.Error())
	}
	if mode != signerapi.RequestModeSign {
		return 0, nil, badRequest("bounded-admin v1 requires one locally signable transaction")
	}
	if len(request.Requests[0].LsigArgs) != 0 {
		return 0, nil, badRequest("bounded-admin does not accept caller LogicSig arguments")
	}
	if plan == nil || len(plan.AllTxns) < 1 || len(plan.BoundedItems) < 1 || plan.BoundedItems[0] == nil || plan.BoundedItems[0].Path != boundedPathAdminKeyRekey {
		return 0, nil, badRequest("transaction 1 is not an admin-key-authorized bounded rekey")
	}
	if len(plan.BoundedItems[0].SpendingPublicKey) != boundedmeta.FalconAdminPublicKeySize {
		return 0, nil, badRequest("bounded-admin v1 requires a Falcon-1024 spending base")
	}
	return 0, plan.BoundedItems[0], nil
}

func (e *Executor) ExecuteBoundedAdminPartial(ctx context.Context, plan *PlanResult, req signerapi.GroupSignRequest, identityID string, session *keystore.KeySession, targetIndex int, item *boundedPlanItem) ([]string, *ServiceError) {
	if targetIndex < 0 || targetIndex >= len(req.Requests) || targetIndex >= len(plan.AllTxns) || item == nil {
		return nil, internal("bounded-admin target index is invalid")
	}
	txn := plan.AllTxns[targetIndex]
	keyMaterial, loadErr := session.GetKeyWithContext(ctx, req.Requests[targetIndex].AuthAddress)
	if loadErr != nil {
		return nil, internal(fmt.Sprintf("failed to load bounded spending key: %v", loadErr))
	}
	defer zeroLoadedKeyMaterial(keyMaterial)
	// validateBoundedAdminPlan pinned the plan item to the admin-key rekey
	// path; the integrity recheck extends that classification to the freshly
	// loaded key without re-deriving it.
	if err := verifyBoundedPlanIntegrity(item, keyMaterial); err != nil {
		return nil, err
	}
	if item.Path != boundedPathAdminKeyRekey {
		return nil, badRequest("loaded key does not authorize this bounded-admin operation")
	}
	provider := coresigning.GetProviderForKey(keyMaterial.Type, keyMaterial.BaseKeyType)
	if provider == nil {
		return nil, internal(fmt.Sprintf("unsupported bounded spending key type %s", keyMaterial.Type))
	}
	txID := algocrypto.TransactionID(txn)
	signature, err := provider.SignMessage(keyMaterial, txID[:])
	if err != nil {
		return nil, internal(fmt.Sprintf("failed to sign bounded-admin spending partial: %v", err))
	}
	defer zeroGeneratedArgs([][]byte{signature})
	baseProvider := lsigprovider.Get(keyMaterial.BaseKeyType)
	if baseProvider == nil {
		return nil, internal(fmt.Sprintf("provider not found for base key type %s", keyMaterial.BaseKeyType))
	}
	args, err := baseProvider.BuildArgs(signature, nil)
	if err != nil {
		return nil, internal(fmt.Sprintf("pack bounded spending signature: %v", err))
	}
	defer zeroGeneratedArgs(args)
	layout := keyMaterial.BoundedAuthorization.BaseSignatureArgLayout
	if len(args) != layout.Count {
		return nil, internal("base provider argument count does not match bounded metadata")
	}
	for i, arg := range args {
		if len(arg) == 0 || len(arg) > layout.MaxSizes[i] {
			return nil, internal(fmt.Sprintf("base signature arg %d violates bounded metadata", i))
		}
	}
	if len(args) != 1 || verify.VerifyFalcon1024(keyMaterial.PublicKey, txID[:], args[0]) != nil {
		return nil, internal("generated bounded spending signature failed verification")
	}
	lsigAccount := algocrypto.LogicSigAccount{Lsig: types.LogicSig{Logic: keyMaterial.Bytecode, Args: args}}
	_, signedBytes, err := algocrypto.SignLogicSigAccountTransaction(lsigAccount, txn)
	if err != nil {
		return nil, internal(fmt.Sprintf("assemble bounded-admin partial: %v", err))
	}
	var signed types.SignedTxn
	if err := msgpack.Decode(signedBytes, &signed); err != nil {
		return nil, internal(fmt.Sprintf("decode bounded-admin partial: %v", err))
	}
	if len(signed.Lsig.Args) != layout.Count || !bytes.Equal(algocrypto.TransactionID(signed.Txn), txID) {
		return nil, internal("bounded-admin partial does not match finalized transaction or base layout")
	}
	partials := make([]string, len(plan.AllTxns))
	partials[targetIndex] = hex.EncodeToString(signedBytes)
	return partials, nil
}

func buildBoundedAdminResult(plan *PlanResult, requestCount, targetIndex int, item *boundedPlanItem, partials []string) (*BoundedAdminResult, *ServiceError) {
	transactions := make([]string, len(plan.AllTxns))
	for i, txn := range plan.AllTxns {
		transactions[i] = txnutil.EncodeWithPrefixHex(txn)
	}
	metadata := item.Metadata
	binding, err := hex.DecodeString(metadata.ProgramBindingHex)
	if err != nil || len(binding) != boundedmeta.ProgramBindingSize {
		return nil, internal("stored bounded program binding is invalid")
	}
	txID := algocrypto.TransactionID(plan.AllTxns[targetIndex])
	message, err := boundedmessage.AdminMessage(boundedmessage.OperationRekey, binding, txID[:])
	if err != nil {
		return nil, internal(fmt.Sprintf("build contract-admin transcript: %v", err))
	}
	authorization := signerapi.BoundedAdminMetadata{
		ContractAdminKeyID:     metadata.AdminKeyID,
		PublicKeyHex:           metadata.AdminPublicKeyHex,
		SpendingPublicKeyHex:   hex.EncodeToString(item.SpendingPublicKey),
		ProgramBindingHex:      metadata.ProgramBindingHex,
		TransactionID:          algocrypto.TransactionIDString(plan.AllTxns[targetIndex]),
		MessageHex:             hex.EncodeToString(message[:]),
		BaseSignatureArgCount:  metadata.BaseSignatureArgLayout.Count,
		AdminSignatureArgIndex: metadata.ArgumentLayout[len(metadata.ArgumentLayout)-1].Index,
		SpendEffects:           append([]string(nil), metadata.SpendEffects...),
		MaxFee:                 metadata.MaxFee,
	}
	if metadata.Sentry != nil {
		for _, slot := range metadata.ArgumentLayout {
			if slot.Source == boundedmeta.ArgSourceSentry {
				authorization.Sentry = &signerapi.BoundedAdminSentryMetadata{
					ComponentKeyType:  metadata.Sentry.ComponentKeyType,
					PublicKeyHex:      metadata.Sentry.PublicKeyHex,
					ComponentKeyID:    metadata.Sentry.ComponentKeyID,
					SignatureArgIndex: slot.Index,
				}
				break
			}
		}
		if authorization.Sentry == nil {
			return nil, internal("stored bounded sentry argument slot is missing")
		}
	}
	return &BoundedAdminResult{
		Operation:     signerapi.BoundedAdminOperationRekey,
		Transactions:  transactions,
		PartialSigned: partials,
		TargetIndex:   targetIndex,
		Authorization: authorization,
		Mutations:     BuildMutationReport(plan, requestCount),
	}, nil
}
