// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/sentry/canonical"
	"github.com/aplane-algo/aplane/internal/sentry/message"
	sentryverify "github.com/aplane-algo/aplane/internal/sentry/verify"
	"github.com/aplane-algo/aplane/internal/signerapi"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
)

const boundedAssemblyReceiptDomain = "APLANE_BOUNDED_SENTRY_ASSEMBLY_V1"

func validateBoundedComponentPlan(req signerapi.ComponentRequest, plan *PlanResult) ([]int, *ServiceError) {
	if plan == nil || len(plan.BoundedItems) < len(req.GroupSignRequest().Requests) {
		return nil, internal("bounded component plan is incomplete")
	}
	if plan.HasPassthrough {
		return nil, badRequest("bounded-base component signing does not accept signed passthrough entries")
	}
	targets := make([]int, 0)
	for _, target := range req.Targets {
		i := target.TargetIndex
		item := plan.BoundedItems[i]
		if item == nil || item.Metadata == nil || item.Metadata.Sentry == nil {
			return nil, badRequest(fmt.Sprintf("transaction %d is not a sentry-enabled bounded account", i+1))
		}
		if item.Path != boundedPathPureSpend {
			return nil, badRequest(fmt.Sprintf("transaction %d is not an admitted bounded spend", i+1))
		}
		targets = append(targets, i)
	}
	if len(targets) == 0 {
		return nil, badRequest("bounded-base component signing requires at least one sentry-enabled bounded target")
	}
	return targets, nil
}

func (s *Service) PrepareBoundedComponentWithContext(ctx context.Context, identityID string, req signerapi.ComponentRequest, session *keystore.KeySession) (*signerapi.ComponentResponse, *ServiceError) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.Planner == nil || s.Approval == nil || s.Executor == nil {
		return nil, internal("signing service not fully configured")
	}
	if session == nil {
		return nil, internal("key session is nil")
	}
	plan, groupReq, err := s.ValidateFrozenComponentContext(identityID, req)
	if err != nil {
		return nil, err
	}
	targets, validationErr := validateBoundedComponentPlan(req, plan)
	if validationErr != nil {
		return nil, validationErr
	}
	policyRuleID, release, gateErr := s.approveGroupWithPlanContext(ctx, identityID, groupReq, plan)
	if gateErr != nil {
		return nil, gateErr
	}
	defer release()
	req.RequestID = guardedRequestID("bcmp", req.RequestID)
	components := make([]signerapi.Component, 0, len(targets))
	for _, targetIndex := range targets {
		component, signErr := signBoundedBaseComponent(ctx, groupReq, plan, targetIndex, session)
		if signErr != nil {
			return nil, signErr
		}
		components = append(components, component)
	}
	s.logBoundedComponentsApproved(identityID, req, plan, targets, policyRuleID)
	consoleOf(s.Console).Printf("[GROUP] Prepared %d bounded-sentry base component(s)\n", len(components))
	return &signerapi.ComponentResponse{RequestID: req.RequestID, Components: components}, nil
}

func (s *Service) logBoundedComponentsApproved(identityID string, req signerapi.ComponentRequest, plan *PlanResult, targets []int, policyRuleID string) {
	if s.AuditLog == nil || plan == nil {
		return
	}
	groupReq := req.GroupSignRequest()
	for _, index := range targets {
		if index < 0 || index >= len(groupReq.Requests) || index >= len(plan.AllTxns) {
			continue
		}
		txReq := groupReq.Requests[index]
		const details = "bounded-sentry base component released after policy and operator approval"
		if policyRuleID != "" {
			if logger, ok := s.AuditLog.(AuditApprovePolicyRuleLogger); ok && logger != nil {
				logger.LogSignApprovedWithPolicyRule(identityID, txReq.AuthAddress, plan.AllTxns[index].Sender.String(), details, policyRuleID)
				continue
			}
		}
		s.AuditLog.LogSignApproved(identityID, txReq.AuthAddress, plan.AllTxns[index].Sender.String(), details)
	}
}

func signBoundedBaseComponent(ctx context.Context, req signerapi.GroupSignRequest, plan *PlanResult, targetIndex int, session componentKeyGetter) (signerapi.Component, *ServiceError) {
	item := plan.BoundedItems[targetIndex]
	account := req.Requests[targetIndex].AuthAddress
	keyMaterial, loadErr := loadBoundedKeyMaterial(ctx, session, account, "bounded spending key")
	if loadErr != nil {
		return signerapi.Component{}, loadErr
	}
	defer zeroLoadedKeyMaterial(keyMaterial)
	if integrityErr := verifyBoundedPlanIntegrity(item, keyMaterial); integrityErr != nil {
		return signerapi.Component{}, integrityErr
	}
	if keyMaterial.BoundedAuthorization == nil || keyMaterial.BoundedAuthorization.Sentry == nil || item.Path != boundedPathPureSpend {
		return signerapi.Component{}, badRequest("loaded key does not authorize bounded-sentry component signing")
	}
	provider := coresigning.GetProviderForKey(keyMaterial.Type, keyMaterial.BaseKeyType)
	baseProvider := lsigprovider.Get(keyMaterial.BaseKeyType)
	if provider == nil || baseProvider == nil {
		return signerapi.Component{}, internal("bounded base signing provider is unavailable")
	}
	txID := algocrypto.TransactionID(plan.AllTxns[targetIndex])
	signature, signErr := provider.SignMessage(keyMaterial, txID[:])
	if signErr != nil {
		return signerapi.Component{}, internal(fmt.Sprintf("failed to sign bounded base component: %v", signErr))
	}
	defer crypto.ZeroBytes(signature)
	baseArgs, packErr := baseProvider.BuildArgs(signature, nil)
	if packErr != nil {
		return signerapi.Component{}, internal(fmt.Sprintf("pack bounded base component: %v", packErr))
	}
	defer zeroGeneratedArgs(baseArgs)
	if err := validateBoundedBaseArgs(keyMaterial, txID[:], baseArgs); err != nil {
		return signerapi.Component{}, err
	}
	receiptMessage, receiptErr := boundedAssemblyReceiptMessage(account, txID[:], item.Metadata, item.RuntimeArgs)
	if receiptErr != nil {
		return signerapi.Component{}, internal(fmt.Sprintf("build bounded assembly receipt: %v", receiptErr))
	}
	receipt, receiptSignErr := provider.SignMessage(keyMaterial, receiptMessage[:])
	if receiptSignErr != nil {
		return signerapi.Component{}, internal(fmt.Sprintf("sign bounded assembly receipt: %v", receiptSignErr))
	}
	defer crypto.ZeroBytes(receipt)
	component := signerapi.Component{
		TargetIndex: targetIndex, Kind: signerapi.ComponentTargetKindBoundedBase,
		AuthAddress: account, RuntimeArgs: encodeRuntimeArgs(item.RuntimeArgs),
		AssemblyReceipt: hex.EncodeToString(receipt), SignatureScheme: keyMaterial.BaseKeyType,
	}
	for _, arg := range baseArgs {
		component.BaseSignatures = append(component.BaseSignatures, hex.EncodeToString(arg))
	}
	return component, nil
}

func validateBoundedBaseArgs(keyMaterial *coresigning.KeyMaterial, messageBytes []byte, args [][]byte) *ServiceError {
	layout := keyMaterial.BoundedAuthorization.BaseSignatureArgLayout
	if len(args) != layout.Count {
		return internal("base provider argument count does not match bounded metadata")
	}
	for i, arg := range args {
		if len(arg) == 0 || len(arg) > layout.MaxSizes[i] {
			return internal(fmt.Sprintf("base signature arg %d violates bounded metadata", i))
		}
	}
	if len(args) != 1 || sentryverify.VerifyFalcon1024(keyMaterial.PublicKey, messageBytes, args[0]) != nil {
		return internal("generated bounded base component failed verification")
	}
	return nil
}

func loadBoundedKeyMaterial(ctx context.Context, session componentKeyGetter, account, label string) (*coresigning.KeyMaterial, *ServiceError) {
	keyMaterial, err := session.GetKeyWithContext(ctx, account)
	if err != nil {
		switch {
		case errors.Is(err, keystore.ErrStoreLocked):
			return nil, lockedError()
		case errors.Is(err, keystore.ErrKeyNotFound):
			return nil, badRequest(fmt.Sprintf("%s %q not found", label, account))
		default:
			return nil, internal(fmt.Sprintf("failed to load %s: %v", label, err))
		}
	}
	if keyMaterial == nil {
		return nil, internal(fmt.Sprintf("loaded %s material is nil", label))
	}
	return keyMaterial, nil
}

func assembleBoundedTarget(ctx context.Context, target signerapi.AssemblyTarget, entry canonical.Txn, session componentKeyGetter) (string, *ServiceError) {
	keyMaterial, loadErr := loadBoundedKeyMaterial(ctx, session, target.AuthAddress, "bounded account key")
	if loadErr != nil {
		return "", loadErr
	}
	defer zeroLoadedKeyMaterial(keyMaterial)
	metadata := keyMaterial.BoundedAuthorization
	if metadata == nil || metadata.Sentry == nil {
		return "", badRequest(fmt.Sprintf("target index %d is not a sentry-enabled bounded account", target.TargetIndex))
	}
	path, classifyErr := classifyBoundedPath(entry.Txn, metadata)
	if classifyErr != nil {
		return "", withTransactionIndex(target.TargetIndex, classifyErr)
	}
	if path != boundedPathPureSpend {
		return "", badRequest(fmt.Sprintf("target index %d is not an admitted bounded spend", target.TargetIndex))
	}
	runtimeArgs, runtimeErr := validateBoundedRuntimeArgs(target.BoundedRuntimeArgs, metadata, path)
	if runtimeErr != nil {
		return "", withTransactionIndex(target.TargetIndex, runtimeErr)
	}
	baseArgs, decodeErr := decodeBoundedBaseArgs(target, metadata)
	if decodeErr != nil {
		return "", decodeErr
	}
	defer zeroGeneratedArgs(baseArgs)
	if err := validateBoundedBaseArgs(keyMaterial, entry.TxID[:], baseArgs); err != nil {
		return "", badRequest(fmt.Sprintf("target index %d base signatures are invalid", target.TargetIndex))
	}
	receipt, decodeReceiptErr := decodeAssemblySignatureHex(target.AssemblyReceipt, "assembly_receipt")
	if decodeReceiptErr != nil {
		return "", decodeReceiptErr
	}
	defer crypto.ZeroBytes(receipt)
	receiptMessage, receiptErr := boundedAssemblyReceiptMessage(target.AuthAddress, entry.TxID[:], metadata, runtimeArgs)
	if receiptErr != nil || sentryverify.VerifyFalcon1024(keyMaterial.PublicKey, receiptMessage[:], receipt) != nil {
		return "", badRequest(fmt.Sprintf("target index %d assembly receipt is invalid or stale", target.TargetIndex))
	}
	sentrySignature, sentryErr := decodeAssemblySignatureHex(target.SentrySignature, "sentry_signature")
	if sentryErr != nil {
		return "", sentryErr
	}
	defer crypto.ZeroBytes(sentrySignature)
	sentryPublicKey, publicKeyErr := hex.DecodeString(metadata.Sentry.PublicKeyHex)
	if publicKeyErr != nil {
		return "", internal("stored bounded sentry public key is invalid")
	}
	sentryMessage := message.ComponentMessage(message.RoleSentry, entry.TxID)
	if err := verifySentryAssemblySignature(metadata.Sentry.ComponentKeyType, sentryPublicKey, sentryMessage[:], sentrySignature); err != nil {
		return "", badRequest(fmt.Sprintf("target index %d sentry_signature invalid: %v", target.TargetIndex, err))
	}
	item := &boundedPlanItem{Path: path, Metadata: metadata, RuntimeArgs: runtimeArgs, SpendingPublicKey: keyMaterial.PublicKey}
	derivedArgs, deriveErr := boundedDerivedArgs(entry.Txn, keyMaterial, metadata, path)
	if deriveErr != nil {
		return "", deriveErr
	}
	defer zeroGeneratedArgs(derivedArgs)
	args, argsErr := assembleBoundedArgsWithSentry(metadata, item, baseArgs, derivedArgs, sentrySignature)
	if argsErr != nil {
		return "", argsErr
	}
	lsigAccount := algocrypto.LogicSigAccount{Lsig: types.LogicSig{Logic: keyMaterial.Bytecode, Args: args}}
	address, addressErr := lsigAccount.Address()
	if addressErr != nil || address.String() != target.AuthAddress {
		return "", internal(fmt.Sprintf("loaded bounded program does not match account %s", target.AuthAddress))
	}
	_, signedBytes, signErr := algocrypto.SignLogicSigAccountTransaction(lsigAccount, entry.Txn)
	if signErr != nil {
		return "", internal(fmt.Sprintf("failed to assemble bounded-sentry transaction: %v", signErr))
	}
	if validateErr := validateAssembledBoundedTarget(target, entry, signedBytes); validateErr != nil {
		return "", validateErr
	}
	return hex.EncodeToString(signedBytes), nil
}

func decodeBoundedBaseArgs(target signerapi.AssemblyTarget, metadata *boundedmeta.Metadata) ([][]byte, *ServiceError) {
	if len(target.BaseSignatures) != metadata.BaseSignatureArgLayout.Count {
		return nil, badRequest(fmt.Sprintf("target index %d base signature count does not match stored layout", target.TargetIndex))
	}
	args := make([][]byte, len(target.BaseSignatures))
	for i, value := range target.BaseSignatures {
		arg, err := decodeAssemblySignatureHex(value, fmt.Sprintf("base_signatures[%d]", i))
		if err != nil {
			zeroGeneratedArgs(args)
			return nil, err
		}
		args[i] = arg
	}
	return args, nil
}

func validateAssembledBoundedTarget(target signerapi.AssemblyTarget, entry canonical.Txn, signedBytes []byte) *ServiceError {
	var signed types.SignedTxn
	if err := msgpack.Decode(signedBytes, &signed); err != nil {
		return internal(fmt.Sprintf("failed to decode assembled bounded transaction: %v", err))
	}
	if !bytes.Equal(algocrypto.TransactionID(signed.Txn), entry.TxID[:]) {
		return internal(fmt.Sprintf("assembled bounded transaction at index %d does not match canonical transaction", target.TargetIndex))
	}
	if entry.Txn.Sender.String() != target.AuthAddress && signed.AuthAddr.String() != target.AuthAddress {
		return internal(fmt.Sprintf("assembled bounded transaction at index %d does not bind bounded account %s", target.TargetIndex, target.AuthAddress))
	}
	return nil
}

func boundedAssemblyReceiptMessage(account string, txID []byte, metadata *boundedmeta.Metadata, runtimeArgs map[string][]byte) ([32]byte, error) {
	metadataJSON, err := json.Marshal(boundedmeta.Clone(metadata))
	if err != nil {
		return [32]byte{}, err
	}
	var transcript bytes.Buffer
	writeReceiptField(&transcript, []byte(boundedAssemblyReceiptDomain))
	writeReceiptField(&transcript, []byte(account))
	writeReceiptField(&transcript, txID)
	metadataHash := sha512.Sum512_256(metadataJSON)
	writeReceiptField(&transcript, metadataHash[:])
	names := make([]string, 0, len(runtimeArgs))
	for name := range runtimeArgs {
		names = append(names, name)
	}
	sort.Strings(names)
	_ = binary.Write(&transcript, binary.BigEndian, uint32(len(names)))
	for _, name := range names {
		writeReceiptField(&transcript, []byte(name))
		writeReceiptField(&transcript, runtimeArgs[name])
	}
	return sha512.Sum512_256(transcript.Bytes()), nil
}

func writeReceiptField(dst *bytes.Buffer, value []byte) {
	_ = binary.Write(dst, binary.BigEndian, uint32(len(value)))
	_, _ = dst.Write(value)
}

func encodeRuntimeArgs(args map[string][]byte) map[string]string {
	if len(args) == 0 {
		return nil
	}
	out := make(map[string]string, len(args))
	for name, value := range args {
		out[name] = hex.EncodeToString(value)
	}
	return out
}
