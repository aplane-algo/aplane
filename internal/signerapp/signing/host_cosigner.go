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

	"github.com/aplane-algo/aplane/internal/cosigner/canonical"
	"github.com/aplane-algo/aplane/internal/cosigner/message"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/hostmeta"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	sigverify "github.com/aplane-algo/aplane/internal/sigconstruction/verify"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

const hostAssemblyReceiptDomain = "APLANE_BOUNDED_COSIGNER_ASSEMBLY_V1"

// componentPaths names each path the cosigned flow carries, as its component
// reports it. The planner has already refused every other transaction.
var componentPaths = map[hostPath]string{
	hostPathPureSpend:        signerapi.ComponentPathSpend,
	hostPathSpendingKeyRekey: signerapi.ComponentPathSpendingRekey,
	hostPathListedRekey:      signerapi.ComponentPathListedRekey,
}

// hostPathNeedsCosigner reports whether the cosigner signs a cosigned
// account's transaction on this path. It signs every spend and every declared
// rekey; a listed rekey never asks it, since the list is the owner's standing
// statement.
func hostPathNeedsCosigner(path hostPath) bool {
	return path != hostPathListedRekey
}

func validateHostComponentPlan(req signerapi.ComponentRequest, plan *PlanResult) ([]int, *ServiceError) {
	if plan == nil || len(plan.HostItems) < len(req.GroupSignRequest().Requests) {
		return nil, internal("bounded component plan is incomplete")
	}
	if plan.HasPassthrough {
		return nil, badRequest("base component signing does not accept signed passthrough entries")
	}
	targets := make([]int, 0)
	for _, target := range req.Targets {
		i := target.TargetIndex
		item := plan.HostItems[i]
		if item == nil || item.Metadata == nil || item.Metadata.Cosigner == nil {
			return nil, badRequest(fmt.Sprintf("transaction %d is not a cosigner-enabled bounded account", i+1))
		}
		if _, ok := componentPaths[item.Path]; !ok {
			return nil, badRequest(fmt.Sprintf("transaction %d is not an admitted cosigned spend or rekey", i+1))
		}
		targets = append(targets, i)
	}
	if len(targets) == 0 {
		return nil, badRequest("base component signing requires at least one cosigner-enabled bounded target")
	}
	return targets, nil
}

func (s *Service) PrepareHostComponentWithContext(ctx context.Context, req signerapi.ComponentRequest, session *keystore.KeySession) (*signerapi.ComponentResponse, *ServiceError) {
	if ctx == nil {
		ctx = context.Background()
	}
	// The prompt is held under the request's ID and the response returns
	// it, so a direct caller that supplies none gets one for both.
	req.RequestID = RequestID(req.RequestID)
	if s.Planner == nil || s.Approval == nil || s.Executor == nil {
		return nil, internal("signing service not fully configured")
	}
	if session == nil {
		return nil, internal("key session is nil")
	}
	plan, groupReq, err := s.ValidateFrozenComponentContext(req)
	if err != nil {
		return nil, err
	}
	targets, validationErr := validateHostComponentPlan(req, plan)
	if validationErr != nil {
		return nil, validationErr
	}
	outcome, gateErr := s.approveGroupWithPlanContext(ctx, groupReq, plan)
	if gateErr != nil {
		return nil, gateErr
	}
	if bindErr := checkApprovalBinding(groupReq, plan); bindErr != nil {
		return nil, bindErr
	}
	useCtx, endKeyUse, useErr := s.openKeyUse(ctx)
	if useErr != nil {
		s.logSessionEndedAfterApproval(groupReq, plan, useErr)
		return nil, useErr
	}
	defer endKeyUse()
	components := make([]signerapi.Component, 0, len(targets))
	for _, targetIndex := range targets {
		if refused := s.keyUseRefused(ctx, useCtx); refused != nil {
			endKeyUse()
			s.logSessionEndedAfterApproval(groupReq, plan, refused)
			return nil, refused
		}
		component, signErr := signBaseComponent(useCtx, groupReq, plan, targetIndex, session)
		if signErr != nil {
			classified := s.classifyKeyUseError(ctx, useCtx, signErr)
			endKeyUse()
			s.logSessionEndedAfterApproval(groupReq, plan, classified)
			return nil, classified
		}
		components = append(components, component)
	}
	if refused := s.keyUseRefused(ctx, useCtx); refused != nil {
		endKeyUse()
		s.logSessionEndedAfterApproval(groupReq, plan, refused)
		return nil, refused
	}
	// Release the key use before blocking console or audit writes so a stalled
	// terminal or disk cannot hold a lock's drain, then recheck the session
	// before returning.
	endKeyUse()
	consoleOf(s.Console).Printf("[GROUP] Prepared %d bounded-cosigner base component(s)\n", len(components))
	records := s.logHostComponentsApproved(req, plan, targets, outcome)
	if refused := s.keyUseRefused(ctx, nil); refused != nil {
		s.logWithheldRecords(records, refused)
		return nil, refused
	}
	return &signerapi.ComponentResponse{RequestID: req.RequestID, Components: components}, nil
}

func (s *Service) logHostComponentsApproved(req signerapi.ComponentRequest, plan *PlanResult, targets []int, outcome approvalOutcome) []SignedRecord {
	if s.AuditLog == nil || plan == nil {
		return nil
	}
	groupReq := req.GroupSignRequest()
	// The group is frozen: each component signs its target's final TxID. The
	// signer never signs the group's dummies: the client signs them itself
	// and sends them as foreign positions to /sign and as passthrough to
	// /sign/assemble, so no record counts them (signerSignedDummies).
	group := auditedGroup(plan)
	records := make([]SignedRecord, 0, len(targets))
	for _, index := range targets {
		if index < 0 || index >= len(groupReq.Requests) || index >= len(plan.AllTxns) {
			continue
		}
		txReq := groupReq.Requests[index]
		const details = "bounded-cosigner base component released after policy and operator approval"
		record := group.record(index, txReq.AuthAddress, details, outcome)
		s.AuditLog.LogSignApproved(record)
		records = append(records, record)
	}
	return records
}

func signBaseComponent(ctx context.Context, req signerapi.GroupSignRequest, plan *PlanResult, targetIndex int, session componentKeyGetter) (signerapi.Component, *ServiceError) {
	item := plan.HostItems[targetIndex]
	account := req.Requests[targetIndex].AuthAddress
	keyMaterial, loadErr := loadHostKeyMaterial(ctx, session, account, "bounded spending key")
	if loadErr != nil {
		return signerapi.Component{}, loadErr
	}
	defer zeroLoadedKeyMaterial(keyMaterial)
	if err := ctx.Err(); err != nil {
		return signerapi.Component{}, canceledSignRequest(err)
	}
	if integrityErr := verifyHostPlanIntegrity(item, keyMaterial); integrityErr != nil {
		return signerapi.Component{}, integrityErr
	}
	componentPath, admitted := componentPaths[item.Path]
	if keyMaterial.Host == nil || keyMaterial.Host.Cosigner == nil || !admitted {
		return signerapi.Component{}, badRequest("loaded key does not authorize cosigned component signing")
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
	if err := validateBaseArgs(keyMaterial, txID[:], baseArgs); err != nil {
		return signerapi.Component{}, err
	}
	receiptMessage, receiptErr := hostAssemblyReceiptMessage(account, txID[:], item.Metadata, item.RuntimeArgs)
	if receiptErr != nil {
		return signerapi.Component{}, internal(fmt.Sprintf("build bounded assembly receipt: %v", receiptErr))
	}
	receipt, receiptSignErr := provider.SignMessage(keyMaterial, receiptMessage[:])
	if receiptSignErr != nil {
		return signerapi.Component{}, internal(fmt.Sprintf("sign bounded assembly receipt: %v", receiptSignErr))
	}
	defer crypto.ZeroBytes(receipt)
	component := signerapi.Component{
		TargetIndex: targetIndex, Kind: signerapi.ComponentTargetKindBase,
		AuthAddress: account, RuntimeArgs: encodeRuntimeArgs(item.RuntimeArgs),
		AssemblyReceipt: hex.EncodeToString(receipt), SignatureScheme: keyMaterial.BaseKeyType,
		Path: componentPath,
	}
	for _, arg := range baseArgs {
		component.BaseSignatures = append(component.BaseSignatures, hex.EncodeToString(arg))
	}
	return component, nil
}

// hostSpendingProofVerifies checks a spending proof through the construction the
// workflow completes for this account's durable base, after checking that the
// account's durable argument layout is that construction's. A base the workflow can't
// complete, or metadata that disagrees with its construction, is refused at the same
// point as a proof that fails to verify.
func hostSpendingProofVerifies(keyMaterial *coresigning.KeyMaterial, workflow hostSigningWorkflow, message []byte, proof ...[]byte) bool {
	authorization := keyMaterial.Host
	construction, supported := hostSpendingConstruction(authorization.Contract, keyMaterial.BaseKeyType, workflow)
	return supported &&
		hostLayoutMatches(construction, authorization.BaseSignatureArgLayout) &&
		sigverify.Verify(construction, keyMaterial.PublicKey, message, proof...) == nil
}

func validateBaseArgs(keyMaterial *coresigning.KeyMaterial, messageBytes []byte, args [][]byte) *ServiceError {
	if err := checkBaseSignatureLayout(keyMaterial.Host.BaseSignatureArgLayout, args); err != nil {
		return err
	}
	if !hostSpendingProofVerifies(keyMaterial, hostWorkflowCosigner, messageBytes, args...) {
		return internal("generated bounded base component failed verification")
	}
	return nil
}

func loadHostKeyMaterial(ctx context.Context, session componentKeyGetter, account, label string) (*coresigning.KeyMaterial, *ServiceError) {
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

func assembleHostTarget(ctx context.Context, target signerapi.AssemblyTarget, entry canonical.Txn, session componentKeyGetter) (string, *ServiceError) {
	keyMaterial, loadErr := loadHostKeyMaterial(ctx, session, target.AuthAddress, "bounded account key")
	if loadErr != nil {
		return "", loadErr
	}
	defer zeroLoadedKeyMaterial(keyMaterial)
	if err := ctx.Err(); err != nil {
		return "", canceledSignRequest(err)
	}
	metadata := keyMaterial.Host
	if metadata == nil || metadata.Cosigner == nil {
		return "", badRequest(fmt.Sprintf("target index %d is not a cosigner-enabled bounded account", target.TargetIndex))
	}
	// The path is decided again here, from the canonical transaction and the
	// stored contract, so a client that skipped the cosigner on a target that
	// needs it gets no transaction.
	path, _, classifyErr := hostAccountPath(entry.Txn, metadata, keyMaterial.Parameters)
	if classifyErr != nil {
		return "", withTransactionIndex(target.TargetIndex, classifyErr)
	}
	if _, ok := componentPaths[path]; !ok {
		return "", badRequest(fmt.Sprintf("target index %d is not an admitted cosigned spend or rekey", target.TargetIndex))
	}
	runtimeArgs, runtimeErr := validateHostRuntimeArgs(target.RuntimeArgs, metadata, path)
	if runtimeErr != nil {
		return "", withTransactionIndex(target.TargetIndex, runtimeErr)
	}
	baseArgs, decodeErr := decodeBaseArgs(target, metadata)
	if decodeErr != nil {
		return "", decodeErr
	}
	defer zeroGeneratedArgs(baseArgs)
	if err := validateBaseArgs(keyMaterial, entry.TxID[:], baseArgs); err != nil {
		return "", badRequest(fmt.Sprintf("target index %d base signatures are invalid", target.TargetIndex))
	}
	receipt, decodeReceiptErr := decodeAssemblySignatureHex(target.AssemblyReceipt, "assembly_receipt")
	if decodeReceiptErr != nil {
		return "", decodeReceiptErr
	}
	defer crypto.ZeroBytes(receipt)
	receiptMessage, receiptErr := hostAssemblyReceiptMessage(target.AuthAddress, entry.TxID[:], metadata, runtimeArgs)
	if receiptErr != nil || !hostSpendingProofVerifies(keyMaterial, hostWorkflowCosigner, receiptMessage[:], receipt) {
		return "", badRequest(fmt.Sprintf("target index %d assembly receipt is invalid or stale", target.TargetIndex))
	}
	var cosignerSignature []byte
	switch {
	case !hostPathNeedsCosigner(path):
		// A listed rekey never asks the cosigner, so it carries no signature.
		if target.CosignerSignature != "" {
			return "", badRequest(fmt.Sprintf("target index %d is a listed rekey, which takes no cosigner_signature", target.TargetIndex))
		}
	case target.CosignerSignature == "":
		return "", badRequest(fmt.Sprintf("target index %d needs a cosigner_signature on %s", target.TargetIndex, componentPaths[path]))
	default:
		var cosignerErr *ServiceError
		if cosignerSignature, cosignerErr = decodeAssemblySignatureHex(target.CosignerSignature, "cosigner_signature"); cosignerErr != nil {
			return "", cosignerErr
		}
		defer crypto.ZeroBytes(cosignerSignature)
		cosignerPublicKey, publicKeyErr := hex.DecodeString(metadata.Cosigner.PublicKeyHex)
		if publicKeyErr != nil {
			return "", internal("stored bounded cosigner public key is invalid")
		}
		cosignerMessage := message.ComponentMessage(message.RoleCosigner, entry.TxID)
		if err := verifyCosignerAssemblySignature(metadata.Cosigner.ComponentKeyType, cosignerPublicKey, cosignerMessage[:], cosignerSignature); err != nil {
			return "", badRequest(fmt.Sprintf("target index %d cosigner_signature invalid: %v", target.TargetIndex, err))
		}
	}
	item := &hostPlanItem{Path: path, Metadata: metadata, RuntimeArgs: runtimeArgs, SpendingPublicKey: keyMaterial.PublicKey}
	derivedArgs, deriveErr := hostDerivedArgs(entry.Txn, keyMaterial, metadata, path)
	if deriveErr != nil {
		return "", deriveErr
	}
	defer zeroDerivedArgs(derivedArgs)
	args, argsErr := assembleHostArgsWithCosigner(metadata, item, baseArgs, derivedArgs, cosignerSignature)
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
		return "", internal(fmt.Sprintf("failed to assemble bounded-cosigner transaction: %v", signErr))
	}
	if validateErr := validateAssembledHostTarget(target, entry, signedBytes); validateErr != nil {
		return "", validateErr
	}
	return hex.EncodeToString(signedBytes), nil
}

func decodeBaseArgs(target signerapi.AssemblyTarget, metadata *hostmeta.Metadata) ([][]byte, *ServiceError) {
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

func validateAssembledHostTarget(target signerapi.AssemblyTarget, entry canonical.Txn, signedBytes []byte) *ServiceError {
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

func hostAssemblyReceiptMessage(account string, txID []byte, metadata *hostmeta.Metadata, runtimeArgs map[string][]byte) ([32]byte, error) {
	metadataJSON, err := json.Marshal(hostmeta.Clone(metadata))
	if err != nil {
		return [32]byte{}, err
	}
	var transcript bytes.Buffer
	writeReceiptField(&transcript, []byte(hostAssemblyReceiptDomain))
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
