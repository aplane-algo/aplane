// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
	"github.com/aplane-algo/aplane/internal/attestor/message"
	attestorverify "github.com/aplane-algo/aplane/internal/attestor/verify"
	"github.com/aplane-algo/aplane/internal/lsig"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
)

type attestedOriginalTarget struct {
	Index             int
	Account           string
	AttestorPublicKey string
}

func (e *Engine) hasAttestedSender(txns []types.Transaction) bool {
	for _, txn := range txns {
		if e.signerCacheKeyType(txn.Sender.String()) == keytypes.AttestedFalcon1024V1 {
			return true
		}
	}
	return false
}

func (e *Engine) signAndSubmitAttestedGroup(txns []types.Transaction, opts signing.SubmitOptions) ([]string, []types.Transaction, error) {
	if len(txns) == 0 {
		return nil, nil, fmt.Errorf("no transactions provided")
	}
	if opts.Ctx == nil {
		opts.Ctx = context.Background()
	}
	w := opts.Out
	if w == nil {
		w = os.Stdout
	}

	targets, err := e.attestedOriginalTargets(txns)
	if err != nil {
		return nil, nil, err
	}
	if len(targets) == 0 {
		return nil, nil, fmt.Errorf("attested signing selected with no attested senders")
	}
	if len(targets) != len(txns) {
		return nil, nil, fmt.Errorf("attested signing currently requires every original transaction sender to be %s", keytypes.AttestedFalcon1024V1)
	}

	plannedTxns, dummyTxns, err := e.planAttestedGroup(txns, targets, w)
	if err != nil {
		return nil, nil, err
	}
	groupBytesHex := encodeGroupHex(plannedTxns)
	group, err := attestorverify.DecodeCanonicalGroupHex(groupBytesHex)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build canonical attested group: %w", err)
	}

	signedDummyHex, err := signAttestedDummies(dummyTxns)
	if err != nil {
		return nil, nil, err
	}

	userSignatures, userRequestIDs, err := e.requestUserComponentSignatures(opts.Ctx, groupBytesHex, targets)
	if err != nil {
		return nil, nil, err
	}
	attestorSignatures, attestorRequestIDs, err := e.requestAttestorComponentSignatures(opts.Ctx, groupBytesHex, group, targets)
	if err != nil {
		return nil, nil, err
	}

	assemblyReq := signerapi.AttestedAssemblyRequest{
		GroupBytesHex: groupBytesHex,
		Targets:       make([]signerapi.AttestedAssemblyTarget, 0, len(targets)),
		Passthrough:   make([]signerapi.AttestedPassthroughItem, 0, len(signedDummyHex)),
	}
	for _, target := range targets {
		userSig, ok := userSignatures[target.Index]
		if !ok {
			return nil, nil, fmt.Errorf("user signer returned no signature for target index %d", target.Index)
		}
		attestorSig, ok := attestorSignatures[target.Index]
		if !ok {
			return nil, nil, fmt.Errorf("attestor endpoint returned no signature for target index %d", target.Index)
		}
		assemblyReq.Targets = append(assemblyReq.Targets, signerapi.AttestedAssemblyTarget{
			TargetIndex:             target.Index,
			AttestedAccount:         target.Account,
			UserSignature:           userSig,
			UserSourceRequestID:     userRequestIDs[target.Account],
			AttestorSignature:       attestorSig,
			AttestorSourceRequestID: attestorRequestIDs[target.AttestorPublicKey],
		})
	}
	for i, signedHex := range signedDummyHex {
		assemblyReq.Passthrough = append(assemblyReq.Passthrough, signerapi.AttestedPassthroughItem{
			TargetIndex:  len(txns) + i,
			SignedTxnHex: signedHex,
		})
	}

	assemblyResp, err := e.Connection.RequestAttestedAssembleWithContext(opts.Ctx, assemblyReq)
	if err != nil {
		return nil, nil, err
	}
	signedBytes, signedObjects, submittedTxns, err := decodeAttestedSignedGroup(assemblyResp.SignedGroup)
	if err != nil {
		return nil, nil, err
	}

	if opts.Simulate {
		txIDs, simErr := signing.SimulateSignedTransactionsWithContext(opts.Ctx, signedObjects, e.AlgodClient, w)
		writeAttestedSubmittedTransactions(opts.TxnWriter, submittedTxns, txIDs, len(txns))
		return txIDs, submittedTxns, simErr
	}

	txIDs, err := signing.SubmitTransactionsWithContext(opts.Ctx, signedBytes, e.AlgodClient, opts.WaitForConfirmation, w)
	if err != nil {
		return txIDs, submittedTxns, err
	}
	writeAttestedSubmittedTransactions(opts.TxnWriter, submittedTxns, txIDs, len(txns))
	return txIDs, submittedTxns, nil
}

func (e *Engine) attestedOriginalTargets(txns []types.Transaction) ([]attestedOriginalTarget, error) {
	targets := make([]attestedOriginalTarget, 0, len(txns))
	for i, txn := range txns {
		sender := txn.Sender.String()
		keyType := e.signerCacheKeyType(sender)
		if keyType == "" {
			return nil, fmt.Errorf("transaction %d sender %s is not in signer cache", i, sender)
		}
		if keyType != keytypes.AttestedFalcon1024V1 {
			continue
		}
		attestorPublicKey, ok := e.signerCacheAttestorPublicKey(sender)
		if !ok || attestorPublicKey == "" {
			return nil, fmt.Errorf("attested account %s is missing attestor_public_key metadata; run keys refresh", sender)
		}
		canonicalPublicKey, err := normalizeAttestorEd25519PublicKeyHex(attestorPublicKey)
		if err != nil {
			return nil, fmt.Errorf("attested account %s has invalid attestor_public_key metadata: %w", sender, err)
		}
		targets = append(targets, attestedOriginalTarget{
			Index:             i,
			Account:           sender,
			AttestorPublicKey: canonicalPublicKey,
		})
	}
	return targets, nil
}

func normalizeAttestorEd25519PublicKeyHex(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("attestor public key is required")
	}
	trimmed = strings.TrimPrefix(strings.TrimPrefix(trimmed, "0x"), "0X")
	publicKey, err := hex.DecodeString(trimmed)
	if err != nil {
		return "", fmt.Errorf("attestor public key must be hex: %w", err)
	}
	wantSize, _ := keytypes.ComponentPublicKeySize(keytypes.AttestorComponentEd25519V1)
	if len(publicKey) != wantSize {
		return "", fmt.Errorf("attestor public key length %d invalid (expected %d bytes)", len(publicKey), wantSize)
	}
	return hex.EncodeToString(publicKey), nil
}

func attestorEd25519ComponentSelector(attestorPublicKey string) (string, error) {
	canonicalPublicKey, err := normalizeAttestorEd25519PublicKeyHex(attestorPublicKey)
	if err != nil {
		return "", err
	}
	publicKey, err := hex.DecodeString(canonicalPublicKey)
	if err != nil {
		return "", err
	}
	return keytypes.ComponentKeySelector(keytypes.AttestorComponentEd25519V1, publicKey)
}

func (e *Engine) planAttestedGroup(txns []types.Transaction, targets []attestedOriginalTarget, w io.Writer) ([]types.Transaction, []types.Transaction, error) {
	originalCount := len(txns)
	planned := append([]types.Transaction(nil), txns...)
	lsigIndices := make([]int, 0, len(targets))
	totalLsigBytes := 0
	for _, target := range targets {
		size := e.signerCacheLsigSize(target.Account)
		if size <= 0 {
			return nil, nil, fmt.Errorf("attested account %s is missing LogicSig size metadata; run keys refresh", target.Account)
		}
		totalLsigBytes += size
		lsigIndices = append(lsigIndices, target.Index)
	}

	currentBudget := len(planned) * lsig.TxLsigBudget
	dummiesNeeded := 0
	if totalLsigBytes > currentBudget {
		extraBudgetNeeded := totalLsigBytes - currentBudget
		dummiesNeeded = (extraBudgetNeeded + lsig.TxLsigBudget - 1) / lsig.TxLsigBudget
	}
	if len(planned)+dummiesNeeded > 16 {
		return nil, nil, fmt.Errorf("attested group would be %d transactions (max 16) after adding %d LogicSig-budget dummies", len(planned)+dummiesNeeded, dummiesNeeded)
	}

	var empty types.Digest
	isPreGrouped := planned[0].Group != empty
	for i := range planned {
		if isPreGrouped && planned[i].Group != planned[0].Group {
			return nil, nil, fmt.Errorf("transaction %d has different group ID - request must contain single group", i+1)
		}
		if !isPreGrouped && planned[i].Group != empty {
			return nil, nil, fmt.Errorf("transaction %d has group ID but transaction 1 does not - inconsistent grouping", i+1)
		}
	}
	if isPreGrouped && dummiesNeeded > 0 {
		return nil, nil, fmt.Errorf("pre-grouped attested transactions require %d additional dummies for LogicSig budget but group is immutable", dummiesNeeded)
	}

	var dummyTxns []types.Transaction
	if dummiesNeeded > 0 {
		sp := suggestedParamsFromTxn(planned[0])
		var err error
		dummyTxns, err = lsig.CreateDummyTransactions(dummiesNeeded, sp)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create attested dummy transactions: %w", err)
		}
		if _, err := signing.ApplyDummyFees(planned, lsigIndices, dummiesNeeded, signing.DefaultMinFee); err != nil {
			return nil, nil, fmt.Errorf("failed to adjust attested transaction fees: %w", err)
		}
		if w != nil {
			_, _ = fmt.Fprintf(w, "[ATTESTED] Added %d dummy transaction(s) for LogicSig budget\n", dummiesNeeded)
		}
	}

	planned = append(planned, dummyTxns...)
	if len(planned) > 1 && (!isPreGrouped || dummiesNeeded > 0) {
		for i := range planned {
			planned[i].Group = types.Digest{}
		}
		if _, err := signing.AssignGroupID(planned); err != nil {
			return nil, nil, err
		}
	}
	if originalCount < len(planned) {
		dummyTxns = append([]types.Transaction(nil), planned[originalCount:]...)
	}
	return planned, dummyTxns, nil
}

func suggestedParamsFromTxn(txn types.Transaction) types.SuggestedParams {
	return types.SuggestedParams{
		Fee:             txn.Fee,
		FirstRoundValid: txn.FirstValid,
		LastRoundValid:  txn.LastValid,
		GenesisID:       txn.GenesisID,
		GenesisHash:     txn.GenesisHash[:],
		FlatFee:         true,
	}
}

func encodeGroupHex(txns []types.Transaction) []string {
	groupHex := make([]string, len(txns))
	for i, txn := range txns {
		groupHex[i] = txnutil.EncodeWithPrefixHex(txn)
	}
	return groupHex
}

func signAttestedDummies(dummyTxns []types.Transaction) ([]string, error) {
	signedDummies, err := lsig.SignDummyTransactions(dummyTxns)
	if err != nil {
		return nil, fmt.Errorf("failed to sign attested dummy transactions: %w", err)
	}
	signedHex := make([]string, len(signedDummies))
	for i, signed := range signedDummies {
		signedHex[i] = hex.EncodeToString(signed)
	}
	return signedHex, nil
}

func (e *Engine) requestUserComponentSignatures(ctx context.Context, groupBytesHex []string, targets []attestedOriginalTarget) (map[int]string, map[string]string, error) {
	byAccount := make(map[string][]int)
	for _, target := range targets {
		byAccount[target.Account] = append(byAccount[target.Account], target.Index)
	}
	signatures := make(map[int]string, len(targets))
	requestIDs := make(map[string]string, len(byAccount))
	for account, indices := range byAccount {
		resp, err := e.Connection.RequestComponentSignWithContext(ctx, signerapi.ComponentSignRequest{
			Role:          signerapi.ComponentSignRoleUser,
			ComponentKey:  account,
			GroupBytesHex: groupBytesHex,
			TargetIndices: indices,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("user component signing failed for %s: %w", account, err)
		}
		if err := collectComponentSignatures(resp, indices, "", signatures); err != nil {
			return nil, nil, fmt.Errorf("user component signing failed for %s: %w", account, err)
		}
		requestIDs[account] = resp.RequestID
	}
	return signatures, requestIDs, nil
}

func (e *Engine) requestAttestorComponentSignatures(ctx context.Context, groupBytesHex []string, group *attestorverify.CanonicalGroup, targets []attestedOriginalTarget) (map[int]string, map[string]string, error) {
	byAttestor := make(map[string][]int)
	for _, target := range targets {
		byAttestor[target.AttestorPublicKey] = append(byAttestor[target.AttestorPublicKey], target.Index)
	}
	signatures := make(map[int]string, len(targets))
	requestIDs := make(map[string]string, len(byAttestor))
	for attestorPublicKey, indices := range byAttestor {
		requestID, err := e.requestOneAttestorComponentSignatureSet(ctx, groupBytesHex, group, attestorPublicKey, indices, signatures)
		if err != nil {
			return nil, nil, err
		}
		requestIDs[attestorPublicKey] = requestID
	}
	return signatures, requestIDs, nil
}

func (e *Engine) requestOneAttestorComponentSignatureSet(ctx context.Context, groupBytesHex []string, group *attestorverify.CanonicalGroup, attestorPublicKey string, indices []int, signatures map[int]string) (string, error) {
	endpoint, err := e.resolveAttestorEndpoint(ctx, attestorPublicKey)
	if err != nil {
		return "", err
	}
	defer endpoint.close()

	componentSelector, err := attestorEd25519ComponentSelector(attestorPublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to derive attestor component selector for public key %s: %w", attestorPublicKey, err)
	}

	resp, err := endpoint.client.RequestComponentSignWithContext(ctx, signerapi.ComponentSignRequest{
		Role:          signerapi.ComponentSignRoleAttestor,
		ComponentKey:  componentSelector,
		GroupBytesHex: groupBytesHex,
		TargetIndices: indices,
	})
	if err != nil {
		return "", fmt.Errorf("attestor component signing failed for public key %s via %s: %w", attestorPublicKey, endpoint.source, err)
	}
	if err := collectComponentSignatures(resp, indices, keytypes.AttestorComponentEd25519V1, signatures); err != nil {
		return "", fmt.Errorf("attestor component signing failed for public key %s via %s: %w", attestorPublicKey, endpoint.source, err)
	}
	if err := verifyAttestorComponentSignatures(attestorPublicKey, group, indices, signatures); err != nil {
		return "", err
	}
	return resp.RequestID, nil
}

func collectComponentSignatures(resp *signerapi.ComponentSignResponse, expected []int, expectedScheme string, dst map[int]string) error {
	if resp == nil {
		return fmt.Errorf("empty component sign response")
	}
	expectedSet := make(map[int]bool, len(expected))
	for _, index := range expected {
		expectedSet[index] = true
	}
	seen := make(map[int]bool, len(resp.Signatures))
	for _, sig := range resp.Signatures {
		if !expectedSet[sig.TargetIndex] {
			return fmt.Errorf("unexpected signature for target index %d", sig.TargetIndex)
		}
		if seen[sig.TargetIndex] {
			return fmt.Errorf("duplicate signature for target index %d", sig.TargetIndex)
		}
		if expectedScheme != "" && sig.SignatureScheme != expectedScheme {
			return fmt.Errorf("signature for target index %d used scheme %s, want %s", sig.TargetIndex, sig.SignatureScheme, expectedScheme)
		}
		seen[sig.TargetIndex] = true
		dst[sig.TargetIndex] = sig.Signature
	}
	for _, index := range expected {
		if !seen[index] {
			return fmt.Errorf("missing signature for target index %d", index)
		}
	}
	return nil
}

func verifyAttestorComponentSignatures(attestorPublicKey string, group *attestorverify.CanonicalGroup, indices []int, signatures map[int]string) error {
	canonicalPublicKey, err := normalizeAttestorEd25519PublicKeyHex(attestorPublicKey)
	if err != nil {
		return err
	}
	publicKey, err := hex.DecodeString(canonicalPublicKey)
	if err != nil {
		return fmt.Errorf("attestor public key must be hex: %w", err)
	}
	for _, index := range indices {
		signatureHex := signatures[index]
		signature, err := hex.DecodeString(signatureHex)
		if err != nil {
			return fmt.Errorf("attestor signature for target index %d must be hex: %w", index, err)
		}
		msg := message.ComponentMessage(message.RoleAttestor, group.Entries[index].TxID)
		if err := attestorverify.VerifyEd25519(publicKey, msg[:], signature); err != nil {
			return fmt.Errorf("attestor signature for target index %d did not verify against embedded attestor public key: %w", index, err)
		}
	}
	return nil
}

func decodeAttestedSignedGroup(signedHex []string) ([][]byte, []types.SignedTxn, []types.Transaction, error) {
	signedBytes := make([][]byte, len(signedHex))
	signedObjects := make([]types.SignedTxn, len(signedHex))
	txns := make([]types.Transaction, len(signedHex))
	for i, item := range signedHex {
		decoded, err := hex.DecodeString(item)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to decode assembled signed transaction %d: %w", i+1, err)
		}
		signedBytes[i] = decoded
		var stxn types.SignedTxn
		if err := msgpack.Decode(decoded, &stxn); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to decode assembled signed transaction %d: %w", i+1, err)
		}
		signedObjects[i] = stxn
		txns[i] = stxn.Txn
	}
	return signedBytes, signedObjects, txns, nil
}

func writeAttestedSubmittedTransactions(writer func(types.Transaction, string), txns []types.Transaction, txIDs []string, originalCount int) {
	if writer == nil {
		return
	}
	if originalCount > len(txns) {
		originalCount = len(txns)
	}
	for i := 0; i < originalCount; i++ {
		if i < len(txIDs) {
			writer(txns[i], txIDs[i])
		}
	}
}
