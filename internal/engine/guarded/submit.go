// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package guarded

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/clientsign"
	"github.com/aplane-algo/aplane/internal/lsig"
	"github.com/aplane-algo/aplane/internal/sentry/canonical"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
)

type guardedTarget struct {
	Index                  int
	Sender                 string
	Account                string
	SentryComponentKeyType string
	SentryPublicKey        string
}

type sentryRequestKey struct {
	ComponentKeyType string
	PublicKey        string
}

// hasGuardedEffectiveSigner reports whether any transaction's effective
// signer declares a component signing flow (signing_flow in signer
// inventory). Any non-empty flow routes through guarded orchestration, which
// rejects flow labels this client does not implement; routing on the flow
// label rather than the key type keeps the client forward-compatible with
// new guarded key families.
func (s *Signer) HasGuardedEffectiveSigner(txns []types.Transaction) bool {
	for _, txn := range txns {
		sender := txn.Sender.String()
		effectiveSigner := s.authCache.ResolveEffectiveSigner(sender)
		if s.cache.SigningFlow(effectiveSigner) != "" {
			return true
		}
	}
	return false
}

func (s *Signer) SignAndSubmitGroup(txns []types.Transaction, opts clientsign.SubmitOptions) ([]string, []types.Transaction, error) {
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

	targets, err := s.guardedTargets(txns)
	if err != nil {
		return nil, nil, err
	}
	if len(targets) == 0 {
		return nil, nil, fmt.Errorf("guarded signing selected with no guarded effective signers")
	}
	guardedTargetsByIndex := make(map[int]guardedTarget, len(targets))
	for _, target := range targets {
		guardedTargetsByIndex[target.Index] = target
	}

	plannedTxns, dummyTxns, err := s.planGuardedGroup(txns, targets, w)
	if err != nil {
		return nil, nil, err
	}
	groupBytesHex := encodeGroupHex(plannedTxns)
	if _, err := canonical.DecodeGroupHex(groupBytesHex); err != nil {
		return nil, nil, fmt.Errorf("failed to build canonical guarded group: %w", err)
	}

	signedDummyHex, err := signGuardedDummies(dummyTxns)
	if err != nil {
		return nil, nil, err
	}

	userSignatures, userRequestIDs, err := s.requestUserComponentSignatures(opts.Ctx, groupBytesHex, targets)
	if err != nil {
		return nil, nil, err
	}
	sentrySignatures, sentryRequestIDs, err := s.requestSentryComponentSignatures(opts.Ctx, groupBytesHex, targets)
	if err != nil {
		return nil, nil, err
	}

	if nonGuardedCount := len(txns) - len(targets); nonGuardedCount > 0 {
		_, _ = fmt.Fprintf(w, "[GUARDED] Mixed group: signing %d non-guarded position(s) over canonical bytes\n", nonGuardedCount)
	}
	nonGuardedSignedHex, err := s.requestNonGuardedSignatures(opts.Ctx, plannedTxns, groupBytesHex, len(txns), guardedTargetsByIndex, opts)
	if err != nil {
		return nil, nil, err
	}

	assemblyReq := signerapi.GuardedAssemblyRequest{
		GroupBytesHex: groupBytesHex,
		Targets:       make([]signerapi.GuardedAssemblyTarget, 0, len(targets)),
		Passthrough:   make([]signerapi.GuardedPassthroughItem, 0, len(signedDummyHex)+len(nonGuardedSignedHex)),
	}
	for _, target := range targets {
		userSig, ok := userSignatures[target.Index]
		if !ok {
			return nil, nil, fmt.Errorf("user signer returned no signature for target index %d", target.Index)
		}
		sentrySig, ok := sentrySignatures[target.Index]
		if !ok {
			return nil, nil, fmt.Errorf("sentry endpoint returned no signature for target index %d", target.Index)
		}
		assemblyReq.Targets = append(assemblyReq.Targets, signerapi.GuardedAssemblyTarget{
			TargetIndex:           target.Index,
			GuardedAccount:        target.Account,
			UserSignature:         userSig,
			UserSourceRequestID:   userRequestIDs[target.Account],
			SentrySignature:       sentrySig,
			SentrySourceRequestID: sentryRequestIDs[target.requestKey()],
		})
	}
	for index, signedHex := range nonGuardedSignedHex {
		assemblyReq.Passthrough = append(assemblyReq.Passthrough, signerapi.GuardedPassthroughItem{
			TargetIndex:  index,
			SignedTxnHex: signedHex,
		})
	}
	for i, signedHex := range signedDummyHex {
		assemblyReq.Passthrough = append(assemblyReq.Passthrough, signerapi.GuardedPassthroughItem{
			TargetIndex:  len(txns) + i,
			SignedTxnHex: signedHex,
		})
	}

	assemblyResp, err := s.conn.RequestGuardedAssembleWithContext(opts.Ctx, assemblyReq)
	if err != nil {
		return nil, nil, err
	}
	signedBytes, signedObjects, submittedTxns, err := decodeGuardedSignedGroup(assemblyResp.SignedGroup)
	if err != nil {
		return nil, nil, err
	}
	if err := verifyAssembledAgainstFrozen(groupBytesHex, submittedTxns); err != nil {
		return nil, nil, err
	}

	if opts.Simulate {
		txIDs, simErr := signing.SimulateSignedTransactionsWithContext(opts.Ctx, signedObjects, s.algod, w)
		writeGuardedSubmittedTransactions(opts.TxnWriter, submittedTxns, txIDs, len(txns))
		return txIDs, submittedTxns, simErr
	}

	txIDs, err := signing.SubmitTransactionsWithContext(opts.Ctx, signedBytes, s.algod, opts.WaitForConfirmation, w)
	if err != nil {
		return txIDs, submittedTxns, err
	}
	writeGuardedSubmittedTransactions(opts.TxnWriter, submittedTxns, txIDs, len(txns))
	return txIDs, submittedTxns, nil
}

// verifyAssembledAgainstFrozen pins the client's frozen-bytes invariant at the
// last step: the signer's assembled group must have one signed transaction per
// frozen canonical entry, and each assembled transaction must re-encode to
// exactly the bytes the client signed over. The signer already enforces this on
// its side and the network would reject a mismatch, but re-checking here keeps
// the client from submitting (and recording in its TxnWriter) bytes it never
// committed to.
func verifyAssembledAgainstFrozen(groupBytesHex []string, assembled []types.Transaction) error {
	if len(assembled) != len(groupBytesHex) {
		return fmt.Errorf("assembled group has %d transaction(s), want %d", len(assembled), len(groupBytesHex))
	}
	for i, txn := range assembled {
		if got := txnutil.EncodeWithPrefixHex(txn); got != groupBytesHex[i] {
			return fmt.Errorf("assembled transaction %d does not match the frozen canonical bytes", i)
		}
	}
	return nil
}

// requestNonGuardedSignatures signs the non-guarded original positions of a
// mixed guarded group over the frozen canonical bytes, so every signature in
// the group commits to the same final transaction IDs. Guarded targets and
// dummies are sent as foreign — guarded with an lsig_size hint for the guarded
// authorizer so the signer's budget accounting stays exact and honest — and
// only the non-guarded originals are signed; the guarded positions are
// assembled later via /sign/assemble. Returns signed-transaction hex keyed by
// group index. When there are no non-guarded originals (the all-guarded case)
// it makes no signer call.
func (s *Signer) requestNonGuardedSignatures(ctx context.Context, plannedTxns []types.Transaction, groupBytesHex []string, originalCount int, guardedTargets map[int]guardedTarget, opts clientsign.SubmitOptions) (map[int]string, error) {
	signRequests := make([]signerapi.SignRequest, len(plannedTxns))
	nonGuarded := make([]int, 0, originalCount)
	for i := range plannedTxns {
		sender := plannedTxns[i].Sender.String()
		switch {
		case i >= originalCount:
			// Dummy: foreign. Already signed locally and passed through at assembly.
			signRequests[i] = signerapi.SignRequest{TxnBytesHex: groupBytesHex[i]}
		case guardedTargets[i].Account != "":
			// Guarded target: foreign with an lsig_size hint. Kept in the group
			// for context and budget accounting but not signed here.
			target := guardedTargets[i]
			if target.Sender != sender {
				return nil, fmt.Errorf("guarded target %d sender %s does not match transaction sender %s", i, target.Sender, sender)
			}
			signRequests[i] = signerapi.SignRequest{
				TxnBytesHex: groupBytesHex[i],
				LsigSize:    s.cache.LsigSize(target.Account),
			}
		default:
			// Non-guarded original: sign mode over the canonical bytes. Resolve
			// the effective signer so a rekeyed account is signed by — and
			// budgeted against — its auth address, matching planGuardedGroup.
			effectiveSigner := s.authCache.ResolveEffectiveSigner(sender)
			req := signerapi.SignRequest{
				AuthAddress: effectiveSigner,
				TxnSender:   sender,
				TxnBytesHex: groupBytesHex[i],
			}
			if i < len(opts.LsigArgsMap) && opts.LsigArgsMap[i] != nil {
				req.LsigArgs = make(map[string]string, len(opts.LsigArgsMap[i]))
				for name, value := range opts.LsigArgsMap[i] {
					req.LsigArgs[name] = hex.EncodeToString(value)
				}
			}
			if i < len(opts.AppCallInfo) {
				req.AppCallInfo = opts.AppCallInfo[i]
			}
			signRequests[i] = req
			nonGuarded = append(nonGuarded, i)
		}
	}

	if len(nonGuarded) == 0 {
		return map[int]string{}, nil
	}

	signResp, err := s.conn.RequestGroupSignWithContext(ctx, signRequests)
	if err != nil {
		return nil, fmt.Errorf("signing non-guarded group positions failed: %w", err)
	}
	if len(signResp.Signed) != len(signRequests) {
		return nil, fmt.Errorf("signer returned %d signed position(s), want %d", len(signResp.Signed), len(signRequests))
	}

	signed := make(map[int]string, len(nonGuarded))
	for _, i := range nonGuarded {
		if signResp.Signed[i] == "" {
			return nil, fmt.Errorf("signer returned no signature for non-guarded position %d", i+1)
		}
		signed[i] = signResp.Signed[i]
	}
	return signed, nil
}

func (s *Signer) guardedTargets(txns []types.Transaction) ([]guardedTarget, error) {
	targets := make([]guardedTarget, 0, len(txns))
	for i, txn := range txns {
		sender := txn.Sender.String()
		account := s.authCache.ResolveEffectiveSigner(sender)
		flow := s.cache.SigningFlow(account)
		if flow == "" {
			continue
		}
		if flow != signerapi.SigningFlowSentry1 {
			return nil, fmt.Errorf("account %s requires signing flow %q, which this client does not support; upgrade the client", account, flow)
		}
		sentryComponentKeyType, ok := s.cache.SentryComponentKeyType(account)
		if !ok {
			return nil, fmt.Errorf("guarded account %s is missing sentry_component_key_type metadata; run keys refresh", account)
		}
		sentryPublicKey, ok := s.cache.SentryPublicKey(account)
		if !ok || sentryPublicKey == "" {
			return nil, fmt.Errorf("guarded account %s is missing sentry_public_key metadata; run keys refresh", account)
		}
		canonicalPublicKey, err := normalizeSentryPublicKeyHex(sentryPublicKey)
		if err != nil {
			return nil, fmt.Errorf("guarded account %s has invalid sentry_public_key metadata: %w", account, err)
		}
		targets = append(targets, guardedTarget{
			Index:                  i,
			Sender:                 sender,
			Account:                account,
			SentryComponentKeyType: sentryComponentKeyType,
			SentryPublicKey:        canonicalPublicKey,
		})
	}
	return targets, nil
}

func (t guardedTarget) requestKey() sentryRequestKey {
	return sentryRequestKey{
		ComponentKeyType: t.SentryComponentKeyType,
		PublicKey:        t.SentryPublicKey,
	}
}

// normalizeSentryPublicKeyHex canonicalizes a sentry public key as lowercase
// hex. Component key types and public keys are runtime metadata, so no
// per-family size table is consulted: integrity comes from the Sentry Key ID
// selector matching the advertising endpoint and, authoritatively, from the
// on-chain LogicSig.
func normalizeSentryPublicKeyHex(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("sentry public key is required")
	}
	trimmed = strings.TrimPrefix(strings.TrimPrefix(trimmed, "0x"), "0X")
	publicKey, err := hex.DecodeString(trimmed)
	if err != nil {
		return "", fmt.Errorf("sentry public key must be hex: %w", err)
	}
	if len(publicKey) == 0 {
		return "", fmt.Errorf("sentry public key is empty")
	}
	return hex.EncodeToString(publicKey), nil
}

func sentryComponentSelector(componentKeyType string, sentryPublicKey string) (string, error) {
	if componentKeyType == "" {
		return "", fmt.Errorf("sentry component key type is required")
	}
	canonicalPublicKey, err := normalizeSentryPublicKeyHex(sentryPublicKey)
	if err != nil {
		return "", err
	}
	publicKey, err := hex.DecodeString(canonicalPublicKey)
	if err != nil {
		return "", err
	}
	return keytypes.DeriveComponentKeySelector(componentKeyType, publicKey), nil
}

func sentryComponentLabel(componentKeyType, sentryPublicKey string) string {
	selector, err := sentryComponentSelector(componentKeyType, sentryPublicKey)
	if err == nil {
		return fmt.Sprintf("Sentry Key ID %s (%s)", selector, componentKeyType)
	}
	return fmt.Sprintf("sentry public key %s (%s)", shortSentryPublicKeyHex(sentryPublicKey), componentKeyType)
}

func shortSentryPublicKeyHex(publicKeyHex string) string {
	trimmed := strings.TrimSpace(publicKeyHex)
	trimmed = strings.TrimPrefix(strings.TrimPrefix(trimmed, "0x"), "0X")
	if len(trimmed) <= 24 {
		return trimmed
	}
	return trimmed[:12] + "..." + trimmed[len(trimmed)-12:]
}

func (s *Signer) planGuardedGroup(txns []types.Transaction, targets []guardedTarget, w io.Writer) ([]types.Transaction, []types.Transaction, error) {
	originalCount := len(txns)
	planned := append([]types.Transaction(nil), txns...)
	guardedTargets := make(map[int]guardedTarget, len(targets))
	for _, target := range targets {
		guardedTargets[target.Index] = target
	}
	// Size LogicSig budget across every LogicSig position, not just guarded
	// ones: a mixed group can include non-guarded LogicSig senders (e.g. a
	// plain falcon1024 account) that also consume program-size budget. The
	// same indices later absorb the dummy fees in ApplyDummyFees.
	//
	// Non-guarded positions are budgeted against the effective signer (the auth
	// address for rekeyed accounts), because that is the LogicSig that goes
	// on-chain and the address the signer sizes budget against — keeping the
	// client and server dummy counts in agreement. Guarded positions are
	// budgeted against the guarded effective signer, because that is the
	// LogicSig that goes on-chain as sender or AuthAddr.
	lsigIndices := make([]int, 0, len(planned))
	totalLsigBytes := 0
	for i, txn := range planned {
		sender := txn.Sender.String()
		budgetAddr := s.authCache.ResolveEffectiveSigner(sender)
		target, guarded := guardedTargets[i]
		if guarded {
			if target.Sender != sender {
				return nil, nil, fmt.Errorf("guarded target %d sender %s does not match transaction sender %s", i, target.Sender, sender)
			}
			budgetAddr = target.Account
		}
		size := s.cache.LsigSize(budgetAddr)
		if guarded && size <= 0 {
			return nil, nil, missingGuardedLsigSizeMessage(target)
		}
		if size > 0 {
			totalLsigBytes += size
			lsigIndices = append(lsigIndices, i)
		}
	}

	currentBudget := len(planned) * lsig.TxLsigBudget
	dummiesNeeded := 0
	if totalLsigBytes > currentBudget {
		extraBudgetNeeded := totalLsigBytes - currentBudget
		dummiesNeeded = (extraBudgetNeeded + lsig.TxLsigBudget - 1) / lsig.TxLsigBudget
	}
	if len(planned)+dummiesNeeded > 16 {
		return nil, nil, fmt.Errorf("guarded group would be %d transactions (max 16) after adding %d LogicSig-budget dummies", len(planned)+dummiesNeeded, dummiesNeeded)
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
		return nil, nil, fmt.Errorf("pre-grouped guarded transactions require %d additional dummies for LogicSig budget but group is immutable", dummiesNeeded)
	}

	var dummyTxns []types.Transaction
	if dummiesNeeded > 0 {
		sp := suggestedParamsFromTxn(planned[0])
		var err error
		dummyTxns, err = lsig.CreateDummyTransactions(dummiesNeeded, sp)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create guarded dummy transactions: %w", err)
		}
		if _, err := signing.ApplyDummyFees(planned, lsigIndices, dummiesNeeded, signing.DefaultMinFee); err != nil {
			return nil, nil, fmt.Errorf("failed to adjust guarded transaction fees: %w", err)
		}
		if w != nil {
			_, _ = fmt.Fprintf(w, "[GUARDED] Added %d dummy transaction(s) for LogicSig budget\n", dummiesNeeded)
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

func missingGuardedLsigSizeMessage(target guardedTarget) error {
	if target.Sender == target.Account {
		return fmt.Errorf("guarded account %s is missing LogicSig size metadata; run keys refresh", target.Account)
	}
	return fmt.Errorf("guarded authorizer %s for sender %s is missing LogicSig size metadata; run keys refresh", target.Account, target.Sender)
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

func signGuardedDummies(dummyTxns []types.Transaction) ([]string, error) {
	signedDummies, err := lsig.SignDummyTransactions(dummyTxns)
	if err != nil {
		return nil, fmt.Errorf("failed to sign guarded dummy transactions: %w", err)
	}
	signedHex := make([]string, len(signedDummies))
	for i, signed := range signedDummies {
		signedHex[i] = hex.EncodeToString(signed)
	}
	return signedHex, nil
}

func (s *Signer) requestUserComponentSignatures(ctx context.Context, groupBytesHex []string, targets []guardedTarget) (map[int]string, map[string]string, error) {
	byAccount := make(map[string][]int)
	for _, target := range targets {
		byAccount[target.Account] = append(byAccount[target.Account], target.Index)
	}
	signatures := make(map[int]string, len(targets))
	requestIDs := make(map[string]string, len(byAccount))
	for account, indices := range byAccount {
		resp, err := s.conn.RequestComponentSignWithContext(ctx, signerapi.ComponentSignRequest{
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

func (s *Signer) requestSentryComponentSignatures(ctx context.Context, groupBytesHex []string, targets []guardedTarget) (map[int]string, map[sentryRequestKey]string, error) {
	bySentry := make(map[sentryRequestKey][]int)
	for _, target := range targets {
		key := target.requestKey()
		bySentry[key] = append(bySentry[key], target.Index)
	}
	signatures := make(map[int]string, len(targets))
	requestIDs := make(map[sentryRequestKey]string, len(bySentry))
	for sentryKey, indices := range bySentry {
		requestID, err := s.requestOneSentryComponentSignatureSet(ctx, groupBytesHex, sentryKey, indices, signatures)
		if err != nil {
			return nil, nil, err
		}
		requestIDs[sentryKey] = requestID
	}
	return signatures, requestIDs, nil
}

// requestOneSentryComponentSignatureSet collects component signatures from a
// sentry endpoint without verifying them cryptographically: the client treats
// component signatures as opaque material. Invalid signatures are rejected by
// the signer during guarded assembly and, authoritatively, by the guarded
// LogicSig on-chain.
func (s *Signer) requestOneSentryComponentSignatureSet(ctx context.Context, groupBytesHex []string, sentryKey sentryRequestKey, indices []int, signatures map[int]string) (string, error) {
	endpoint, err := s.resolveSentryEndpoint(ctx, sentryKey)
	if err != nil {
		return "", err
	}
	defer endpoint.close()

	componentSelector, err := sentryComponentSelector(sentryKey.ComponentKeyType, sentryKey.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to derive Sentry Key ID for sentry public key %s: %w", shortSentryPublicKeyHex(sentryKey.PublicKey), err)
	}
	componentLabel := fmt.Sprintf("Sentry Key ID %s (%s)", componentSelector, sentryKey.ComponentKeyType)

	resp, err := endpoint.client.RequestComponentSignWithContext(ctx, signerapi.ComponentSignRequest{
		Role:          signerapi.ComponentSignRoleSentry,
		ComponentKey:  componentSelector,
		GroupBytesHex: groupBytesHex,
		TargetIndices: indices,
	})
	if err != nil {
		return "", fmt.Errorf("sentry component signing failed for %s via %s: %w", componentLabel, endpoint.source, err)
	}
	if err := collectComponentSignatures(resp, indices, sentryKey.ComponentKeyType, signatures); err != nil {
		return "", fmt.Errorf("sentry component signing failed for %s via %s: %w", componentLabel, endpoint.source, err)
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

func decodeGuardedSignedGroup(signedHex []string) ([][]byte, []types.SignedTxn, []types.Transaction, error) {
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

func writeGuardedSubmittedTransactions(writer func(types.Transaction, string), txns []types.Transaction, txIDs []string, originalCount int) {
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
