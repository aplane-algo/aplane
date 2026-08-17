// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package guarded

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/clientsign"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/sentry/canonical"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/internal/witness"
)

type guardedTarget struct {
	Index                  int
	Sender                 string
	Account                string
	SentryComponentKeyType string
	SentryPublicKey        string
	Flow                   string
	BoundedMaxFee          uint64
}

type sentryRequestKey struct {
	ComponentKeyType string
	PublicKey        string
}

// flowRoute is the client-side route a signing_flow label takes. Every flow
// label is classified in exactly one place, routeForSigningFlow, so the
// guarded pre-check and target assembly cannot disagree about a label.
type flowRoute int

const (
	// flowRoutePlain signs through the ordinary client path. Bounded1 belongs
	// here: it has its own transaction-aware server-side path behind /sign.
	flowRoutePlain flowRoute = iota
	// flowRouteGuarded routes through sentry component orchestration.
	flowRouteGuarded
	flowRouteBoundedSentry
	// flowRouteUnknown fails closed: the client must be upgraded. Unknown
	// labels still enter guarded routing so guardedTargets rejects them
	// explicitly instead of silently falling through to ordinary signing.
	flowRouteUnknown
)

func routeForSigningFlow(flow string) flowRoute {
	switch flow {
	case "", signerapi.SigningFlowBounded1:
		return flowRoutePlain
	case signerapi.SigningFlowSentry1:
		return flowRouteGuarded
	case signerapi.SigningFlowBoundedSentry1:
		return flowRouteBoundedSentry
	default:
		return flowRouteUnknown
	}
}

// hasGuardedEffectiveSigner reports whether any transaction's effective
// signer declares a component signing flow (signing_flow in signer
// inventory).
func (s *Signer) HasGuardedEffectiveSigner(txns []types.Transaction) bool {
	for _, txn := range txns {
		sender := txn.Sender.String()
		effectiveSigner := s.authCache.ResolveEffectiveSigner(sender)
		if routeForSigningFlow(s.cache.SigningFlow(effectiveSigner)) != flowRoutePlain {
			return true
		}
	}
	return false
}

func (s *Signer) SignAndSubmitGroup(txns []types.Transaction, opts clientsign.SubmitOptions) ([]string, []types.Transaction, error) {
	if len(txns) == 0 {
		return nil, nil, fmt.Errorf("no transactions provided")
	}
	if s.algod == nil {
		return nil, nil, fmt.Errorf("algod client not configured")
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
	hasBoundedSentry, hasLegacyGuarded := false, false
	for _, target := range targets {
		switch target.Flow {
		case signerapi.SigningFlowBoundedSentry1:
			hasBoundedSentry = true
		case signerapi.SigningFlowSentry1:
			hasLegacyGuarded = true
		}
	}
	if hasBoundedSentry {
		if hasLegacyGuarded {
			return nil, nil, fmt.Errorf("cannot mix sentry1 and bounded-sentry1 targets in one group")
		}
		return s.signAndSubmitBoundedSentryGroup(txns, targets, opts, w)
	}
	guardedTargetsByIndex := make(map[int]guardedTarget, len(targets))
	for _, target := range targets {
		guardedTargetsByIndex[target.Index] = target
	}

	plannedTxns, dummyTxns, err := s.planGuardedGroupWithSigner(opts.Ctx, txns, targets, opts, w)
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

	assemblyReq := signerapi.AssemblyRequest{
		GroupBytesHex: groupBytesHex,
		Targets:       make([]signerapi.AssemblyTarget, 0, len(targets)),
		Passthrough:   make([]signerapi.AssemblyPassthroughItem, 0, len(signedDummyHex)+len(nonGuardedSignedHex)),
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
		assemblyReq.Targets = append(assemblyReq.Targets, signerapi.AssemblyTarget{
			TargetIndex:           target.Index,
			Kind:                  signerapi.AssemblyTargetKindGuarded,
			AuthAddress:           target.Account,
			UserSignature:         userSig,
			UserSourceRequestID:   userRequestIDs[target.Account],
			SentrySignature:       sentrySig,
			SentrySourceRequestID: sentryRequestIDs[target.requestKey()],
		})
	}
	for index, signedHex := range nonGuardedSignedHex {
		assemblyReq.Passthrough = append(assemblyReq.Passthrough, signerapi.AssemblyPassthroughItem{
			TargetIndex:  index,
			SignedTxnHex: signedHex,
		})
	}
	for i, signedHex := range signedDummyHex {
		assemblyReq.Passthrough = append(assemblyReq.Passthrough, signerapi.AssemblyPassthroughItem{
			TargetIndex:  len(txns) + i,
			SignedTxnHex: signedHex,
		})
	}

	assemblyResp, err := s.conn.RequestAssembleWithContext(opts.Ctx, assemblyReq)
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

// planGuardedGroupWithSigner makes the signer-side consensus planner the sole
// authority for dummy membership, fee factors, and final group IDs. Guarded
// positions are sign-mode here because /plan never signs or prompts; this lets
// the signer use its exact stored path profile instead of trusting a client
// approximation. The component-signing choreography begins only after these
// returned bytes are frozen.
func (s *Signer) planGuardedGroupWithSigner(ctx context.Context, txns []types.Transaction, targets []guardedTarget, opts clientsign.SubmitOptions, w io.Writer) ([]types.Transaction, []types.Transaction, error) {
	targetsByIndex := make(map[int]guardedTarget, len(targets))
	for _, target := range targets {
		targetsByIndex[target.Index] = target
	}
	requests := make([]signerapi.SignRequest, len(txns))
	for i, txn := range txns {
		authorizer := s.authCache.ResolveEffectiveSigner(txn.Sender.String())
		if target, ok := targetsByIndex[i]; ok {
			authorizer = target.Account
		}
		requests[i] = signerapi.SignRequest{
			AuthAddress: authorizer,
			TxnSender:   txn.Sender.String(),
			TxnBytesHex: txnutil.EncodeWithPrefixHex(txn),
		}
		if i < len(opts.LsigArgsMap) && opts.LsigArgsMap[i] != nil {
			requests[i].LsigArgs = make(map[string]string, len(opts.LsigArgsMap[i]))
			for name, value := range opts.LsigArgsMap[i] {
				requests[i].LsigArgs[name] = hex.EncodeToString(value)
			}
		}
		if i < len(opts.AppCallInfo) {
			requests[i].AppCallInfo = opts.AppCallInfo[i]
		}
	}
	response, err := s.conn.RequestGroupPlanWithContext(ctx, requests)
	if err != nil {
		return nil, nil, fmt.Errorf("guarded group planning failed: %w", err)
	}
	group, err := canonical.DecodeGroupHex(response.Transactions)
	if err != nil {
		return nil, nil, fmt.Errorf("signer returned invalid guarded group plan: %w", err)
	}
	planned := make([]types.Transaction, len(group.Entries))
	for i, entry := range group.Entries {
		planned[i] = entry.Txn
	}
	if err := validateBoundedComponentPlan(txns, planned, response.Mutations); err != nil {
		return nil, nil, fmt.Errorf("invalid guarded group plan: %w", err)
	}
	dummies := append([]types.Transaction(nil), planned[len(txns):]...)
	if len(dummies) > 0 && w != nil {
		_, _ = fmt.Fprintf(w, "[GUARDED] Signer added %d dummy transaction(s) for LogicSig arguments/opcode budget\n", len(dummies))
	}
	return planned, dummies, nil
}

func (s *Signer) signAndSubmitBoundedSentryGroup(txns []types.Transaction, targets []guardedTarget, opts clientsign.SubmitOptions, w io.Writer) ([]string, []types.Transaction, error) {
	targetsByIndex := make(map[int]guardedTarget, len(targets))
	for _, target := range targets {
		targetsByIndex[target.Index] = target
	}
	requests, err := s.buildBoundedComponentRequests(txns, targetsByIndex, opts)
	if err != nil {
		return nil, nil, err
	}
	planResp, err := s.conn.RequestGroupPlanWithContext(opts.Ctx, requests)
	if err != nil {
		return nil, nil, fmt.Errorf("bounded group planning failed: %w", err)
	}
	group, err := canonical.DecodeGroupHex(planResp.Transactions)
	if err != nil {
		return nil, nil, fmt.Errorf("signer returned invalid bounded canonical group: %w", err)
	}
	plannedTxns := make([]types.Transaction, len(group.Entries))
	for i, entry := range group.Entries {
		plannedTxns[i] = entry.Txn
	}
	if err := validateBoundedComponentPlan(txns, plannedTxns, planResp.Mutations); err != nil {
		return nil, nil, err
	}
	componentReq := signerapi.ComponentRequest{GroupBytesHex: append([]string(nil), planResp.Transactions...)}
	for i, request := range requests {
		if _, ok := targetsByIndex[i]; ok {
			componentReq.Targets = append(componentReq.Targets, signerapi.ComponentTarget{
				TargetIndex: i, Kind: signerapi.ComponentTargetKindBoundedBase,
				AuthAddress: request.AuthAddress, LsigArgs: request.LsigArgs,
			})
		} else {
			componentReq.ContextualPositions = append(componentReq.ContextualPositions, signerapi.ComponentContextPosition{
				TargetIndex: i, LsigResources: request.LsigResources, PQScheme: request.PQScheme,
			})
		}
	}
	for i := len(txns); i < len(planResp.Transactions); i++ {
		componentReq.DummyPositions = append(componentReq.DummyPositions, signerapi.ComponentDummyPosition{TargetIndex: i})
	}
	componentResp, err := s.conn.RequestComponentsWithContext(opts.Ctx, componentReq)
	if err != nil {
		return nil, nil, fmt.Errorf("bounded base component signing failed: %w", err)
	}
	if err := validateBoundedTargetFees(plannedTxns, targets); err != nil {
		return nil, nil, err
	}
	groupBytesHex := append([]string(nil), planResp.Transactions...)
	components := make(map[int]signerapi.Component, len(componentResp.Components))
	for _, component := range componentResp.Components {
		target, ok := targetsByIndex[component.TargetIndex]
		if !ok || component.Kind != signerapi.ComponentTargetKindBoundedBase || component.AuthAddress != target.Account {
			return nil, nil, fmt.Errorf("signer returned unexpected bounded component target %d", component.TargetIndex)
		}
		if _, duplicate := components[component.TargetIndex]; duplicate {
			return nil, nil, fmt.Errorf("signer returned duplicate bounded component target %d", component.TargetIndex)
		}
		components[component.TargetIndex] = component
	}
	for _, target := range targets {
		if _, ok := components[target.Index]; !ok {
			return nil, nil, fmt.Errorf("signer returned no bounded component for target index %d", target.Index)
		}
	}

	// User policy and operator approval completed before this point. Only now
	// may the client disclose the frozen group to the sentry endpoint.
	sentrySignatures, sentryRequestIDs, err := s.requestSentryComponentSignatures(opts.Ctx, groupBytesHex, targets)
	if err != nil {
		return nil, nil, err
	}
	signedDummyHex, err := signGuardedDummies(plannedTxns[len(txns):])
	if err != nil {
		return nil, nil, err
	}
	nonGuardedSignedHex, err := s.requestNonGuardedSignatures(opts.Ctx, plannedTxns, groupBytesHex, len(txns), targetsByIndex, opts)
	if err != nil {
		return nil, nil, err
	}
	assemblyReq := signerapi.AssemblyRequest{
		GroupBytesHex: groupBytesHex,
		Targets:       make([]signerapi.AssemblyTarget, 0, len(targets)),
		Passthrough:   make([]signerapi.AssemblyPassthroughItem, 0, len(nonGuardedSignedHex)+len(signedDummyHex)),
	}
	for _, target := range targets {
		component := components[target.Index]
		sentrySignature, ok := sentrySignatures[target.Index]
		if !ok {
			return nil, nil, fmt.Errorf("sentry endpoint returned no signature for target index %d", target.Index)
		}
		assemblyReq.Targets = append(assemblyReq.Targets, signerapi.AssemblyTarget{
			TargetIndex: target.Index, Kind: signerapi.AssemblyTargetKindBoundedSentry, AuthAddress: target.Account,
			BaseSignatures: component.BaseSignatures, BoundedRuntimeArgs: component.RuntimeArgs,
			AssemblyReceipt: component.AssemblyReceipt, BaseSourceRequestID: componentResp.RequestID,
			SentrySignature: sentrySignature, SentrySourceRequestID: sentryRequestIDs[target.requestKey()],
		})
	}
	for index, signedHex := range nonGuardedSignedHex {
		assemblyReq.Passthrough = append(assemblyReq.Passthrough, signerapi.AssemblyPassthroughItem{TargetIndex: index, SignedTxnHex: signedHex})
	}
	for i, signedHex := range signedDummyHex {
		assemblyReq.Passthrough = append(assemblyReq.Passthrough, signerapi.AssemblyPassthroughItem{TargetIndex: len(txns) + i, SignedTxnHex: signedHex})
	}
	assemblyResp, err := s.conn.RequestAssembleWithContext(opts.Ctx, assemblyReq)
	if err != nil {
		return nil, nil, fmt.Errorf("bounded-sentry assembly failed: %w", err)
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

func (s *Signer) buildBoundedComponentRequests(txns []types.Transaction, targetsByIndex map[int]guardedTarget, opts clientsign.SubmitOptions) ([]signerapi.SignRequest, error) {
	requests := make([]signerapi.SignRequest, len(txns))
	for i, txn := range txns {
		txnHex := txnutil.EncodeWithPrefixHex(txn)
		if target, ok := targetsByIndex[i]; ok {
			requests[i] = signerapi.SignRequest{AuthAddress: target.Account, TxnSender: target.Sender, TxnBytesHex: txnHex}
			if i < len(opts.LsigArgsMap) && opts.LsigArgsMap[i] != nil {
				requests[i].LsigArgs = make(map[string]string, len(opts.LsigArgsMap[i]))
				for name, value := range opts.LsigArgsMap[i] {
					requests[i].LsigArgs[name] = hex.EncodeToString(value)
				}
			}
			if i < len(opts.AppCallInfo) {
				requests[i].AppCallInfo = opts.AppCallInfo[i]
			}
			continue
		}
		effectiveSigner := s.authCache.ResolveEffectiveSigner(txn.Sender.String())
		requests[i] = signerapi.SignRequest{TxnBytesHex: txnHex}
		if err := applyForeignAuthorizationHint(&requests[i], s.cache, effectiveSigner); err != nil {
			return nil, fmt.Errorf("prepare foreign transaction %d: %w", i+1, err)
		}
	}
	return requests, nil
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

// validateBoundedComponentPlan permits only the planner's contracted
// mutations to original positions: reported fee pooling and group-ID
// assignment. Appended positions must be canonical budget dummies.
func validateBoundedComponentPlan(original, planned []types.Transaction, mutations *signerapi.MutationReport) error {
	if len(planned) < len(original) {
		return fmt.Errorf("signer returned %d bounded group positions, want at least %d", len(planned), len(original))
	}
	appended := len(planned) - len(original)
	if mutations == nil {
		if appended != 0 {
			return fmt.Errorf("signer appended %d bounded group positions without a mutation report", appended)
		}
	} else {
		if mutations.OriginalCount != len(original) {
			return fmt.Errorf("bounded mutation original_count %d does not match request count %d", mutations.OriginalCount, len(original))
		}
		if mutations.FinalCount != len(planned) {
			return fmt.Errorf("bounded mutation final_count %d does not match returned count %d", mutations.FinalCount, len(planned))
		}
		if mutations.DummiesAdded != appended {
			return fmt.Errorf("bounded mutation dummies_added %d does not match appended count %d", mutations.DummiesAdded, appended)
		}
	}

	feeModified := make(map[int]struct{})
	if mutations != nil {
		for _, index := range mutations.FeesModified {
			if index < 0 || index >= len(original) {
				return fmt.Errorf("bounded mutation fee index %d is outside original positions", index)
			}
			if _, duplicate := feeModified[index]; duplicate {
				return fmt.Errorf("bounded mutation fee index %d is duplicated", index)
			}
			feeModified[index] = struct{}{}
		}
	}
	if mutations != nil && mutations.GroupIDChanged && appended == 0 && len(feeModified) == 0 {
		var zero types.Digest
		requiresAssignment := false
		for i := range original {
			requiresAssignment = requiresAssignment || original[i].Group == zero
		}
		if !requiresAssignment {
			return fmt.Errorf("signer changed an existing bounded group ID without a fee or membership mutation")
		}
	}
	totalFeeDelta := uint64(0)
	for i := range original {
		want := original[i]
		got := planned[i]
		if mutations != nil && mutations.GroupIDChanged {
			want.Group = got.Group
		}
		if _, ok := feeModified[i]; ok {
			if got.Fee < want.Fee {
				return fmt.Errorf("bounded mutation decreased fee at original position %d", i)
			}
			totalFeeDelta += uint64(got.Fee - want.Fee)
			want.Fee = got.Fee
		}
		if !bytes.Equal(txnutil.EncodeWithPrefix(want), txnutil.EncodeWithPrefix(got)) {
			return fmt.Errorf("signer changed unreported fields at bounded original position %d", i)
		}
	}
	if mutations != nil && uint64(mutations.TotalFeesDelta) != totalFeeDelta {
		return fmt.Errorf("bounded mutation total_fees_delta %d does not match observed delta %d", mutations.TotalFeesDelta, totalFeeDelta)
	}
	if err := validateGuardedDummies(planned[len(original):]); err != nil {
		return err
	}
	return nil
}

func validateBoundedTargetFees(planned []types.Transaction, targets []guardedTarget) error {
	for _, target := range targets {
		if target.Index < 0 || target.Index >= len(planned) {
			return fmt.Errorf("bounded target index %d is outside planned group", target.Index)
		}
		if fee := uint64(planned[target.Index].Fee); fee > target.BoundedMaxFee {
			return fmt.Errorf("bounded target %d fee %d exceeds advertised max_fee %d", target.Index, fee, target.BoundedMaxFee)
		}
	}
	return nil
}

// requestNonGuardedSignatures signs the non-guarded original positions of a
// mixed guarded group over the frozen canonical bytes, so every signature in
// the group commits to the same final transaction IDs. Guarded targets and
// dummies are sent as foreign — guarded with an LogicSig resource hint for the guarded
// authorizer so the signer's budget accounting stays exact and honest — and
// only the non-guarded originals are signed; the guarded positions are
// assembled later via /sign/assemble. Returns signed-transaction hex keyed by
// group index. When there are no non-guarded originals (the all-guarded case)
// it makes no signer call.
// buildGroupSignRequests builds the per-position /sign request array for the
// frozen guarded group: dummies as foreign placeholders, guarded targets as
// foreign entries with LogicSig resource hints, and non-guarded originals in sign
// mode. It returns the requests plus the non-guarded sign-mode indices.
func (s *Signer) buildGroupSignRequests(plannedTxns []types.Transaction, groupBytesHex []string, originalCount int, guardedTargets map[int]guardedTarget, opts clientsign.SubmitOptions) ([]signerapi.SignRequest, []int, error) {
	signRequests := make([]signerapi.SignRequest, len(plannedTxns))
	nonGuarded := make([]int, 0, originalCount)
	for i := range plannedTxns {
		sender := plannedTxns[i].Sender.String()
		switch {
		case i >= originalCount:
			// Dummy: foreign. Already signed locally and passed through at assembly.
			signRequests[i] = signerapi.SignRequest{
				TxnBytesHex: groupBytesHex[i],
				LsigResources: &signerapi.LogicSigResourceUsage{
					ProgramBytes:  uint64(len(signing.EmbeddedDummyTealTok)),
					MaxOpcodeCost: 1,
				},
			}
		case guardedTargets[i].Account != "":
			// Guarded target: foreign with a LogicSig resource hint. Kept in the group
			// for context and budget accounting but not signed here.
			target := guardedTargets[i]
			if target.Sender != sender {
				return nil, nil, fmt.Errorf("guarded target %d sender %s does not match transaction sender %s", i, target.Sender, sender)
			}
			signRequests[i] = signerapi.SignRequest{TxnBytesHex: groupBytesHex[i]}
			path, err := guardedLogicSigResourcePath(target.Flow)
			if err != nil {
				return nil, nil, fmt.Errorf("guarded target %d: %w", i, err)
			}
			if err := applyForeignLogicSigPathHint(&signRequests[i], s.cache, target.Account, path); err != nil {
				return nil, nil, fmt.Errorf("guarded target %d: %w", i, err)
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
	return signRequests, nonGuarded, nil
}

func guardedLogicSigResourcePath(flow string) (lsigresource.AuthorizationPath, error) {
	switch flow {
	case "", signerapi.SigningFlowSentry1:
		return lsigresource.PathDefault, nil
	case signerapi.SigningFlowBoundedSentry1:
		// Bounded component preparation admits only the pure-spend path. Carry
		// that exact path into the later mixed-group /sign call rather than
		// replacing it with the maximum across unrelated rekey paths.
		return lsigresource.PathSpend, nil
	default:
		return 0, fmt.Errorf("unsupported guarded signing flow %q", flow)
	}
}

func applyForeignLogicSigPathHint(request *signerapi.SignRequest, cache SignerCacheView, address string, path lsigresource.AuthorizationPath) error {
	if request == nil || cache == nil {
		return fmt.Errorf("LogicSig resource cache is unavailable")
	}
	profile, ok := cache.LogicSigResourceProfile(address)
	if !ok {
		return fmt.Errorf("LogicSig resource profile for %s is unavailable", address)
	}
	usage, err := profile.UsageForPath(path)
	if err != nil {
		return fmt.Errorf("resolve selected LogicSig resource path for %s: %w", address, err)
	}
	request.LsigResources = &signerapi.LogicSigResourceUsage{
		ProgramBytes:  usage.ProgramBytes,
		ArgumentBytes: usage.ArgumentBytes,
		MaxOpcodeCost: usage.MaxOpcodeCost,
	}
	return nil
}

func applyForeignAuthorizationHint(request *signerapi.SignRequest, cache SignerCacheView, address string) error {
	if request == nil || cache == nil {
		return fmt.Errorf("signer cache is unavailable")
	}
	kind, present := cache.AuthorizationKind(address)
	if !present {
		return nil
	}
	if kind == "" {
		return fmt.Errorf("authorization metadata for %s is unavailable", address)
	}
	if kind == authorizationNativePQ {
		request.PQScheme = signerapi.PQSchemeFalcon1024
		return nil
	}
	if kind != authorizationLogicSig {
		return nil
	}
	profile, ok := cache.LogicSigResourceProfile(address)
	if !ok {
		return fmt.Errorf("LogicSig resource profile for %s is unavailable", address)
	}
	usage := conservativeLogicSigResourceUsage(profile)
	if usage == nil {
		return fmt.Errorf("LogicSig resource profile for %s is invalid", address)
	}
	request.LsigResources = usage
	return nil
}

func conservativeLogicSigResourceUsage(profile lsigresource.Profile) *signerapi.LogicSigResourceUsage {
	var argumentBytes, opcodeCost uint64
	paths := []*lsigresource.PathProfile{profile.Default, profile.Spend, profile.SpendingRekey, profile.AdminRekey}
	for _, path := range paths {
		if path == nil {
			continue
		}
		argumentBytes = max(argumentBytes, path.ArgumentBytes)
		opcodeCost = max(opcodeCost, path.MaxOpcodeCost)
	}
	if profile.ProgramBytes == 0 || opcodeCost == 0 {
		return nil
	}
	return &signerapi.LogicSigResourceUsage{
		ProgramBytes:  profile.ProgramBytes,
		ArgumentBytes: argumentBytes,
		MaxOpcodeCost: opcodeCost,
	}
}

func (s *Signer) requestNonGuardedSignatures(ctx context.Context, plannedTxns []types.Transaction, groupBytesHex []string, originalCount int, guardedTargets map[int]guardedTarget, opts clientsign.SubmitOptions) (map[int]string, error) {
	signRequests, nonGuarded, err := s.buildGroupSignRequests(plannedTxns, groupBytesHex, originalCount, guardedTargets, opts)
	if err != nil {
		return nil, err
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
		switch routeForSigningFlow(flow) {
		case flowRoutePlain:
			continue
		case flowRouteGuarded, flowRouteBoundedSentry:
		default:
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
		var boundedMaxFee uint64
		if flow == signerapi.SigningFlowBoundedSentry1 {
			var found bool
			boundedMaxFee, found = s.cache.BoundedMaxFee(account)
			if !found {
				return nil, fmt.Errorf("bounded account %s is missing max_fee metadata; run keys refresh", account)
			}
		}
		targets = append(targets, guardedTarget{
			Index:                  i,
			Sender:                 sender,
			Account:                account,
			SentryComponentKeyType: sentryComponentKeyType,
			SentryPublicKey:        canonicalPublicKey,
			Flow:                   flow,
			BoundedMaxFee:          boundedMaxFee,
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
// per-family size table is consulted: integrity comes from the Witness Key ID
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
	return witness.DeriveID(componentKeyType, publicKey), nil
}

func sentryComponentLabel(componentKeyType, sentryPublicKey string) string {
	selector, err := sentryComponentSelector(componentKeyType, sentryPublicKey)
	if err == nil {
		return fmt.Sprintf("Witness Key ID %s (%s)", selector, componentKeyType)
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
	if err := validateGuardedDummies(dummyTxns); err != nil {
		return nil, err
	}
	signedDummies, err := signing.SignDummyTransactions(dummyTxns)
	if err != nil {
		return nil, fmt.Errorf("failed to sign guarded dummy transactions: %w", err)
	}
	signedHex := make([]string, len(signedDummies))
	for i, signed := range signedDummies {
		signedHex[i] = hex.EncodeToString(signed)
	}
	return signedHex, nil
}

func validateGuardedDummies(dummyTxns []types.Transaction) error {
	dummyAddress, err := signing.DummyAddress()
	if err != nil {
		return fmt.Errorf("failed to derive guarded dummy address: %w", err)
	}
	for i, txn := range dummyTxns {
		if txn.Type != types.PaymentTx || txn.Sender != dummyAddress || txn.Receiver != dummyAddress ||
			txn.Amount != 0 || txn.Fee != 0 || len(txn.Note) != 1 || txn.Note[0] != byte(i) ||
			!txn.RekeyTo.IsZero() || !txn.CloseRemainderTo.IsZero() {
			return fmt.Errorf("signer-appended transaction %d is not a canonical guarded budget dummy", i)
		}
	}
	return nil
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
		return "", fmt.Errorf("failed to derive Witness Key ID for sentry public key %s: %w", shortSentryPublicKeyHex(sentryKey.PublicKey), err)
	}
	componentLabel := fmt.Sprintf("Witness Key ID %s (%s)", componentSelector, sentryKey.ComponentKeyType)

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
