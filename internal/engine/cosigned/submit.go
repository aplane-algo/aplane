// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cosigned

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
	"github.com/aplane-algo/aplane/internal/cosigner/canonical"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

type cosignedTarget struct {
	Index                    int
	Sender                   string
	Account                  string
	CosignerComponentKeyType string
	CosignerPublicKey        string
	Route                    flowRoute
	// BoundedMaxFee is a bounded host's fee ceiling, nil on a plain host.
	BoundedMaxFee *uint64
	// BoundedPath is the path the signer's base component named for a cosigned
	// target, once components are in: what the position is budgeted on.
	BoundedPath string
}

type cosignerRequestKey struct {
	ComponentKeyType string
	PublicKey        string
}

// flowRoute is the client-side route a signing_flow label takes. Every flow
// label is classified in exactly one place, routeForSigningFlow, and targets
// carry the result, so the cosigned pre-check, target assembly, and resource
// hints cannot disagree about a label.
type flowRoute int

const (
	// flowRoutePlain signs through the ordinary client path. Bounded1 belongs
	// here: it has its own transaction-aware server-side path behind /sign.
	flowRoutePlain flowRoute = iota
	// flowRouteBoundedCosigner routes through the cosigned1 component
	// orchestration.
	flowRouteBoundedCosigner
	// flowRouteUnknown fails closed: the client must be upgraded. Unknown
	// labels still enter cosigned routing so cosignedTargets rejects them
	// explicitly instead of silently falling through to ordinary signing.
	flowRouteUnknown
)

func routeForSigningFlow(flow string) flowRoute {
	switch flow {
	case "", signerapi.SigningFlowBounded1:
		return flowRoutePlain
	case signerapi.SigningFlowCosigned1:
		return flowRouteBoundedCosigner
	default:
		return flowRouteUnknown
	}
}

// CanAuthorizeOtherAccounts reports whether an account on flow may be another
// account's auth address: the client can route signing for an account
// rekeyed to it. It fails closed, so a flow this client does not know,
// rotating1 included, is never an acceptable rekey target.
func CanAuthorizeOtherAccounts(flow string) bool {
	return routeForSigningFlow(flow) != flowRouteUnknown
}

// frozenGroup is the signer-planned group that every component, signature,
// and assembly commits to. Positions from OriginalCount on are budget dummies.
type frozenGroup struct {
	BytesHex      []string
	Txns          []types.Transaction
	OriginalCount int
}

// HasCosignedEffectiveSigner reports whether any transaction's effective
// signer declares a component signing flow (signing_flow in signer
// inventory).
func (s *Signer) HasCosignedEffectiveSigner(txns []types.Transaction) bool {
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

	targets, err := s.cosignedTargets(txns)
	if err != nil {
		return nil, nil, err
	}
	if len(targets) == 0 {
		return nil, nil, fmt.Errorf("cosigned signing selected with no cosigned effective signers")
	}
	targetsByIndex := make(map[int]cosignedTarget, len(targets))
	for _, target := range targets {
		targetsByIndex[target.Index] = target
	}
	return s.signAndSubmitBoundedCosignerGroup(txns, targets, targetsByIndex, opts, w)
}

// signAndSubmitBoundedCosignerGroup runs the cosigned1 choreography: the user
// signer's base components, then the cosigner's for each target whose path needs
// one. A listed rekey takes none: the signer's component says so, and assembly
// checks it again.
func (s *Signer) signAndSubmitBoundedCosignerGroup(txns []types.Transaction, targets []cosignedTarget, targetsByIndex map[int]cosignedTarget, opts clientsign.SubmitOptions, w io.Writer) ([]string, []types.Transaction, error) {
	requests, err := s.buildBoundedComponentRequests(txns, targetsByIndex, opts)
	if err != nil {
		return nil, nil, err
	}
	group, err := s.planFrozenGroup(opts.Ctx, txns, requests, w)
	if err != nil {
		return nil, nil, err
	}
	if err := validateBoundedTargetFees(group.Txns, targets); err != nil {
		return nil, nil, err
	}
	components, baseRequestID, err := s.requestBoundedBaseComponents(opts.Ctx, group, requests, targets, targetsByIndex, opts.AppCallInfo)
	if err != nil {
		return nil, nil, err
	}
	for i, target := range targets {
		target.BoundedPath = components[target.Index].Path
		targets[i], targetsByIndex[target.Index] = target, target
	}

	passthrough, err := s.signContextPositions(opts.Ctx, group, targetsByIndex, opts, w)
	if err != nil {
		return nil, nil, err
	}
	cosigned := make([]cosignedTarget, 0, len(targets))
	for _, target := range targets {
		if components[target.Index].NeedsCosigner() {
			cosigned = append(cosigned, target)
		}
	}
	// The user side is complete, including any non-cosigned positions. Only
	// now may the client disclose the frozen group to the cosigner endpoint,
	// and only for the targets that need it.
	var cosignerSignatures map[int]string
	var cosignerRequestIDs map[cosignerRequestKey]string
	if len(cosigned) > 0 {
		cosignerSignatures, cosignerRequestIDs, err = s.requestCosignerComponentSignatures(opts.Ctx, group.BytesHex, group.OriginalCount, cosigned, opts.AppCallInfo)
		if err != nil {
			return nil, nil, err
		}
	}
	if skipped := len(targets) - len(cosigned); skipped > 0 {
		_, _ = fmt.Fprintf(w, "[COSIGNED] %d listed rekey(s) need no cosigner\n", skipped)
	}

	assemblyTargets := make([]signerapi.AssemblyTarget, 0, len(targets))
	for _, target := range targets {
		component := components[target.Index]
		assemblyTarget := signerapi.AssemblyTarget{
			TargetIndex: target.Index, Kind: signerapi.AssemblyTargetKindBoundedCosigner, AuthAddress: target.Account,
			BaseSignatures: component.BaseSignatures, BoundedRuntimeArgs: component.RuntimeArgs,
			AssemblyReceipt: component.AssemblyReceipt, BaseSourceRequestID: baseRequestID,
		}
		if component.NeedsCosigner() {
			cosignerSignature, ok := cosignerSignatures[target.Index]
			if !ok {
				return nil, nil, fmt.Errorf("cosigner endpoint returned no signature for target index %d", target.Index)
			}
			assemblyTarget.CosignerSignature = cosignerSignature
			assemblyTarget.CosignerSourceRequestID = cosignerRequestIDs[target.requestKey()]
		}
		assemblyTargets = append(assemblyTargets, assemblyTarget)
	}
	return s.assembleAndSubmit(group, assemblyTargets, passthrough, opts, w)
}

// planFrozenGroup makes the signer-side consensus planner the sole authority
// for dummy membership, fee factors, and final group IDs, and admits only the
// planner's contracted mutations. Component signing begins only after these
// returned bytes are frozen.
func (s *Signer) planFrozenGroup(ctx context.Context, original []types.Transaction, requests []signerapi.SignRequest, w io.Writer) (frozenGroup, error) {
	response, err := s.conn.RequestGroupPlanWithContext(ctx, requests)
	if err != nil {
		return frozenGroup{}, fmt.Errorf("group planning failed: %w", err)
	}
	decoded, err := canonical.DecodeGroupHex(response.Transactions)
	if err != nil {
		return frozenGroup{}, fmt.Errorf("signer returned invalid group plan: %w", err)
	}
	planned := make([]types.Transaction, len(decoded.Entries))
	for i, entry := range decoded.Entries {
		planned[i] = entry.Txn
	}
	if err := validatePlannedGroup(original, planned, response.Mutations); err != nil {
		return frozenGroup{}, fmt.Errorf("invalid group plan: %w", err)
	}
	if dummies := len(planned) - len(original); dummies > 0 {
		_, _ = fmt.Fprintf(w, "[COSIGNED] Signer added %d dummy transaction(s) for LogicSig arguments/opcode budget\n", dummies)
	}
	// DecodeGroupHex admits only canonical encodings, so re-encoding yields the
	// signer's exact bytes in normalized hex.
	return frozenGroup{BytesHex: encodeGroupHex(planned), Txns: planned, OriginalCount: len(original)}, nil
}

// requestBoundedBaseComponents obtains the user signer's bounded base
// component for every target over the frozen group. This is where user policy
// and operator approval run for bounded targets, so every contextual position
// carries the caller's app call description: the approval shows another
// position's ABI method, as the cosigner's request does.
func (s *Signer) requestBoundedBaseComponents(ctx context.Context, group frozenGroup, requests []signerapi.SignRequest, targets []cosignedTarget, targetsByIndex map[int]cosignedTarget, appCallInfo []*signerapi.AppCallInfo) (map[int]signerapi.Component, string, error) {
	componentReq := signerapi.ComponentRequest{GroupBytesHex: group.BytesHex}
	for i, request := range requests {
		if _, ok := targetsByIndex[i]; ok {
			componentReq.Targets = append(componentReq.Targets, signerapi.ComponentTarget{
				TargetIndex: i, Kind: signerapi.ComponentTargetKindBoundedBase,
				AuthAddress: request.AuthAddress, LsigArgs: request.LsigArgs, AppCallInfo: request.AppCallInfo,
			})
		} else {
			position := signerapi.ComponentContextPosition{
				TargetIndex: i, LsigResources: request.LsigResources, PQScheme: request.PQScheme, AppCallInfo: request.AppCallInfo,
			}
			if i < len(appCallInfo) && appCallInfo[i] != nil {
				position.AppCallInfo = appCallInfo[i]
			}
			componentReq.ContextualPositions = append(componentReq.ContextualPositions, position)
		}
	}
	for i := group.OriginalCount; i < len(group.BytesHex); i++ {
		componentReq.DummyPositions = append(componentReq.DummyPositions, signerapi.ComponentDummyPosition{TargetIndex: i})
	}
	componentResp, err := s.conn.RequestComponentsWithContext(ctx, componentReq)
	if err != nil {
		return nil, "", fmt.Errorf("bounded base component signing failed: %w", err)
	}
	components := make(map[int]signerapi.Component, len(componentResp.Components))
	for _, component := range componentResp.Components {
		target, ok := targetsByIndex[component.TargetIndex]
		if !ok || component.Kind != signerapi.ComponentTargetKindBoundedBase || component.AuthAddress != target.Account {
			return nil, "", fmt.Errorf("signer returned unexpected bounded component target %d", component.TargetIndex)
		}
		if _, duplicate := components[component.TargetIndex]; duplicate {
			return nil, "", fmt.Errorf("signer returned duplicate bounded component target %d", component.TargetIndex)
		}
		components[component.TargetIndex] = component
	}
	for _, target := range targets {
		if _, ok := components[target.Index]; !ok {
			return nil, "", fmt.Errorf("signer returned no bounded component for target index %d", target.Index)
		}
	}
	return components, componentResp.RequestID, nil
}

// signContextPositions signs the frozen group's positions that are not cosigned
// targets, returning them as assembly passthrough items: budget dummies
// locally, and non-cosigned originals through /sign over the frozen bytes.
func (s *Signer) signContextPositions(ctx context.Context, group frozenGroup, targetsByIndex map[int]cosignedTarget, opts clientsign.SubmitOptions, w io.Writer) ([]signerapi.AssemblyPassthroughItem, error) {
	signedDummies, err := signCosignedDummies(group.Txns[group.OriginalCount:])
	if err != nil {
		return nil, err
	}
	if nonCosignedCount := group.OriginalCount - len(targetsByIndex); nonCosignedCount > 0 {
		_, _ = fmt.Fprintf(w, "[COSIGNED] Mixed group: signing %d non-cosigned position(s) over canonical bytes\n", nonCosignedCount)
	}
	signedOriginals, err := s.requestNonCosignedSignatures(ctx, group.Txns, group.BytesHex, group.OriginalCount, targetsByIndex, opts)
	if err != nil {
		return nil, err
	}
	passthrough := make([]signerapi.AssemblyPassthroughItem, 0, len(signedOriginals)+len(signedDummies))
	for i := 0; i < group.OriginalCount; i++ {
		if signedHex, ok := signedOriginals[i]; ok {
			passthrough = append(passthrough, signerapi.AssemblyPassthroughItem{TargetIndex: i, SignedTxnHex: signedHex})
		}
	}
	for i, signedHex := range signedDummies {
		passthrough = append(passthrough, signerapi.AssemblyPassthroughItem{TargetIndex: group.OriginalCount + i, SignedTxnHex: signedHex})
	}
	return passthrough, nil
}

// assembleAndSubmit has the signer assemble the frozen group, checks the
// result against the frozen bytes, and then simulates or submits it.
func (s *Signer) assembleAndSubmit(group frozenGroup, targets []signerapi.AssemblyTarget, passthrough []signerapi.AssemblyPassthroughItem, opts clientsign.SubmitOptions, w io.Writer) ([]string, []types.Transaction, error) {
	assemblyResp, err := s.conn.RequestAssembleWithContext(opts.Ctx, signerapi.AssemblyRequest{
		GroupBytesHex: group.BytesHex,
		Targets:       targets,
		Passthrough:   passthrough,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("group assembly failed: %w", err)
	}
	signedBytes, signedObjects, submittedTxns, err := decodeCosignedSignedGroup(assemblyResp.SignedGroup)
	if err != nil {
		return nil, nil, err
	}
	if err := verifyAssembledAgainstFrozen(group.BytesHex, submittedTxns); err != nil {
		return nil, nil, err
	}
	if opts.Simulate {
		txIDs, simErr := signing.SimulateSignedTransactionsWithContext(opts.Ctx, signedObjects, s.algod, w)
		writeCosignedSubmittedTransactions(opts.TxnWriter, submittedTxns, txIDs, group.OriginalCount)
		return txIDs, submittedTxns, simErr
	}
	txIDs, err := signing.SubmitTransactionsWithContext(opts.Ctx, signedBytes, s.algod, opts.WaitForConfirmation, w)
	if err != nil {
		return txIDs, submittedTxns, err
	}
	writeCosignedSubmittedTransactions(opts.TxnWriter, submittedTxns, txIDs, group.OriginalCount)
	return txIDs, submittedTxns, nil
}

// signModeRequest builds the sign-mode request for original position i,
// carrying the caller's LogicSig arguments and app-call context for it.
func signModeRequest(i int, authAddress, sender, txnHex string, opts clientsign.SubmitOptions) signerapi.SignRequest {
	request := signerapi.SignRequest{AuthAddress: authAddress, TxnSender: sender, TxnBytesHex: txnHex}
	if i < len(opts.LsigArgsMap) && opts.LsigArgsMap[i] != nil {
		request.LsigArgs = make(map[string]string, len(opts.LsigArgsMap[i]))
		for name, value := range opts.LsigArgsMap[i] {
			request.LsigArgs[name] = hex.EncodeToString(value)
		}
	}
	if i < len(opts.AppCallInfo) {
		request.AppCallInfo = opts.AppCallInfo[i]
	}
	return request
}

func (s *Signer) buildBoundedComponentRequests(txns []types.Transaction, targetsByIndex map[int]cosignedTarget, opts clientsign.SubmitOptions) ([]signerapi.SignRequest, error) {
	requests := make([]signerapi.SignRequest, len(txns))
	for i, txn := range txns {
		txnHex := txnutil.EncodeWithPrefixHex(txn)
		if target, ok := targetsByIndex[i]; ok {
			requests[i] = signModeRequest(i, target.Account, target.Sender, txnHex, opts)
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

// validatePlannedGroup permits only the planner's contracted mutations to
// original positions: reported fee pooling and group-ID assignment. Appended
// positions must be canonical budget dummies.
func validatePlannedGroup(original, planned []types.Transaction, mutations *signerapi.MutationReport) error {
	if len(planned) < len(original) {
		return fmt.Errorf("signer returned %d group positions, want at least %d", len(planned), len(original))
	}
	appended := len(planned) - len(original)
	if mutations == nil {
		if appended != 0 {
			return fmt.Errorf("signer appended %d group positions without a mutation report", appended)
		}
	} else {
		if mutations.OriginalCount != len(original) {
			return fmt.Errorf("mutation original_count %d does not match request count %d", mutations.OriginalCount, len(original))
		}
		if mutations.FinalCount != len(planned) {
			return fmt.Errorf("mutation final_count %d does not match returned count %d", mutations.FinalCount, len(planned))
		}
		if mutations.DummiesAdded != appended {
			return fmt.Errorf("mutation dummies_added %d does not match appended count %d", mutations.DummiesAdded, appended)
		}
	}

	feeModified := make(map[int]struct{})
	if mutations != nil {
		for _, index := range mutations.FeesModified {
			if index < 0 || index >= len(original) {
				return fmt.Errorf("mutation fee index %d is outside original positions", index)
			}
			if _, duplicate := feeModified[index]; duplicate {
				return fmt.Errorf("mutation fee index %d is duplicated", index)
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
			return fmt.Errorf("signer changed an existing group ID without a fee or membership mutation")
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
				return fmt.Errorf("mutation decreased fee at original position %d", i)
			}
			totalFeeDelta += uint64(got.Fee - want.Fee)
			want.Fee = got.Fee
		}
		if !bytes.Equal(txnutil.EncodeWithPrefix(want), txnutil.EncodeWithPrefix(got)) {
			return fmt.Errorf("signer changed unreported fields at original position %d", i)
		}
	}
	if mutations != nil && uint64(mutations.TotalFeesDelta) != totalFeeDelta {
		return fmt.Errorf("mutation total_fees_delta %d does not match observed delta %d", mutations.TotalFeesDelta, totalFeeDelta)
	}
	if err := validateCosignedDummies(planned[len(original):]); err != nil {
		return err
	}
	return nil
}

func validateBoundedTargetFees(planned []types.Transaction, targets []cosignedTarget) error {
	for _, target := range targets {
		if target.Index < 0 || target.Index >= len(planned) {
			return fmt.Errorf("bounded target index %d is outside planned group", target.Index)
		}
		if target.BoundedMaxFee == nil {
			continue
		}
		if fee := uint64(planned[target.Index].Fee); fee > *target.BoundedMaxFee {
			return fmt.Errorf("bounded target %d fee %d exceeds advertised max_fee %d", target.Index, fee, *target.BoundedMaxFee)
		}
	}
	return nil
}

// buildGroupSignRequests builds the per-position /sign request array for the
// frozen cosigned group: dummies as foreign placeholders, cosigned targets as
// foreign entries with LogicSig resource hints, and non-cosigned originals in sign
// mode. It returns the requests plus the non-cosigned sign-mode indices.
func (s *Signer) buildGroupSignRequests(plannedTxns []types.Transaction, groupBytesHex []string, originalCount int, cosignedTargets map[int]cosignedTarget, opts clientsign.SubmitOptions) ([]signerapi.SignRequest, []int, error) {
	signRequests := make([]signerapi.SignRequest, len(plannedTxns))
	nonCosigned := make([]int, 0, originalCount)
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
		case cosignedTargets[i].Account != "":
			// Cosigned target: foreign with a LogicSig resource hint. Kept in the group
			// for context and budget accounting but not signed here.
			target := cosignedTargets[i]
			if target.Sender != sender {
				return nil, nil, fmt.Errorf("cosigned target %d sender %s does not match transaction sender %s", i, target.Sender, sender)
			}
			signRequests[i] = signerapi.SignRequest{TxnBytesHex: groupBytesHex[i]}
			path, err := cosignedLogicSigResourcePath(target)
			if err != nil {
				return nil, nil, fmt.Errorf("cosigned target %d: %w", i, err)
			}
			if err := applyForeignLogicSigPathHint(&signRequests[i], s.cache, target.Account, path); err != nil {
				return nil, nil, fmt.Errorf("cosigned target %d: %w", i, err)
			}
		default:
			// Non-cosigned original: sign mode over the canonical bytes. Resolve
			// the effective signer so a rekeyed account is signed by — and
			// budgeted against — its auth address, matching the plan request.
			effectiveSigner := s.authCache.ResolveEffectiveSigner(sender)
			signRequests[i] = signModeRequest(i, effectiveSigner, sender, groupBytesHex[i], opts)
			nonCosigned = append(nonCosigned, i)
		}
	}
	return signRequests, nonCosigned, nil
}

func cosignedLogicSigResourcePath(target cosignedTarget) (lsigresource.AuthorizationPath, error) {
	switch target.Route {
	case flowRouteBoundedCosigner:
		// Carry the exact path the signer's base component named into the later
		// mixed-group /sign call, rather than the maximum across unrelated paths.
		switch target.BoundedPath {
		case signerapi.ComponentPathSpend:
			return lsigresource.PathSpend, nil
		case signerapi.ComponentPathSpendingRekey:
			return lsigresource.PathSpendingRekey, nil
		case signerapi.ComponentPathListedRekey:
			return lsigresource.PathListedRekey, nil
		default:
			return 0, fmt.Errorf("cosigned target has no base component path yet")
		}
	default:
		return 0, fmt.Errorf("cosigned target has unsupported flow route %d", target.Route)
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
	paths := []*lsigresource.PathProfile{profile.Default, profile.Spend, profile.SpendingRekey, profile.ListedRekey}
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

// requestNonCosignedSignatures signs the non-cosigned original positions of a
// mixed cosigned group over the frozen canonical bytes, so every signature in
// the group commits to the same final transaction IDs. Cosigned targets and
// dummies are sent as foreign — cosigned with a LogicSig resource hint for the cosigned
// authorizer so the signer's budget accounting stays exact and honest — and
// only the non-cosigned originals are signed; the cosigned positions are
// assembled later via /sign/assemble. Returns signed-transaction hex keyed by
// group index. When there are no non-cosigned originals (the all-cosigned case)
// it makes no signer call.
func (s *Signer) requestNonCosignedSignatures(ctx context.Context, plannedTxns []types.Transaction, groupBytesHex []string, originalCount int, cosignedTargets map[int]cosignedTarget, opts clientsign.SubmitOptions) (map[int]string, error) {
	signRequests, nonCosigned, err := s.buildGroupSignRequests(plannedTxns, groupBytesHex, originalCount, cosignedTargets, opts)
	if err != nil {
		return nil, err
	}

	if len(nonCosigned) == 0 {
		return map[int]string{}, nil
	}

	signResp, err := s.conn.RequestGroupSignWithContext(ctx, signRequests)
	if err != nil {
		return nil, fmt.Errorf("signing non-cosigned group positions failed: %w", err)
	}
	if len(signResp.Signed) != len(signRequests) {
		return nil, fmt.Errorf("signer returned %d signed position(s), want %d", len(signResp.Signed), len(signRequests))
	}

	signed := make(map[int]string, len(nonCosigned))
	for _, i := range nonCosigned {
		if signResp.Signed[i] == "" {
			return nil, fmt.Errorf("signer returned no signature for non-cosigned position %d", i+1)
		}
		signed[i] = signResp.Signed[i]
	}
	return signed, nil
}

func (s *Signer) cosignedTargets(txns []types.Transaction) ([]cosignedTarget, error) {
	targets := make([]cosignedTarget, 0, len(txns))
	for i, txn := range txns {
		sender := txn.Sender.String()
		account := s.authCache.ResolveEffectiveSigner(sender)
		flow := s.cache.SigningFlow(account)
		route := routeForSigningFlow(flow)
		switch route {
		case flowRoutePlain:
			continue
		case flowRouteBoundedCosigner:
		default:
			return nil, fmt.Errorf("account %s requires signing flow %q, which this client does not support; upgrade the client", account, flow)
		}
		cosignerComponentKeyType, ok := s.cache.CosignerComponentKeyType(account)
		if !ok {
			return nil, fmt.Errorf("cosigned account %s is missing cosigner_component_key_type metadata; run keys refresh", account)
		}
		cosignerPublicKey, ok := s.cache.CosignerPublicKey(account)
		if !ok || cosignerPublicKey == "" {
			return nil, fmt.Errorf("cosigned account %s is missing cosigner_public_key metadata; run keys refresh", account)
		}
		canonicalPublicKey, err := normalizeCosignerPublicKeyHex(cosignerPublicKey)
		if err != nil {
			return nil, fmt.Errorf("cosigned account %s has invalid cosigner_public_key metadata: %w", account, err)
		}
		boundedMaxFee, err := s.boundedFeeCeiling(account)
		if err != nil {
			return nil, err
		}
		targets = append(targets, cosignedTarget{
			Index:                    i,
			Sender:                   sender,
			Account:                  account,
			CosignerComponentKeyType: cosignerComponentKeyType,
			CosignerPublicKey:        canonicalPublicKey,
			Route:                    route,
			BoundedMaxFee:            boundedMaxFee,
		})
	}
	return targets, nil
}

// boundedFeeCeiling is a cosigned account's on-chain fee ceiling: a bounded
// host has one, a plain host has none. Missing metadata, or a contract this
// client doesn't know, fails closed.
func (s *Signer) boundedFeeCeiling(account string) (*uint64, error) {
	contract, found := s.cache.BoundedContract(account)
	if !found {
		return nil, fmt.Errorf("bounded account %s is missing contract metadata; run keys refresh", account)
	}
	switch contract {
	case signerapi.BoundedContractBounded2:
		maxFee, found := s.cache.BoundedMaxFee(account)
		if !found {
			return nil, fmt.Errorf("bounded account %s is missing max_fee metadata; run keys refresh", account)
		}
		return &maxFee, nil
	case signerapi.BoundedContractPlain1:
		return nil, nil
	default:
		return nil, fmt.Errorf("bounded account %s has contract %q, which this client does not support; upgrade the client", account, contract)
	}
}

func (t cosignedTarget) requestKey() cosignerRequestKey {
	return cosignerRequestKey{
		ComponentKeyType: t.CosignerComponentKeyType,
		PublicKey:        t.CosignerPublicKey,
	}
}

// normalizeCosignerPublicKeyHex canonicalizes a cosigner public key as lowercase
// hex. Component key types and public keys are runtime metadata, so no
// per-family size table is consulted: integrity comes from the Witness Key ID
// selector matching the advertising endpoint and, authoritatively, from the
// on-chain LogicSig.
func normalizeCosignerPublicKeyHex(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("cosigner public key is required")
	}
	trimmed = strings.TrimPrefix(strings.TrimPrefix(trimmed, "0x"), "0X")
	publicKey, err := hex.DecodeString(trimmed)
	if err != nil {
		return "", fmt.Errorf("cosigner public key must be hex: %w", err)
	}
	if len(publicKey) == 0 {
		return "", fmt.Errorf("cosigner public key is empty")
	}
	return hex.EncodeToString(publicKey), nil
}

func cosignerComponentSelector(componentKeyType string, cosignerPublicKey string) (string, error) {
	if componentKeyType == "" {
		return "", fmt.Errorf("cosigner component key type is required")
	}
	canonicalPublicKey, err := normalizeCosignerPublicKeyHex(cosignerPublicKey)
	if err != nil {
		return "", err
	}
	publicKey, err := hex.DecodeString(canonicalPublicKey)
	if err != nil {
		return "", err
	}
	return witness.DeriveID(componentKeyType, publicKey), nil
}

func cosignerComponentLabel(componentKeyType, cosignerPublicKey string) string {
	selector, err := cosignerComponentSelector(componentKeyType, cosignerPublicKey)
	if err == nil {
		return fmt.Sprintf("Witness Key ID %s (%s)", selector, componentKeyType)
	}
	return fmt.Sprintf("cosigner public key %s (%s)", shortCosignerPublicKeyHex(cosignerPublicKey), componentKeyType)
}

func shortCosignerPublicKeyHex(publicKeyHex string) string {
	trimmed := strings.TrimSpace(publicKeyHex)
	trimmed = strings.TrimPrefix(strings.TrimPrefix(trimmed, "0x"), "0X")
	if len(trimmed) <= 24 {
		return trimmed
	}
	return trimmed[:12] + "..." + trimmed[len(trimmed)-12:]
}

func encodeGroupHex(txns []types.Transaction) []string {
	groupHex := make([]string, len(txns))
	for i, txn := range txns {
		groupHex[i] = txnutil.EncodeWithPrefixHex(txn)
	}
	return groupHex
}

func signCosignedDummies(dummyTxns []types.Transaction) ([]string, error) {
	if err := validateCosignedDummies(dummyTxns); err != nil {
		return nil, err
	}
	signedDummies, err := signing.SignDummyTransactions(dummyTxns)
	if err != nil {
		return nil, fmt.Errorf("failed to sign cosigned dummy transactions: %w", err)
	}
	signedHex := make([]string, len(signedDummies))
	for i, signed := range signedDummies {
		signedHex[i] = hex.EncodeToString(signed)
	}
	return signedHex, nil
}

func validateCosignedDummies(dummyTxns []types.Transaction) error {
	dummyAddress, err := signing.DummyAddress()
	if err != nil {
		return fmt.Errorf("failed to derive cosigned dummy address: %w", err)
	}
	for i, txn := range dummyTxns {
		if txn.Type != types.PaymentTx || txn.Sender != dummyAddress || txn.Receiver != dummyAddress ||
			txn.Amount != 0 || txn.Fee != 0 || len(txn.Note) != 1 || txn.Note[0] != byte(i) ||
			!txn.RekeyTo.IsZero() || !txn.CloseRemainderTo.IsZero() {
			return fmt.Errorf("signer-appended transaction %d is not a canonical cosigned budget dummy", i)
		}
	}
	return nil
}

func (s *Signer) requestCosignerComponentSignatures(ctx context.Context, groupBytesHex []string, originalCount int, targets []cosignedTarget, appCallInfo []*signerapi.AppCallInfo) (map[int]string, map[cosignerRequestKey]string, error) {
	byCosigner := make(map[cosignerRequestKey][]int)
	for _, target := range targets {
		key := target.requestKey()
		byCosigner[key] = append(byCosigner[key], target.Index)
	}
	required := make([]cosignerRequestKey, 0, len(byCosigner))
	for key := range byCosigner {
		required = append(required, key)
	}
	snapshot, err := s.resolveCosignerEndpoints(ctx, required)
	if err != nil {
		return nil, nil, err
	}
	defer snapshot.close()
	required = distinctSortedCosignerRequestKeys(required)
	signatures := make(map[int]string, len(targets))
	requestIDs := make(map[cosignerRequestKey]string, len(byCosigner))
	for _, cosignerKey := range required {
		requestID, err := s.requestOneCosignerComponentSignatureSet(ctx, snapshot.routes[cosignerKey], groupBytesHex, originalCount, cosignerKey, byCosigner[cosignerKey], signatures, appCallInfo)
		if err != nil {
			return nil, nil, err
		}
		requestIDs[cosignerKey] = requestID
	}
	return signatures, requestIDs, nil
}

// requestOneCosignerComponentSignatureSet collects component signatures from a
// cosigner endpoint without verifying them cryptographically: the client treats
// component signatures as opaque material. Invalid signatures are rejected by
// the signer during cosigned assembly and, authoritatively, by the cosigned
// LogicSig on-chain.
func (s *Signer) requestOneCosignerComponentSignatureSet(ctx context.Context, endpoint *resolvedCosignerEndpoint, groupBytesHex []string, originalCount int, cosignerKey cosignerRequestKey, indices []int, signatures map[int]string, appCallInfo []*signerapi.AppCallInfo) (string, error) {
	componentSelector, err := cosignerComponentSelector(cosignerKey.ComponentKeyType, cosignerKey.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to derive Witness Key ID for cosigner public key %s: %w", shortCosignerPublicKeyHex(cosignerKey.PublicKey), err)
	}
	componentLabel := fmt.Sprintf("Witness Key ID %s (%s)", componentSelector, cosignerKey.ComponentKeyType)

	resp, err := endpoint.client.RequestComponentsWithContext(ctx, componentRequestForIndices(groupBytesHex, originalCount, indices, signerapi.ComponentTargetKindCosigner, componentSelector, appCallInfo))
	if err != nil {
		return "", fmt.Errorf("cosigner component signing failed for %s via %s: %w", componentLabel, endpoint.source, err)
	}
	if err := collectComponentSignatures(resp, indices, cosignerKey.ComponentKeyType, signatures); err != nil {
		return "", fmt.Errorf("cosigner component signing failed for %s via %s: %w", componentLabel, endpoint.source, err)
	}
	return resp.RequestID, nil
}

func componentRequestForIndices(groupBytesHex []string, originalCount int, indices []int, kind signerapi.ComponentTargetKind, key string, appCallInfo []*signerapi.AppCallInfo) signerapi.ComponentRequest {
	targetSet := make(map[int]bool, len(indices))
	request := signerapi.ComponentRequest{GroupBytesHex: groupBytesHex}
	for _, index := range indices {
		targetSet[index] = true
		target := signerapi.ComponentTarget{TargetIndex: index, Kind: kind, ComponentKey: key}
		if index < len(appCallInfo) {
			target.AppCallInfo = appCallInfo[index]
		}
		request.Targets = append(request.Targets, target)
	}
	for index := 0; index < originalCount; index++ {
		if !targetSet[index] {
			position := signerapi.ComponentContextPosition{TargetIndex: index}
			if index < len(appCallInfo) {
				position.AppCallInfo = appCallInfo[index]
			}
			request.ContextualPositions = append(request.ContextualPositions, position)
		}
	}
	for index := originalCount; index < len(groupBytesHex); index++ {
		request.DummyPositions = append(request.DummyPositions, signerapi.ComponentDummyPosition{TargetIndex: index})
	}
	return request
}

func collectComponentSignatures(resp *signerapi.ComponentResponse, expected []int, expectedScheme string, dst map[int]string) error {
	if resp == nil {
		return fmt.Errorf("empty component sign response")
	}
	expectedSet := make(map[int]bool, len(expected))
	for _, index := range expected {
		expectedSet[index] = true
	}
	seen := make(map[int]bool, len(resp.Components))
	for _, component := range resp.Components {
		if !expectedSet[component.TargetIndex] {
			return fmt.Errorf("unexpected signature for target index %d", component.TargetIndex)
		}
		if seen[component.TargetIndex] {
			return fmt.Errorf("duplicate signature for target index %d", component.TargetIndex)
		}
		if expectedScheme != "" && component.SignatureScheme != expectedScheme {
			return fmt.Errorf("signature for target index %d used scheme %s, want %s", component.TargetIndex, component.SignatureScheme, expectedScheme)
		}
		seen[component.TargetIndex] = true
		dst[component.TargetIndex] = component.Signature
	}
	for _, index := range expected {
		if !seen[index] {
			return fmt.Errorf("missing signature for target index %d", index)
		}
	}
	return nil
}

func decodeCosignedSignedGroup(signedHex []string) ([][]byte, []types.SignedTxn, []types.Transaction, error) {
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

func writeCosignedSubmittedTransactions(writer func(types.Transaction, string), txns []types.Transaction, txIDs []string, originalCount int) {
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
