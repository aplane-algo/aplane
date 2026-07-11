// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"fmt"

	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/sentry/canonical"
	"github.com/aplane-algo/aplane/internal/signerapi"
)

// GuardedSimulateAssembly is the signer-internal result of guarded simulation
// assembly. SignedGroup is consumed by the REST simulation handler and is
// never serialized back to the client.
type GuardedSimulateAssembly struct {
	RequestID   string
	SignedGroup []string
}

// AssembleGuardedForSimulationWithContext runs the contained guarded
// simulation flow: it gates and produces the user component signatures
// in-process, signs local non-guarded legs through the ordinary simulation
// path (no operator prompts), and assembles the full group with the standard
// assembly invariants. The caller must simulate the result internally and
// discard the signed bytes.
func (s *Service) AssembleGuardedForSimulationWithContext(ctx context.Context, identityID string, req signerapi.GuardedSimulateRequest, session *keystore.KeySession) (*GuardedSimulateAssembly, *ServiceError) {
	var getter componentKeyGetter
	if session != nil {
		getter = session
	}
	signLocalLegs := func(ctx context.Context, groupReq signerapi.GroupSignRequest) (*SignGroupResult, *ServiceError) {
		return s.SignGroupForSimulationWithContext(ctx, identityID, groupReq, session)
	}
	return s.assembleGuardedForSimulation(ctx, identityID, req, getter, signLocalLegs)
}

func (s *Service) assembleGuardedForSimulation(ctx context.Context, identityID string, req signerapi.GuardedSimulateRequest, session componentKeyGetter, signLocalLegs func(context.Context, signerapi.GroupSignRequest) (*SignGroupResult, *ServiceError)) (*GuardedSimulateAssembly, *ServiceError) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, canceledSignRequest(err)
	}
	if err := req.Validate(); err != nil {
		return nil, badRequest(err.Error())
	}
	if s.IsUnlocked != nil && !s.IsUnlocked() {
		return nil, lockedError()
	}
	if session == nil {
		return nil, internal("key session is nil")
	}
	requestID := guardedRequestID("gsim", req.RequestID)

	groupBytesHex := make([]string, len(req.Requests))
	for i, request := range req.Requests {
		groupBytesHex[i] = request.TxnBytesHex
	}
	group, decodeErr := canonical.DecodeGroupHex(groupBytesHex)
	if decodeErr != nil {
		return nil, badRequest(decodeErr.Error())
	}

	// Group guarded targets by account: each guarded account is gated and
	// signed with its own component plan, matching per-account /sign/component.
	accountOrder := make([]string, 0, len(req.Targets))
	indicesByAccount := make(map[string][]int, len(req.Targets))
	for _, target := range req.Targets {
		if _, ok := indicesByAccount[target.GuardedAccount]; !ok {
			accountOrder = append(accountOrder, target.GuardedAccount)
		}
		indicesByAccount[target.GuardedAccount] = append(indicesByAccount[target.GuardedAccount], target.TargetIndex)
	}

	// Gate every guarded account before any private-key access. The preflight
	// reads inventory metadata only, so rejected simulations never decrypt key
	// material. Simulation skips review and operator approval; hard policy
	// rejection still applies.
	plansByAccount := make(map[string]*ComponentSignPlan, len(accountOrder))
	for _, account := range accountOrder {
		if err := s.preflightGuardedAccountKeyMetadata(identityID, account); err != nil {
			return nil, err
		}
		plan, err := PrepareComponentSigning(signerapi.ComponentSignRequest{
			RequestID:     requestID,
			Role:          signerapi.ComponentSignRoleUser,
			ComponentKey:  account,
			GroupBytesHex: groupBytesHex,
			TargetIndices: indicesByAccount[account],
		})
		if err != nil {
			return nil, err
		}
		if _, gateErr := s.gateUserComponentSigning(ctx, identityID, plan, true); gateErr != nil {
			return nil, gateErr
		}
		plansByAccount[account] = plan
	}

	// Sign local non-guarded legs through the ordinary simulation path: same
	// planner, policy, and budget backstop as /simulate, no operator prompts.
	// This runs before the component lease because the group signing path
	// acquires its own operation lease; nesting the shared lifecycle read lock
	// could deadlock behind a queued decommission writer.
	localIndices := make([]int, 0, len(req.Requests))
	for i, request := range req.Requests {
		if request.AuthAddress != "" {
			localIndices = append(localIndices, i)
		}
	}
	localSigned := make(map[int]string, len(localIndices))
	if len(localIndices) > 0 {
		if signLocalLegs == nil {
			return nil, internal("local leg signing is not configured")
		}
		result, err := signLocalLegs(ctx, signerapi.GroupSignRequest{
			RequestID: requestID,
			Requests:  req.Requests,
		})
		if err != nil {
			return nil, err
		}
		if len(result.Signed) != len(req.Requests) {
			return nil, internal(fmt.Sprintf("local simulation signing returned %d position(s), want %d", len(result.Signed), len(req.Requests)))
		}
		for _, i := range localIndices {
			if result.Signed[i] == "" {
				return nil, internal(fmt.Sprintf("local simulation signing returned no signature for position %d", i))
			}
			localSigned[i] = result.Signed[i]
		}
	}

	// Hold one operation lease across component signing and assembly so
	// decommission cannot complete while decrypted component material is in
	// use (the BeginOperation/Decommission contract).
	release, leaseErr := s.beforeExecute()
	if leaseErr != nil {
		return nil, leaseErr
	}
	defer release()

	// Produce user component signatures in-process. They are packed into the
	// assembled LogicSig below and never returned to the client.
	userSignatures := make(map[int]string, len(req.Targets))
	for _, account := range accountOrder {
		result, signErr := signPreparedUserComponents(ctx, plansByAccount[account], session)
		if signErr != nil {
			return nil, signErr
		}
		for _, signature := range result.Signatures {
			userSignatures[signature.TargetIndex] = signature.Signature
		}
	}

	// Assemble through the standard guarded assembly path so every invariant
	// (component verification, canonical passthrough, LogicSig address, and
	// AuthAddr checks) applies identically to simulation.
	assemblyReq := signerapi.GuardedAssemblyRequest{
		RequestID:     requestID,
		GroupBytesHex: groupBytesHex,
		Targets:       make([]signerapi.GuardedAssemblyTarget, 0, len(req.Targets)),
		Passthrough:   make([]signerapi.GuardedPassthroughItem, 0, len(req.Passthrough)+len(localIndices)),
	}
	for _, target := range req.Targets {
		userSignature, ok := userSignatures[target.TargetIndex]
		if !ok || userSignature == "" {
			return nil, internal(fmt.Sprintf("no user component signature produced for target index %d", target.TargetIndex))
		}
		assemblyReq.Targets = append(assemblyReq.Targets, signerapi.GuardedAssemblyTarget{
			TargetIndex:           target.TargetIndex,
			GuardedAccount:        target.GuardedAccount,
			UserSignature:         userSignature,
			UserSourceRequestID:   requestID,
			SentrySignature:       target.SentrySignature,
			SentrySourceRequestID: target.SentrySourceRequestID,
			RuntimeArgs:           target.RuntimeArgs,
		})
	}
	assemblyReq.Passthrough = append(assemblyReq.Passthrough, req.Passthrough...)
	for _, i := range localIndices {
		assemblyReq.Passthrough = append(assemblyReq.Passthrough, signerapi.GuardedPassthroughItem{
			TargetIndex:  i,
			SignedTxnHex: localSigned[i],
		})
	}

	assembled, assembleErr := assembleDecodedGuarded(ctx, assemblyReq, group, session)
	if assembleErr != nil {
		return nil, assembleErr
	}

	return &GuardedSimulateAssembly{
		RequestID:   requestID,
		SignedGroup: assembled.SignedGroup,
	}, nil
}
