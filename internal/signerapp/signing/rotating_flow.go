// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"runtime"
	"time"

	"github.com/aplane-algo/aplane/internal/cosigner/canonical"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/stagetable"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/pkg/signerapi"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// The rotating signing rules, in the numbering of the design:
//
//  1. Stage proven: the authorizer is A_n, read fresh under the account lock
//     immediately before signing, and the program signed with derives to it.
//  2. Target is the next stage: RekeyTo = A_{n+1}; the group's RekeyTo is
//     what fixes n, so nothing is carried across approval.
//  3. Timing: FirstValid <= round + rotatingkey.RotatingMaxLead, LastValid
//     >= round + rotatingkey.RotatingMinRemaining, window <= the template's
//     maximum.
//  4. Target can sign later: the open test on stage n + 1.
//  5. Group exact: rebuilding the group from the presented spend reproduces
//     the presented bytes (dummies, fees, group ID), and the spend's sender,
//     network and close-out are as required.
//
// There is deliberately no limit on releases per stage.
const (
	// DefaultDiscoveryTimeout bounds how long prepare scans for an unknown
	// live stage before refusing with rotating_stage_unproven. HTTP request
	// contexts carry no deadline of their own, and the scan uses every
	// core; progress stays in the table for the retry and the background
	// worker.
	DefaultDiscoveryTimeout = 30 * time.Second
)

// rotatingPlanItem describes a rotating spend for policy and approval.
type rotatingPlanItem struct {
	Stage         uint64
	Target        uint64
	TargetAddress types.Address
}

func (r *rotatingPlanItem) describe() string {
	return fmt.Sprintf("\n  Rotation: stage %d signs and hands the account to stage %d (%s), held by this signer", r.Stage, r.Target, r.TargetAddress)
}

// groupKnownAddresses is the address set approval warnings treat as the
// signer's own. A rotating plan names its rotation target in its own set;
// every other plan keeps the runtime's key-file addresses.
func (s *ApprovalService) groupKnownAddresses(plan *PlanResult) map[string]bool {
	if plan != nil && plan.Rotating != nil && plan.KnownAddresses != nil {
		return plan.KnownAddresses
	}
	if s.KnownAddresses == nil {
		return nil
	}
	return s.KnownAddresses()
}

func rotatingStageUnproven(scanned uint64) *ServiceError {
	return &ServiceError{
		Kind:    ErrorRotatingStageUnproven,
		Message: fmt.Sprintf("the account's live stage has not been found yet (%d stages scanned); the signer is still extending its stage table, retry shortly", scanned),
	}
}

func rotatingStageChanged(authorizer types.Address) *ServiceError {
	return &ServiceError{
		Kind:    ErrorRotatingStageChanged,
		Message: fmt.Sprintf("the account's authorizer changed to %s before signing; nothing was signed, rebuild the transaction and prepare again", authorizer),
	}
}

// validateRotatingSpend applies the sender, shape and window rules that do
// not depend on the chain.
func validateRotatingSpend(txn types.Transaction, account types.Address, genesis []byte) *ServiceError {
	switch {
	case txn.Sender != account:
		return badRequest("transaction sender must be the rotating account")
	case !bytes.Equal(txn.GenesisHash[:], genesis):
		return badRequest("transaction genesis hash is not the rotating account's network")
	case !txn.CloseRemainderTo.IsZero():
		return badRequest("rotating accounts cannot close out")
	case txn.LastValid < txn.FirstValid || txn.LastValid-txn.FirstValid > rotatingkey.RotatingMaxValidityWindow:
		return badRequest(fmt.Sprintf("validity window must be at most %d rounds", rotatingkey.RotatingMaxValidityWindow))
	}
	return nil
}

// buildRotatingGroup adds the resource dummies, sets fees and computes the
// group ID for one rotating spend, reusing the ordinary planner's solver and
// fee rules. It is deterministic in the spend: running it again on a spend
// it already adjusted reproduces the same group, which is what lets sign
// check a presented group by rebuilding it.
func buildRotatingGroup(console Console, txn types.Transaction, profile *lsigresource.Profile) (*PlanResult, *ServiceError) {
	txn.Group = types.Digest{}
	consensus, err := lsigresource.CurrentConsensus()
	if err != nil {
		return nil, internal(err.Error())
	}
	usage, err := profile.UsageForPath(lsigresource.PathDefault)
	if err != nil {
		return nil, internal(err.Error())
	}
	resourcePlan, err := lsigresource.Solve(consensus, lsigresource.PlanInput{
		TransactionCount: 1,
		LogicSigs:        []lsigresource.Usage{usage},
		Dummy:            lsigresource.Usage{ProgramBytes: uint64(len(coresigning.EmbeddedDummyTealTok)), MaxOpcodeCost: 1},
	})
	if err != nil {
		return nil, badRequest(fmt.Sprintf("rotating spend does not fit the consensus resource limits: %v", err))
	}
	dummies := int(resourcePlan.DummyCount)
	allTxns, dummyTxns, _, _, buildErr := buildFinalGroupWithoutFees(console, []types.Transaction{txn}, dummies, false)
	if buildErr != nil {
		return nil, buildErr
	}
	lsigIndices := []int{0}
	feeInfo, feeErr := applyGroupFees(allTxns, []authorizationBudget{{mutable: true}}, resourcePlan, dummies, lsigIndices, false)
	if feeErr != nil {
		return nil, feeErr
	}
	if len(allTxns) > 1 {
		for i := range allTxns {
			allTxns[i].Group = types.Digest{}
		}
		gid, gidErr := algocrypto.ComputeGroupID(allTxns)
		if gidErr != nil {
			return nil, internal(fmt.Sprintf("failed to compute group ID: %v", gidErr))
		}
		for i := range allTxns {
			allTxns[i].Group = gid
		}
	}
	return &PlanResult{
		AllTxns:              allTxns,
		DummyTxns:            dummyTxns,
		PassthroughIndices:   map[int]bool{},
		ForeignIndices:       map[int]bool{},
		LsigIndices:          lsigIndices,
		DummiesNeeded:        dummies,
		LogicSigResourcePlan: resourcePlan,
		FeeInfo:              feeInfo,
		NeedsRegroup:         len(allTxns) > 1,
	}, nil
}

// requestDeriver derives stages for a request path: every core, no pacing,
// bounded only by the request's context.
func (s *Service) requestDeriver(account string, session *keystore.KeySession) stageDeriver {
	return s.stageDeriver(account, session, StageFillOptions{Parallel: runtime.GOMAXPROCS(0)})
}

// liveStage finds the account's live stage from its authorizer: the account
// itself is stage 0, otherwise the table answers, otherwise the table is
// extended, under the request's context and the discovery timeout, until
// the authorizer appears. A deadline that passes first refuses with
// rotating_stage_unproven and the progress stays in the table for the next
// attempt or the background worker.
func (s *Service) liveStage(ctx context.Context, deps *RotatingDeps, table *stagetable.Table, derive stageDeriver, account, authorizer types.Address) (uint64, *ServiceError) {
	if stage, ok := resolveStage(table, account, authorizer); ok {
		return stage, nil
	}
	timeout := deps.DiscoveryTimeout
	if timeout <= 0 {
		timeout = DefaultDiscoveryTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	opts := StageFillOptions{Parallel: runtime.GOMAXPROCS(0)}
	for ctx.Err() == nil {
		found, err := extendUntil(ctx, table, derive, authorizer, opts.batch(), opts)
		if err != nil {
			return 0, internal(fmt.Sprintf("extend stage table: %v", err))
		}
		if found {
			break
		}
	}
	stage, ok := table.Lookup(authorizer)
	if !ok {
		return 0, rotatingStageUnproven(table.Len())
	}
	return stage, nil
}

// derivedStageAddress derives A_stage from the seed, never from the table,
// and reconciles the table with the result: a missing prefix is filled, a
// missing entry is appended, and an entry that disagrees with the derivation
// means the table has been altered, so it is refused and will be discarded
// and rebuilt. The target of a rotation always comes from here, because the
// table is a hint and a rekey target decides who controls the account.
func derivedStageAddress(ctx context.Context, deps *RotatingDeps, table *stagetable.Table, derive stageDeriver, stage uint64) (types.Address, *ServiceError) {
	// Fill any gap below stage first, from a length captured once so a
	// concurrent fill cannot shift the starting index under us.
	if from := table.Len(); from < stage {
		addrs, err := derive(ctx, from, stage)
		if err != nil {
			return types.Address{}, internal(fmt.Sprintf("derive stages: %v", err))
		}
		if uint64(len(addrs)) != stage-from {
			return types.Address{}, unavailable("derivation interrupted")
		}
		if err := table.AppendFrom(from, addrs); err != nil {
			return types.Address{}, internal(fmt.Sprintf("extend stage table: %v", err))
		}
	}
	addrs, err := derive(ctx, stage, stage+1)
	if err != nil {
		return types.Address{}, internal(fmt.Sprintf("derive stage %d: %v", stage, err))
	}
	if len(addrs) != 1 {
		return types.Address{}, unavailable("derivation interrupted")
	}
	derived := addrs[0]
	if cached, ok := table.Address(stage); ok {
		if cached != derived {
			deps.discardTable(table)
			return types.Address{}, internal(fmt.Sprintf("stage table entry %d does not match the seed; the table has been discarded and will be rebuilt", stage))
		}
		return derived, nil
	}
	if err := table.AppendFrom(stage, addrs); err != nil {
		return types.Address{}, internal(fmt.Sprintf("extend stage table: %v", err))
	}
	return derived, nil
}

// PrepareRotatingWithContext prepares one spend from a rotating account: it
// finds the live stage n on chain, sets RekeyTo to A_{n+1}, adds the resource
// dummies, sets fees and the group ID, and returns the exact unsigned group.
// It stores nothing and takes no account lock.
func (s *Service) PrepareRotatingWithContext(ctx context.Context, req signerapi.RotatingPrepareRequest, session *keystore.KeySession) (*signerapi.RotatingPrepareResponse, *ServiceError) {
	if err := req.Validate(); err != nil {
		return nil, badRequest(err.Error())
	}
	deps, depErr := s.rotatingDeps()
	if depErr != nil {
		return nil, depErr
	}
	txn, decodeErr := txnutil.DecodePrefixedHex(req.TxnBytesHex)
	if decodeErr != nil {
		return nil, badRequest(decodeErr.Error())
	}
	if txn.Group != (types.Digest{}) {
		return nil, badRequest("transaction must be ungrouped; the signer forms the group")
	}
	if !txn.RekeyTo.IsZero() {
		return nil, badRequest("transaction must not set rekey_to; the signer sets it")
	}

	account, genesis, profile, svcErr := s.rotatingAccount(ctx, req.Account, session)
	if svcErr != nil {
		return nil, svcErr
	}
	if err := validateRotatingSpend(txn, account, genesis); err != nil {
		return nil, err
	}
	table, tableErr := deps.Tables.Table(account, genesis, s.keyPresent(req.Account))
	if table == nil {
		return nil, internal(fmt.Sprintf("stage table: %v", tableErr))
	}
	derive := s.requestDeriver(req.Account, session)

	readCtx, cancelRead := context.WithTimeout(ctx, DefaultChainReadTimeout)
	view, readErr := deps.Chain.ReadAccount(readCtx, genesis, account)
	cancelRead()
	if readErr != nil {
		return nil, unavailable(readErr.Error())
	}
	stage, err := s.liveStage(ctx, deps, table, derive, account, view.Authorizer)
	if err != nil {
		return nil, err
	}
	target := stage + 1
	targetAddr, err := derivedStageAddress(ctx, deps, table, derive, target)
	if err != nil {
		return nil, err
	}
	txn.RekeyTo = targetAddr

	plan, err := buildRotatingGroup(s.Console, txn, profile)
	if err != nil {
		return nil, err
	}
	encoded := make([]string, len(plan.AllTxns))
	for i, t := range plan.AllTxns {
		encoded[i] = hex.EncodeToString(txnutil.EncodeWithPrefix(t))
	}
	consoleOf(s.Console).Printf("[ROTATING] Prepared spend for %s: stage %d rotates to %d\n", req.Account, stage, target)
	return &signerapi.RotatingPrepareResponse{
		Account:      req.Account,
		Stage:        stage,
		Target:       target,
		RekeyTo:      targetAddr.String(),
		Transactions: encoded,
		Mutations:    BuildMutationReport(plan, 1),
	}, nil
}

// SignRotatingWithContext signs a prepared rotating group. It is the
// complete validation boundary: everything is re-established from the
// presented bytes and a fresh chain read; nothing from prepare is remembered.
func (s *Service) SignRotatingWithContext(ctx context.Context, req signerapi.RotatingSignRequest, session *keystore.KeySession) (*signerapi.RotatingSignResponse, *ServiceError) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := req.Validate(); err != nil {
		return nil, badRequest(err.Error())
	}
	deps, depErr := s.rotatingDeps()
	if depErr != nil {
		return nil, depErr
	}
	if s.Approval == nil {
		return nil, internal("signing service not fully configured")
	}
	group, decodeErr := canonical.DecodeGroupHex(req.Transactions)
	if decodeErr != nil {
		return nil, badRequest(decodeErr.Error())
	}
	raws := make([][]byte, len(group.Entries))
	allTxns := make([]types.Transaction, len(group.Entries))
	for i, e := range group.Entries {
		raws[i] = e.Raw
		allTxns[i] = e.Txn
	}
	spend := allTxns[0]

	account, genesis, profile, svcErr := s.rotatingAccount(ctx, req.Account, session)
	if svcErr != nil {
		return nil, svcErr
	}
	if err := validateRotatingSpend(spend, account, genesis); err != nil {
		return nil, err
	}
	table, tableErr := deps.Tables.Table(account, genesis, s.keyPresent(req.Account))
	if table == nil {
		return nil, internal(fmt.Sprintf("stage table: %v", tableErr))
	}

	// Rule 2: the group's RekeyTo is A_{n+1} for some n, which fixes the
	// signing stage from the bytes alone. The table only proposes the
	// number; the derivation that follows is what proves the address,
	// because a rekey target decides who controls the account and the table
	// is a plaintext cache.
	targetStage, ok := table.Lookup(spend.RekeyTo)
	if !ok || targetStage == 0 {
		return nil, badRequest("rekey target is not a stage of this account; prepare the spend again")
	}
	stage := targetStage - 1
	derive := s.requestDeriver(req.Account, session)
	derivedTarget, err := derivedStageAddress(ctx, deps, table, derive, targetStage)
	if err != nil {
		return nil, err
	}
	if derivedTarget != spend.RekeyTo {
		deps.discardTable(table)
		return nil, badRequest("rekey target does not derive from this account's seed; the stage table has been discarded, prepare the spend again")
	}

	// Rule 5: rebuilding the group from the presented spend must reproduce
	// the presented bytes exactly.
	rebuilt, groupErr := buildRotatingGroup(s.Console, spend, profile)
	if groupErr != nil {
		return nil, groupErr
	}
	if len(rebuilt.AllTxns) != len(allTxns) {
		return nil, badRequest(fmt.Sprintf("group has %d transactions; the spend needs %d", len(allTxns), len(rebuilt.AllTxns)))
	}
	for i := range allTxns {
		if !bytes.Equal(txnutil.EncodeWithPrefix(rebuilt.AllTxns[i]), raws[i]) {
			return nil, badRequest(fmt.Sprintf("transaction %d differs from the group the signer would build (dummies, fees and group ID must be exactly the prepared ones)", i+1))
		}
	}
	item := &rotatingPlanItem{Stage: stage, Target: targetStage, TargetAddress: spend.RekeyTo}
	known := make(map[string]bool, len(s.Planner.Snapshot().KeyFiles)+1)
	for addr := range knownAddressesFromSnapshot(s.Planner.Snapshot()) {
		known[addr] = true
	}
	// The rotation target is this signer's own next stage, never a foreign
	// authority: approval warnings and reject_foreign_rekey see it as held.
	known[spend.RekeyTo.String()] = true
	plan := &PlanResult{
		AllTxns:            allTxns,
		DummyTxns:          allTxns[1:],
		PassthroughIndices: map[int]bool{},
		ForeignIndices:     map[int]bool{},
		LsigIndices:        []int{0},
		DummiesNeeded:      len(allTxns) - 1,
		NeedsRegroup:       len(allTxns) > 1,
		AuthKeyTypes:       []string{s.Planner.Snapshot().KeyTypes[req.Account]},
		KnownAddresses:     known,
		Rotating:           item,
	}
	signReq := signerapi.GroupSignRequest{
		RequestID: req.RequestID,
		Requests:  []signerapi.SignRequest{{AuthAddress: req.Account, TxnBytesHex: hex.EncodeToString(raws[0])}},
	}
	policyRuleID, release, gateErr := s.approveGroupWithPlanContext(ctx, signReq, plan)
	if gateErr != nil {
		return nil, gateErr
	}
	defer release()

	// Under the account lock: a fresh read, rule 1, rule 3, then the seed is
	// opened only to run the open test and sign.
	unlock := deps.Locks.Lock(req.Account)
	defer unlock()
	readCtx, cancelRead := context.WithTimeout(ctx, DefaultChainReadTimeout)
	view, readErr := deps.Chain.ReadAccount(readCtx, genesis, account)
	cancelRead()
	if readErr != nil {
		return nil, unavailable(readErr.Error())
	}
	liveStage, resolved := resolveStage(table, account, view.Authorizer)
	if !resolved || liveStage != stage {
		return nil, rotatingStageChanged(view.Authorizer)
	}
	if uint64(spend.FirstValid) > view.Round+rotatingkey.RotatingMaxLead {
		return nil, badRequest(fmt.Sprintf("first valid round %d is more than %d rounds ahead of the current round %d", spend.FirstValid, rotatingkey.RotatingMaxLead, view.Round))
	}
	if uint64(spend.LastValid) < view.Round+rotatingkey.RotatingMinRemaining {
		return nil, badRequest(fmt.Sprintf("fewer than %d rounds remain before last valid round %d (current round %d); prepare the spend again", rotatingkey.RotatingMinRemaining, spend.LastValid, view.Round))
	}

	rs, svcErr := s.openRotatingSession(ctx, req.Account, session)
	if svcErr != nil {
		return nil, svcErr
	}
	defer rs.close()
	// Rule 4, and rule 2 once more from the seed held under the lock: the
	// target program must open and must be the address the spend hands the
	// account to.
	if err := rs.ops.CheckStageOpens(rs.secret, targetStage); err != nil {
		return nil, internal(fmt.Sprintf("rotation target stage %d failed its open check: %v", targetStage, err))
	}
	if addr, err := rs.stageAddress(targetStage); err != nil || addr != spend.RekeyTo {
		return nil, internal("rotation target does not derive from the seed")
	}
	// The spend and the transaction ID about to be signed must be exactly
	// the group the approval covered.
	if bindErr := checkApprovalBinding(signReq, plan); bindErr != nil {
		return nil, bindErr
	}
	txID := group.Entries[0].TxID
	if !bytes.Equal(txnutil.EncodeWithPrefix(spend), txnutil.EncodeWithPrefix(plan.AllTxns[0])) || !bytes.Equal(txID[:], algocrypto.TransactionID(plan.AllTxns[0])) {
		return nil, internal("refusing to sign: the rotating spend differs from the approved group")
	}
	stageSig, signErr := rs.ops.SignStage(rs.secret, stage, txID[:])
	if signErr != nil {
		return nil, internal(fmt.Sprintf("sign with stage %d: %v", stage, signErr))
	}
	defer zeroGeneratedArgs(stageSig.Args)
	stxn := types.SignedTxn{
		Txn:  spend,
		Lsig: types.LogicSig{Logic: stageSig.Program, Args: stageSig.Args},
	}
	stageAddr := algocrypto.LogicSigAddress(stxn.Lsig)
	if stageAddr != account {
		stxn.AuthAddr = stageAddr
	}
	// Rule 1, second half: the program signed with derives to the authorizer.
	// This is also what proves the table's hint for stage n was right.
	if stageAddr != view.Authorizer {
		return nil, internal("signing stage does not match the live authorizer")
	}
	if cached, ok := table.Address(stage); ok && cached != stageAddr {
		return nil, internal("stage table disagrees with the signing derivation; it will be rebuilt")
	}
	signed := make([]string, 0, len(allTxns))
	signed = append(signed, hex.EncodeToString(msgpack.Encode(stxn)))
	dummies, dummyErr := coresigning.SignDummyTransactions(allTxns[1:])
	if dummyErr != nil {
		return nil, internal(fmt.Sprintf("sign dummy transactions: %v", dummyErr))
	}
	for _, d := range dummies {
		signed = append(signed, hex.EncodeToString(d))
	}

	txIDText := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(txID[:])
	groupIDText := base64.StdEncoding.EncodeToString(group.GroupID[:])

	// The release is audited durably and remembered before the signature
	// leaves. Both are observational: a failure is reported, not fatal.
	if logger, ok := s.AuditLog.(AuditRotatingReleaseLogger); ok && logger != nil {
		if err := logger.LogRotatingRelease(req.Account, txIDText, stage, uint64(spend.LastValid)); err != nil {
			consoleOf(s.Console).Printf("[ROTATING] WARNING: release of stage %d for %s was not recorded in the audit log: %v\n", stage, req.Account, err)
		}
	}
	deps.Releases.Record(ReleaseRecord{
		Account: req.Account, Stage: stage, StageAddr: stageAddr, NextAddr: spend.RekeyTo,
		TxID: txIDText, LastValid: uint64(spend.LastValid),
	})
	consoleOf(s.Console).Printf("[ROTATING] Released stage %d for %s (%s); the account moves to stage %d when it lands\n", stage, req.Account, txIDText, targetStage)
	s.logSuccessfulSignatures(signReq, plan, allTxns, policyRuleID)
	return &signerapi.RotatingSignResponse{
		Signed:  signed,
		Stage:   stage,
		Target:  targetStage,
		TxID:    txIDText,
		GroupID: groupIDText,
	}, nil
}

// rotatingAccount returns the account address, genesis hash and resource
// profile of a rotating key. The seed is opened only long enough to copy the
// genesis hash out.
func (s *Service) rotatingAccount(ctx context.Context, account string, session *keystore.KeySession) (types.Address, []byte, *lsigresource.Profile, *ServiceError) {
	rs, svcErr := s.openRotatingSession(ctx, account, session)
	if svcErr != nil {
		return types.Address{}, nil, nil, svcErr
	}
	defer rs.close()
	return rs.account, bytes.Clone(rs.secret.GenesisHash), rs.profile, nil
}

// keyPresent reports whether the account's key is still in the inventory.
func (s *Service) keyPresent(account string) func() bool {
	return func() bool {
		_, ok := s.Planner.Snapshot().KeyFiles[account]
		return ok
	}
}
