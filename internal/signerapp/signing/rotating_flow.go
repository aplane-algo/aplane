// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"runtime"
	"time"

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
//  5. Group exact: rebuilding the complete group from the presented user
//     slots, with the shared planner's dummies, fees and group ID,
//     reproduces their bytes and their group ID; the single-transaction
//     form's complete presented group is compared in full. The spend's
//     sender, network and close-out are as required, and every other slot
//     is a transaction this signer signs with an ordinary key
//     (normalizeRotatingSlots). The rebuild proves the group is one the
//     signer would build from these slots, not that the slots are the ones
//     prepare saw: policy and approval judge what is presented.
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
	// Index is the rotating slot's position in the group.
	Index         int
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
		Message: fmt.Sprintf("the account's authorizer changed to %s before the rotating signature; no signature was released, rebuild the transaction and prepare again", authorizer),
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

// requestDeriver derives stages without background pacing, honoring the
// family's parallelism cap and the request's context.
func (s *Service) requestDeriver(account string, session *keystore.KeySession) stageDeriver {
	opts := s.stageFillOptions(account, StageFillOptions{Parallel: runtime.GOMAXPROCS(0)})
	return s.stageDeriver(account, session, opts)
}

// liveStage finds the account's live stage from its authorizer: the account
// itself is stage 0, otherwise the table answers, otherwise the table is
// extended, under the request's context, discovery timeout and any family
// derivation ceiling, until the authorizer appears. Exhausting either bound refuses with
// rotating_stage_unproven and the progress stays in the table for the next
// attempt or the background worker.
func (s *Service) liveStage(ctx context.Context, deps *RotatingDeps, table *stagetable.Table, derive stageDeriver, account, authorizer types.Address) (uint64, *ServiceError) {
	stage, class := classifyAuthorizer(table, account, authorizer, knownAddressesFromSnapshot(s.Planner.Snapshot()))
	switch class {
	case ClassStage:
		return stage, nil
	case ClassHeldKey:
		return 0, badRequest(fmt.Sprintf("the account is rekeyed to %s, a key this signer holds; its rotating stages no longer control it, sign through that key instead", authorizer))
	}
	timeout := deps.DiscoveryTimeout
	if timeout <= 0 {
		timeout = DefaultDiscoveryTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	opts := s.stageFillOptions(account.String(), StageFillOptions{Parallel: runtime.GOMAXPROCS(0)})
	profile, _ := rotatingkey.Lookup(s.Planner.Snapshot().KeyTypes[account.String()])
	for ctx.Err() == nil {
		found, err := extendUntil(ctx, table, derive, authorizer, opts.batch(), opts)
		if err != nil {
			return 0, internal(fmt.Sprintf("extend stage table: %v", err))
		}
		if found || profile.Preparation.MaxDerivations > 0 {
			// Expensive families search one bounded batch per request. Progress
			// remains in the table; background/operator recovery can continue.
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

// PrepareRotatingWithContext prepares a spend from a rotating account, alone
// or grouped with transactions this signer signs with ordinary keys: it
// finds the live stage n on chain, sets the rotating slot's RekeyTo to
// A_{n+1}, and builds the canonical group with the ordinary planner's rules,
// resource dummies, fee allocation and group ID, returning the exact
// unsigned group. It stores nothing and takes no account lock.
func (s *Service) PrepareRotatingWithContext(ctx context.Context, req signerapi.RotatingPrepareRequest, session *keystore.KeySession) (*signerapi.RotatingPrepareResponse, *ServiceError) {
	if err := req.Validate(); err != nil {
		return nil, badRequest(err.Error())
	}
	deps, depErr := s.rotatingDeps()
	if depErr != nil {
		return nil, depErr
	}
	account, genesis, _, svcErr := s.rotatingAccount(ctx, req.Account, session)
	if svcErr != nil {
		return nil, svcErr
	}
	snapshot := s.Planner.Snapshot()
	slots, err := normalizeRotatingSlots(snapshot, account, genesis, rotatingPrepareRequests(req), rotatingPrepare)
	if err != nil {
		return nil, err
	}
	// The key's bound genesis is not enough: the network must also be one
	// this node is configured for, checked before any gate runs.
	if err := validateKnownNetwork(slots.Txns, s.genesisHashResolver()); err != nil {
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
	slots.Txns[slots.Rotating].RekeyTo = targetAddr

	plan, err := s.buildRotatingPlan(snapshot, slots)
	if err != nil {
		return nil, err
	}
	encoded := make([]string, len(plan.AllTxns))
	for i, t := range plan.AllTxns {
		encoded[i] = hex.EncodeToString(txnutil.EncodeWithPrefix(t))
	}
	if len(slots.Owned) > 0 {
		consoleOf(s.Console).Printf("[ROTATING] Prepared spend for %s with %d other transaction(s): stage %d rotates to %d\n", req.Account, len(slots.Owned), stage, target)
	} else {
		consoleOf(s.Console).Printf("[ROTATING] Prepared spend for %s: stage %d rotates to %d\n", req.Account, stage, target)
	}
	rotation := rotationSlot(slots.Rotating, stage, targetAddr)
	return &signerapi.RotatingPrepareResponse{
		Account:      req.Account,
		Stage:        rotation.Stage,
		Target:       rotation.Target,
		RekeyTo:      rotation.RekeyTo,
		Transactions: encoded,
		Mutations:    BuildMutationReport(plan, len(slots.Txns)),
		Rotations:    []signerapi.RotationSlot{rotation},
		OwnedIndexes: slots.Owned,
	}, nil
}

// SignRotatingWithContext signs a prepared rotating group. It is the
// complete validation boundary: everything is re-established from the
// presented bytes and a fresh chain read; nothing from prepare is remembered.
//
// The order is what keeps a failure from recording a release that never
// left: approval once for the whole group; the approval binding, checked
// before any key is used; the owned slots' signatures, made in memory
// through the ordinary per-slot path; then the rotating path under the
// account lock, unchanged; and only then release accounting and the
// response. A failure before the rotating signature leaves no rotating
// signature and no release record. A failure after it, at the post-sign
// recheck, wipes the signature and records nothing. One execution lease,
// taken by the approval gate, spans both signing phases.
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
	presented, full, formErr := rotatingSignRequests(req)
	if formErr != nil {
		return nil, formErr
	}

	account, genesis, _, svcErr := s.rotatingAccount(ctx, req.Account, session)
	if svcErr != nil {
		return nil, svcErr
	}
	snapshot := s.Planner.Snapshot()
	slots, err := normalizeRotatingSlots(snapshot, account, genesis, presented, rotatingSign)
	if err != nil {
		return nil, err
	}
	rot := slots.Rotating
	spend := slots.Txns[rot]
	// The key's bound genesis is not enough: the network must also be one
	// this node is configured for, checked before any gate runs.
	if err := validateKnownNetwork(slots.Txns, s.genesisHashResolver()); err != nil {
		return nil, err
	}
	if len(slots.Owned) > 0 && s.Executor == nil {
		return nil, internal("signing service not fully configured")
	}
	table, tableErr := deps.Tables.Table(account, genesis, s.keyPresent(req.Account))
	if table == nil {
		return nil, internal(fmt.Sprintf("stage table: %v", tableErr))
	}

	// Rule 2: the spend's RekeyTo is A_{n+1} for some n, which fixes the
	// signing stage from the bytes alone. The table only proposes the
	// number; the derivation that follows is what proves the address,
	// because a rekey target decides who controls the account and the table
	// is a plaintext cache. A wrong target is refused, never replaced.
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

	// Rule 5: rebuilding the complete group from the presented user slots
	// must reproduce their bytes and their group ID.
	plan, groupErr := s.buildRotatingPlan(snapshot, slots)
	if groupErr != nil {
		return nil, groupErr
	}
	if cmpErr := compareRebuiltRotatingGroup(slots, plan, full); cmpErr != nil {
		return nil, cmpErr
	}
	allTxns := plan.AllTxns
	users := len(slots.Txns)
	known := make(map[string]bool, len(snapshot.KeyFiles)+1)
	for addr := range knownAddressesFromSnapshot(snapshot) {
		known[addr] = true
	}
	// The rotation target is this signer's own next stage, never a foreign
	// authority: reject_foreign_rekey sees it as held, and because the signer
	// set the rekey itself and proved it derives from the seed, approval
	// warnings do not report it at all.
	known[spend.RekeyTo.String()] = true
	plan.KnownAddresses = known
	plan.ProtocolRekeyTargets = map[string]bool{spend.RekeyTo.String(): true}
	plan.Rotating = &rotatingPlanItem{Index: rot, Stage: stage, Target: targetStage, TargetAddress: spend.RekeyTo}
	signReq := signerapi.GroupSignRequest{RequestID: req.RequestID, Requests: slots.Requests}
	policyRuleID, release, gateErr := s.approveGroupWithPlanContext(ctx, signReq, plan)
	if gateErr != nil {
		return nil, gateErr
	}
	defer release()
	// The approval covers the whole group: check it before any key is used,
	// and again below before the rotating signature.
	if bindErr := checkApprovalBinding(signReq, plan); bindErr != nil {
		return nil, bindErr
	}
	var owned map[int]string
	if len(slots.Owned) > 0 {
		owned, err = s.Executor.SignOwnedSlots(ctx, plan, signReq, session, slots.Owned)
		if err != nil {
			return nil, err
		}
	}
	var lockGeneration uint64
	if deps.LockGeneration != nil {
		lockGeneration = deps.LockGeneration()
	}

	// A leaf family picks its one-time leaf from the stage's history, so a
	// spend arriving before that history has been restored from the audit
	// log after an unlock waits for it, bounded by the request. A restore
	// that fails opens the wait: state chooses the leaf, never whether to
	// sign.
	if p, ok := rotatingkey.Lookup(snapshot.KeyTypes[req.Account]); ok && p.LeavesPerStage > 1 {
		if err := deps.Releases.AwaitRestored(ctx, req.Account); err != nil {
			return nil, unavailable("release memory is still being restored from the audit log: " + err.Error())
		}
	}

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
	txID := sha512.Sum512_256(slots.Raw[rot])
	if !bytes.Equal(txnutil.EncodeWithPrefix(spend), txnutil.EncodeWithPrefix(allTxns[rot])) || !bytes.Equal(txID[:], algocrypto.TransactionID(allTxns[rot])) {
		return nil, internal("refusing to sign: the rotating spend differs from the approved group")
	}
	// The one-time leaf: the one this transaction already used if it was
	// signed before, else the first unused one from the TxID's pick, else
	// (every leaf spent) the TxID's pick again, reported as reuse. State
	// chooses the leaf, never whether to sign.
	txIDText := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(txID[:])
	leafProfile, _ := rotatingkey.Lookup(rs.keyType)
	prior, _ := deps.Releases.Get(req.Account)
	var leaf LeafRelease
	var leafReused bool
	if !leafProfile.StatelessHash {
		leaf, leafReused = chooseLeaf(leafProfile, stage, txID[:], txIDText, prior)
	}
	stageSig, signErr := rs.ops.SignStage(rs.secret, stage, leaf.Index, txID[:])
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
	// Stateless signing performs a complete hypertree signature. Re-read the
	// chain after that work and before releasing bytes. The existing execution
	// lease remains held; do not acquire a second lease here.
	if leafProfile.StatelessHash {
		readCtx, cancelRead := context.WithTimeout(ctx, DefaultChainReadTimeout)
		fresh, readErr := deps.Chain.ReadAccount(readCtx, genesis, account)
		cancelRead()
		if readErr != nil {
			return nil, unavailable(readErr.Error())
		}
		if fresh.Authorizer != stageAddr {
			return nil, rotatingStageChanged(fresh.Authorizer)
		}
		if uint64(spend.FirstValid) > fresh.Round+rotatingkey.RotatingMaxLead ||
			uint64(spend.LastValid) < fresh.Round+rotatingkey.RotatingMinRemaining {
			return nil, badRequest("validity window aged during signing; prepare the spend again")
		}
		if ctx.Err() != nil {
			return nil, unavailable(ctx.Err().Error())
		}
		if (s.IsUnlocked != nil && !s.IsUnlocked()) ||
			(deps.LockGeneration != nil && deps.LockGeneration() != lockGeneration) {
			return nil, lockedError()
		}
		if !s.keyPresent(req.Account)() {
			return nil, unavailable("rotating key was removed during signing")
		}
	}
	signed := make([]string, len(allTxns))
	signed[rot] = hex.EncodeToString(msgpack.Encode(stxn))
	for i, signedHex := range owned {
		signed[i] = signedHex
	}
	dummies, dummyErr := coresigning.SignDummyTransactions(allTxns[users:])
	if dummyErr != nil {
		return nil, internal(fmt.Sprintf("sign dummy transactions: %v", dummyErr))
	}
	for i, d := range dummies {
		signed[users+i] = hex.EncodeToString(d)
	}
	for i, entry := range signed {
		if entry == "" {
			return nil, internal(fmt.Sprintf("refusing to release an incomplete group: transaction %d is unsigned", i+1))
		}
	}
	var groupID types.Digest
	if len(allTxns) > 1 {
		groupID = allTxns[0].Group
	}
	groupIDText := base64.StdEncoding.EncodeToString(groupID[:])

	// The release is audited durably and remembered before the signature
	// leaves. Both are observational: a failure is reported, not fatal.
	if logger, ok := s.AuditLog.(AuditRotatingReleaseLogger); ok && logger != nil {
		if err := logger.LogRotatingRelease(req.Account, txIDText, stage, uint64(spend.LastValid), leaf.Tree, leaf.Index); err != nil {
			consoleOf(s.Console).Printf("[ROTATING] WARNING: release of stage %d for %s was not recorded in the audit log: %v\n", stage, req.Account, err)
		}
	}
	leaf.TxID, leaf.LastValid = txIDText, uint64(spend.LastValid)
	deps.Releases.Record(ReleaseRecord{
		Account: req.Account, Stage: stage, StageAddr: stageAddr, NextAddr: spend.RekeyTo,
		TxID: txIDText, LastValid: uint64(spend.LastValid), Reused: leafReused, Leaves: []LeafRelease{leaf}, StatelessHash: leafProfile.StatelessHash,
	})
	consoleOf(s.Console).Printf("[ROTATING] Released stage %d for %s (%s); the account moves to stage %d when it lands\n", stage, req.Account, txIDText, targetStage)
	s.logSuccessfulSignatures(signReq, plan, allTxns, policyRuleID)
	return &signerapi.RotatingSignResponse{
		Signed:    signed,
		Stage:     stage,
		Target:    targetStage,
		TxID:      txIDText,
		GroupID:   groupIDText,
		Rotations: []signerapi.RotationSlot{{Index: rot, Stage: stage, Target: targetStage, TxID: txIDText}},
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

// chooseLeaf picks the one-time leaf stage signs txID with, for a family
// whose stage holds several (rotatingkey.Profile.LeavesPerStage). A
// transaction the stage already released keeps its leaf, so an identical
// retry reproduces the identical signature. Otherwise the TxID's first byte
// picks a leaf inside the stage's range, and the first unused leaf upward
// from it, wrapping, is taken; two signers that share a seed and no memory
// therefore collide with probability one in LeavesPerStage rather than
// always. When every leaf is used the TxID's pick is reused and reported:
// state chooses the leaf, never whether to sign. A family with one key per
// stage always gets leaf 0.
func chooseLeaf(profile rotatingkey.Profile, stage uint64, txID []byte, txIDText string, prior ReleaseRecord) (LeafRelease, bool) {
	lo, hi := profile.LeafRange(stage)
	tree := profile.TreeOf(stage)
	leaf := LeafRelease{Tree: tree, Index: uint32(lo)}
	if hi-lo <= 1 {
		return leaf, false
	}
	if prior.Stage == stage {
		if used, ok := prior.LeafFor(txIDText); ok {
			return used, false
		}
	}
	n := hi - lo
	pick := lo
	if len(txID) > 0 {
		pick = lo + uint64(txID[0])%n
	}
	for i := uint64(0); i < n; i++ {
		candidate := lo + (pick-lo+i)%n
		if prior.Stage != stage || !prior.LeafUsed(tree, uint32(candidate), txIDText) {
			leaf.Index = uint32(candidate)
			return leaf, false
		}
	}
	leaf.Index = uint32(pick)
	return leaf, true
}
