// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"encoding/hex"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/rekeylist"
	"github.com/aplane-algo/aplane/internal/txeffects"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

type boundedPath string

const (
	boundedPathPureSpend        boundedPath = "pure_spend"
	boundedPathSpendingKeyRekey boundedPath = "spending_key_rekey"
	// boundedPathListedRekey is a pure rekey to an address on the account's
	// rekey-to list, signed by the spending key with a list proof.
	boundedPathListedRekey boundedPath = "listed_rekey"
)

type boundedPlanItem struct {
	Path              boundedPath
	Metadata          *boundedmeta.Metadata
	BaseKeyType       string
	SpendingPublicKey []byte
	RuntimeArgs       map[string][]byte
	// ListedRekeyTargets is the account's rekey-to list, when it has one.
	// reject_foreign_rekey counts these targets as declared.
	ListedRekeyTargets map[string]bool
}

func resolveBoundedPlanItems(snapshot PlannerRuntimeSnapshot, req []signerapi.SignRequest, txns []types.Transaction, passthroughIndices, foreignIndices map[int]bool) ([]*boundedPlanItem, *ServiceError) {
	items := make([]*boundedPlanItem, len(req))
	for i, request := range req {
		if passthroughIndices[i] || foreignIndices[i] {
			continue
		}
		metadata := snapshot.KeyMetadata[request.AuthAddress].BoundedAuthorization
		if metadata == nil {
			continue
		}
		if i >= len(txns) {
			return nil, internal("bounded plan transaction index is out of bounds")
		}
		path, listed, err := boundedAccountPath(txns[i], metadata, snapshot.KeyMetadata[request.AuthAddress].Parameters)
		if err != nil {
			return nil, withTransactionIndex(i, err)
		}
		runtimeArgs, argErr := validateBoundedRuntimeArgs(request.LsigArgs, metadata, path)
		if argErr != nil {
			return nil, withTransactionIndex(i, argErr)
		}
		spendingPublicKey, decodeErr := hex.DecodeString(snapshot.KeyMetadata[request.AuthAddress].PublicKeyHex)
		if decodeErr != nil || len(spendingPublicKey) == 0 {
			return nil, internal(fmt.Sprintf("transaction %d: bounded spending public key metadata is invalid", i+1))
		}
		// The planner snapshot is request-owned and read-only downstream, so
		// the item references its metadata directly instead of cloning again.
		items[i] = &boundedPlanItem{
			Path: path, Metadata: metadata, BaseKeyType: snapshot.KeyMetadata[request.AuthAddress].BaseKeyType,
			SpendingPublicKey: spendingPublicKey, RuntimeArgs: runtimeArgs, ListedRekeyTargets: listed,
		}
	}
	return items, nil
}

func validateBoundedRuntimeArgs(encoded map[string]string, metadata *boundedmeta.Metadata, path boundedPath) (map[string][]byte, *ServiceError) {
	decoded, err := DecodeHexRuntimeArgs(encoded)
	if err != nil {
		return nil, badRequest(err.Error())
	}
	slots := make(map[string]boundedmeta.ArgumentSlot, len(metadata.RuntimeArgs))
	for _, slot := range metadata.ArgumentLayout {
		if slot.Source == boundedmeta.ArgSourceRuntime {
			slots[slot.Name] = slot
		}
	}
	for name := range decoded {
		slot, ok := slots[name]
		if !ok {
			return nil, badRequest(fmt.Sprintf("bounded caller argument %q is not a declared runtime slot", name))
		}
		if boundedSlotRule(slot, path) == boundedmeta.ArgForbidden {
			return nil, badRequest(fmt.Sprintf("bounded runtime argument %q is forbidden on %s", name, path))
		}
	}
	for _, arg := range metadata.RuntimeArgs {
		slot := slots[arg.Name]
		value, present := decoded[arg.Name]
		rule := boundedSlotRule(slot, path)
		if rule == boundedmeta.ArgRequired && (!present || len(value) == 0) {
			return nil, badRequest(fmt.Sprintf("missing required bounded runtime argument %q", arg.Name))
		}
		if !present {
			continue
		}
		if arg.ByteLength > 0 && len(value) != arg.ByteLength {
			return nil, badRequest(fmt.Sprintf("bounded runtime argument %q must be %d bytes, got %d", arg.Name, arg.ByteLength, len(value)))
		}
		if len(value) > arg.MaxSize {
			return nil, badRequest(fmt.Sprintf("bounded runtime argument %q exceeds %d-byte maximum", arg.Name, arg.MaxSize))
		}
		// The network's own limit, for an account stored with a larger maximum.
		// Only a supplied value is checked, so a path that omits the argument,
		// such as a rekey, still works.
		if len(value) > lsigresource.MaxLogicSigArgBytes {
			return nil, badRequest(fmt.Sprintf("bounded runtime argument %q is %d bytes, and a LogicSig argument is at most %d", arg.Name, len(value), lsigresource.MaxLogicSigArgBytes))
		}
	}
	return decoded, nil
}

func boundedSlotRule(slot boundedmeta.ArgumentSlot, path boundedPath) string {
	switch path {
	case boundedPathPureSpend:
		return slot.Paths.Spend
	case boundedPathSpendingKeyRekey:
		return slot.Paths.SpendingRekey
	case boundedPathListedRekey:
		return slot.Paths.ListedRekey
	default:
		return ""
	}
}

// listedRekeyTargets reads an account's rekey-to list from its stored
// parameters, or returns nil for an account without one.
func listedRekeyTargets(metadata *boundedmeta.Metadata, parameters map[string]string) (map[string]bool, *ServiceError) {
	if metadata == nil || metadata.RekeyList == nil {
		return nil, nil
	}
	entries, err := rekeylist.ParseEntries(parameters[boundedmeta.RekeyListEntriesParameter])
	if err != nil {
		return nil, internal(fmt.Sprintf("stored rekey-to list is invalid: %v", err))
	}
	listed := make(map[string]bool, len(entries))
	for _, entry := range entries {
		listed[entry.String()] = true
	}
	return listed, nil
}

// boundedAccountPath is the path the signer signs a transaction on, and the
// account's rekey-to list: the declaration's path, with a listed target moved to
// the listed path. The planner and assembly both decide through it, so a
// component and its assembly can't disagree about whether the cosigner signs.
func boundedAccountPath(txn types.Transaction, metadata *boundedmeta.Metadata, parameters map[string]string) (boundedPath, map[string]bool, *ServiceError) {
	path, err := classifyBoundedPath(txn, metadata)
	if err != nil {
		return "", nil, err
	}
	listed, err := listedRekeyTargets(metadata, parameters)
	if err != nil {
		return "", nil, err
	}
	// Under plus cosigned the list is the owner's standing statement: a listed
	// target always takes the listed path, with the spending key alone, and only
	// another target asks the cosigner.
	if path == boundedPathSpendingKeyRekey && listed[txn.RekeyTo.String()] {
		path = boundedPathListedRekey
	}
	// The program takes a listed rekey only to a listed target, so the signer
	// refuses any other rekey here instead of building a transaction the chain
	// would reject.
	if path == boundedPathListedRekey && !listed[txn.RekeyTo.String()] {
		return "", nil, &ServiceError{Kind: ErrorBoundedRekeyNotListed, Message: fmt.Sprintf(
			"%s is not on this account's rekey-to list, and the account refuses every other rekey", txn.RekeyTo)}
	}
	return path, listed, nil
}

// classifyBoundedPath decides which path the account's path declaration admits a
// transaction on. The declaration comes from the stored metadata, so the signer
// makes the decision txeffects.ClassifyFor makes for the account's contract.
func classifyBoundedPath(txn types.Transaction, metadata *boundedmeta.Metadata) (boundedPath, *ServiceError) {
	if metadata == nil {
		return "", internal("bounded authorization metadata is missing")
	}
	if err := metadata.Validate(); err != nil {
		return "", internal(fmt.Sprintf("invalid stored bounded authorization metadata: %v", err))
	}
	declaration, err := metadata.Declaration()
	if err != nil {
		return "", internal(fmt.Sprintf("invalid stored bounded declaration: %v", err))
	}
	decision, err := txeffects.ClassifyFor(txn, declaration)
	if err != nil {
		return "", internal(fmt.Sprintf("classify bounded transaction: %v", err))
	}
	switch decision.Path {
	case txeffects.PathSpend:
		return boundedPathPureSpend, nil
	case txeffects.PathSpendingRekey:
		return boundedPathSpendingKeyRekey, nil
	case txeffects.PathListedRekey:
		return boundedPathListedRekey, nil
	case txeffects.PathRefused:
		return "", badRequest(decision.Reason)
	default:
		return "", internal(fmt.Sprintf("unknown bounded path %q", decision.Path))
	}
}

// withTransactionIndex is err naming the transaction at the zero-based index
// of the group: its message says "transaction N:" for people, and its
// RefusedPosition carries the index, where the audit log records a refusal.
func withTransactionIndex(index int, err *ServiceError) *ServiceError {
	if err == nil {
		return nil
	}
	position := index
	return &ServiceError{Kind: err.Kind, Message: fmt.Sprintf("transaction %d: %s", index+1, err.Message), RefusedPosition: &position}
}

// planHasCosignedBoundedTarget reports whether any bounded position belongs to a
// cosigned account, which signs only through the cosigned flow, even on a listed
// rekey that needs no cosigner component.
func planHasCosignedBoundedTarget(plan *PlanResult) bool {
	if plan == nil {
		return false
	}
	for _, item := range plan.BoundedItems {
		if item != nil && item.Metadata != nil && item.Metadata.Cosigner != nil {
			return true
		}
	}
	return false
}

func planHasBoundedRekey(plan *PlanResult) bool {
	if plan == nil {
		return false
	}
	for _, item := range plan.BoundedItems {
		if item != nil && item.Path != boundedPathPureSpend {
			return true
		}
	}
	return false
}

// listedRekeyTargetsForPlan is each bounded position's rekey-to list, by index.
func listedRekeyTargetsForPlan(plan *PlanResult) map[int]map[string]bool {
	if plan == nil {
		return nil
	}
	var listed map[int]map[string]bool
	for i, item := range plan.BoundedItems {
		if item == nil || item.ListedRekeyTargets == nil {
			continue
		}
		if listed == nil {
			listed = make(map[int]map[string]bool)
		}
		listed[i] = item.ListedRekeyTargets
	}
	return listed
}
