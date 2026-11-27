// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"encoding/hex"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/hostmeta"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/rekeylist"
	"github.com/aplane-algo/aplane/internal/txeffects"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

type hostPath string

const (
	hostPathPureSpend        hostPath = "pure_spend"
	hostPathSpendingKeyRekey hostPath = "spending_key_rekey"
	// hostPathListedRekey is a pure rekey to an address on the account's
	// rekey-to list, signed by the spending key with a list proof.
	hostPathListedRekey hostPath = "listed_rekey"
)

type hostPlanItem struct {
	Path              hostPath
	Metadata          *hostmeta.Metadata
	BaseKeyType       string
	SpendingPublicKey []byte
	RuntimeArgs       map[string][]byte
	// ListedRekeyTargets is the account's rekey-to list, when it has one.
	// reject_foreign_rekey counts these targets as declared.
	ListedRekeyTargets map[string]bool
}

func resolveHostPlanItems(snapshot PlannerRuntimeSnapshot, req []signerapi.SignRequest, txns []types.Transaction, passthroughIndices, foreignIndices map[int]bool) ([]*hostPlanItem, *ServiceError) {
	items := make([]*hostPlanItem, len(req))
	for i, request := range req {
		if passthroughIndices[i] || foreignIndices[i] {
			continue
		}
		metadata := snapshot.KeyMetadata[request.AuthAddress].Host
		if metadata == nil {
			continue
		}
		if i >= len(txns) {
			return nil, internal("host plan transaction index is out of bounds")
		}
		path, listed, err := hostAccountPath(txns[i], metadata, snapshot.KeyMetadata[request.AuthAddress].Parameters)
		if err != nil {
			return nil, withTransactionIndex(i, err)
		}
		runtimeArgs, argErr := validateHostRuntimeArgs(request.LsigArgs, metadata, path)
		if argErr != nil {
			return nil, withTransactionIndex(i, argErr)
		}
		spendingPublicKey, decodeErr := hex.DecodeString(snapshot.KeyMetadata[request.AuthAddress].PublicKeyHex)
		if decodeErr != nil || len(spendingPublicKey) == 0 {
			return nil, internal(fmt.Sprintf("transaction %d: spending public key metadata is invalid", i+1))
		}
		// The planner snapshot is request-owned and read-only downstream, so
		// the item references its metadata directly instead of cloning again.
		items[i] = &hostPlanItem{
			Path: path, Metadata: metadata, BaseKeyType: snapshot.KeyMetadata[request.AuthAddress].BaseKeyType,
			SpendingPublicKey: spendingPublicKey, RuntimeArgs: runtimeArgs, ListedRekeyTargets: listed,
		}
	}
	return items, nil
}

func validateHostRuntimeArgs(encoded map[string]string, metadata *hostmeta.Metadata, path hostPath) (map[string][]byte, *ServiceError) {
	decoded, err := decodeHexRuntimeArgs(encoded)
	if err != nil {
		return nil, badRequest(err.Error())
	}
	slots := make(map[string]hostmeta.ArgumentSlot, len(metadata.RuntimeArgs))
	for _, slot := range metadata.ArgumentLayout {
		if slot.Source == hostmeta.ArgSourceRuntime {
			slots[slot.Name] = slot
		}
	}
	for name := range decoded {
		slot, ok := slots[name]
		if !ok {
			return nil, badRequest(fmt.Sprintf("caller argument %q is not a declared runtime slot", name))
		}
		if hostSlotRule(slot, path) == hostmeta.ArgForbidden {
			return nil, badRequest(fmt.Sprintf("bounded runtime argument %q is forbidden on %s", name, path))
		}
	}
	for _, arg := range metadata.RuntimeArgs {
		slot := slots[arg.Name]
		value, present := decoded[arg.Name]
		rule := hostSlotRule(slot, path)
		if rule == hostmeta.ArgRequired && (!present || len(value) == 0) {
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

func hostSlotRule(slot hostmeta.ArgumentSlot, path hostPath) string {
	switch path {
	case hostPathPureSpend:
		return slot.Paths.Spend
	case hostPathSpendingKeyRekey:
		return slot.Paths.SpendingRekey
	case hostPathListedRekey:
		return slot.Paths.ListedRekey
	default:
		return ""
	}
}

// listedRekeyTargets reads an account's rekey-to list from its stored
// parameters, or returns nil for an account without one.
func listedRekeyTargets(metadata *hostmeta.Metadata, parameters map[string]string) (map[string]bool, *ServiceError) {
	if metadata == nil || metadata.RekeyList == nil {
		return nil, nil
	}
	entries, err := rekeylist.ParseEntries(parameters[hostmeta.RekeyListEntriesParameter])
	if err != nil {
		return nil, internal(fmt.Sprintf("stored rekey-to list is invalid: %v", err))
	}
	listed := make(map[string]bool, len(entries))
	for _, entry := range entries {
		listed[entry.String()] = true
	}
	return listed, nil
}

// hostAccountPath is the path the signer signs a transaction on, and the
// account's rekey-to list: the declaration's path, with a listed target moved to
// the listed path. The planner and assembly both decide through it, so a
// component and its assembly can't disagree about whether the cosigner signs.
func hostAccountPath(txn types.Transaction, metadata *hostmeta.Metadata, parameters map[string]string) (hostPath, map[string]bool, *ServiceError) {
	path, err := classifyHostPath(txn, metadata)
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
	if path == hostPathSpendingKeyRekey && listed[txn.RekeyTo.String()] {
		path = hostPathListedRekey
	}
	// The program takes a listed rekey only to a listed target, so the signer
	// refuses any other rekey here instead of building a transaction the chain
	// would reject.
	if path == hostPathListedRekey && !listed[txn.RekeyTo.String()] {
		return "", nil, &ServiceError{Kind: ErrorRekeyTargetNotListed, Message: fmt.Sprintf(
			"%s is not on this account's rekey-to list, and the account refuses every other rekey", txn.RekeyTo)}
	}
	return path, listed, nil
}

// classifyHostPath decides which path the account's path declaration admits a
// transaction on. The declaration comes from the stored metadata, so the signer
// makes the decision txeffects.ClassifyFor makes for the account's contract.
func classifyHostPath(txn types.Transaction, metadata *hostmeta.Metadata) (hostPath, *ServiceError) {
	if metadata == nil {
		return "", internal("host metadata is missing")
	}
	if err := metadata.Validate(); err != nil {
		return "", internal(fmt.Sprintf("invalid stored host metadata: %v", err))
	}
	declaration, err := metadata.Declaration()
	if err != nil {
		return "", internal(fmt.Sprintf("invalid stored host declaration: %v", err))
	}
	decision, err := txeffects.ClassifyFor(txn, declaration)
	if err != nil {
		return "", internal(fmt.Sprintf("classify host transaction: %v", err))
	}
	switch decision.Path {
	case txeffects.PathSpend:
		return hostPathPureSpend, nil
	case txeffects.PathSpendingRekey:
		return hostPathSpendingKeyRekey, nil
	case txeffects.PathListedRekey:
		return hostPathListedRekey, nil
	case txeffects.PathRefused:
		return "", badRequest(decision.Reason)
	default:
		return "", internal(fmt.Sprintf("unknown host path %q", decision.Path))
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

// planHasCosignedHostTarget reports whether any host position belongs to a
// cosigned account, which signs only through the cosigned flow, even on a listed
// rekey that needs no cosigner component.
func planHasCosignedHostTarget(plan *PlanResult) bool {
	if plan == nil {
		return false
	}
	for _, item := range plan.HostItems {
		if item != nil && item.Metadata != nil && item.Metadata.Cosigner != nil {
			return true
		}
	}
	return false
}

func planHasHostRekey(plan *PlanResult) bool {
	if plan == nil {
		return false
	}
	for _, item := range plan.HostItems {
		if item != nil && item.Path != hostPathPureSpend {
			return true
		}
	}
	return false
}

// listedRekeyTargetsForPlan is each host position's rekey-to list, by index.
func listedRekeyTargetsForPlan(plan *PlanResult) map[int]map[string]bool {
	if plan == nil {
		return nil
	}
	var listed map[int]map[string]bool
	for i, item := range plan.HostItems {
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
