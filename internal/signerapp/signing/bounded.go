// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"encoding/hex"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/txeffects"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

type boundedPath string

const (
	boundedPathPureSpend        boundedPath = "pure_spend"
	boundedPathSpendingKeyRekey boundedPath = "spending_key_rekey"
)

type boundedPlanItem struct {
	Path              boundedPath
	Metadata          *boundedmeta.Metadata
	BaseKeyType       string
	SpendingPublicKey []byte
	RuntimeArgs       map[string][]byte
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
		path, err := classifyBoundedPath(txns[i], metadata)
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
			SpendingPublicKey: spendingPublicKey, RuntimeArgs: runtimeArgs,
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
	}
	return decoded, nil
}

func boundedSlotRule(slot boundedmeta.ArgumentSlot, path boundedPath) string {
	switch path {
	case boundedPathPureSpend:
		return slot.Paths.Spend
	case boundedPathSpendingKeyRekey:
		return slot.Paths.SpendingRekey
	default:
		return ""
	}
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
	case txeffects.PathRefused:
		return "", badRequest(decision.Reason)
	default:
		return "", internal(fmt.Sprintf("unknown bounded path %q", decision.Path))
	}
}

func withTransactionIndex(index int, err *ServiceError) *ServiceError {
	if err == nil {
		return nil
	}
	return &ServiceError{Kind: err.Kind, Message: fmt.Sprintf("transaction %d: %s", index+1, err.Message)}
}

func planHasBoundedCosignerSpend(plan *PlanResult) bool {
	if plan == nil {
		return false
	}
	for _, item := range plan.BoundedItems {
		if item != nil && item.Path == boundedPathPureSpend && item.Metadata != nil && item.Metadata.Cosigner != nil {
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
