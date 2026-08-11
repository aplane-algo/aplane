// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/txeffects"
)

type boundedPath string

const (
	boundedPathPureSpend        boundedPath = "pure_spend"
	boundedPathSpendingKeyRekey boundedPath = "spending_key_rekey"
	boundedPathAdminKeyRekey    boundedPath = "admin_key_rekey"
)

type boundedPlanItem struct {
	Path              boundedPath
	Metadata          *boundedmeta.Metadata
	SpendingPublicKey []byte
	RuntimeArgs       map[string][]byte
}

func resolveBoundedPlanItems(snapshot PlannerIdentitySnapshot, req []signerapi.SignRequest, txns []types.Transaction, passthroughIndices, foreignIndices map[int]bool) ([]*boundedPlanItem, *ServiceError) {
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
		items[i] = &boundedPlanItem{Path: path, Metadata: metadata, SpendingPublicKey: spendingPublicKey, RuntimeArgs: runtimeArgs}
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
			return nil, badRequest(fmt.Sprintf("bounded1 caller argument %q is not a declared runtime slot", name))
		}
		if boundedSlotRule(slot, path) == boundedmeta.ArgForbidden {
			return nil, badRequest(fmt.Sprintf("bounded1 runtime argument %q is forbidden on %s", name, path))
		}
	}
	for _, arg := range metadata.RuntimeArgs {
		slot := slots[arg.Name]
		value, present := decoded[arg.Name]
		rule := boundedSlotRule(slot, path)
		if rule == boundedmeta.ArgRequired && (!present || len(value) == 0) {
			return nil, badRequest(fmt.Sprintf("missing required bounded1 runtime argument %q", arg.Name))
		}
		if !present {
			continue
		}
		if arg.ByteLength > 0 && len(value) != arg.ByteLength {
			return nil, badRequest(fmt.Sprintf("bounded1 runtime argument %q must be %d bytes, got %d", arg.Name, arg.ByteLength, len(value)))
		}
		if len(value) > arg.MaxSize {
			return nil, badRequest(fmt.Sprintf("bounded1 runtime argument %q exceeds %d-byte maximum", arg.Name, arg.MaxSize))
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
	case boundedPathAdminKeyRekey:
		return slot.Paths.AdminRekey
	default:
		return ""
	}
}

func classifyBoundedPath(txn types.Transaction, metadata *boundedmeta.Metadata) (boundedPath, *ServiceError) {
	if metadata == nil {
		return "", internal("bounded authorization metadata is missing")
	}
	if err := metadata.Validate(); err != nil {
		return "", internal(fmt.Sprintf("invalid stored bounded authorization metadata: %v", err))
	}
	if uint64(txn.Fee) > metadata.MaxFee {
		return "", badRequest(fmt.Sprintf("bounded1 fee %d exceeds account maximum %d", txn.Fee, metadata.MaxFee))
	}

	classification := txeffects.Classify(txn)
	switch classification.Shape {
	case txeffects.ShapePureSpend:
		if !boundedSpendEffectAllowed(metadata, classification.SpendEffect) {
			return "", badRequest(fmt.Sprintf("bounded1 account does not allow spend effect %q", classification.SpendEffect))
		}
		return boundedPathPureSpend, nil
	case txeffects.ShapePureRekey:
		authorization, ok := boundedRekeyAuthorization(metadata)
		if !ok {
			return "", badRequest("bounded1 account permanently disables rekey")
		}
		switch authorization {
		case boundedmeta.AdminAuthorizationSpend:
			return boundedPathSpendingKeyRekey, nil
		case boundedmeta.AdminAuthorizationAdmin:
			return boundedPathAdminKeyRekey, nil
		default:
			return "", internal(fmt.Sprintf("invalid stored rekey authorization %q", authorization))
		}
	case txeffects.ShapeHybrid:
		return "", badRequest(fmt.Sprintf("bounded1 rejects hybrid transaction effects: %s", boundedEffectNames(classification.Facts)))
	case txeffects.ShapeDeniedEffect:
		return "", badRequest(fmt.Sprintf("bounded1 rejects transaction effects: %s", boundedEffectNames(classification.Facts)))
	case txeffects.ShapeDeniedType:
		return "", badRequest(fmt.Sprintf("bounded1 rejects transaction type %q", txn.Type))
	default:
		return "", internal(fmt.Sprintf("unknown bounded1 classification %q", classification.Shape))
	}
}

func boundedSpendEffectAllowed(metadata *boundedmeta.Metadata, effect txeffects.SpendEffect) bool {
	for _, allowed := range metadata.SpendEffects {
		if allowed == string(effect) {
			return true
		}
	}
	return false
}

func boundedRekeyAuthorization(metadata *boundedmeta.Metadata) (string, bool) {
	for _, operation := range metadata.AdminOperations {
		if operation.Kind == boundedmeta.AdminOperationRekey {
			return operation.Authorization, true
		}
	}
	return "", false
}

func boundedEffectNames(facts txeffects.Facts) string {
	effects := facts.Effects()
	if len(effects) == 0 {
		return "none"
	}
	names := make([]string, len(effects))
	for i, effect := range effects {
		names[i] = string(effect)
	}
	return strings.Join(names, ", ")
}

func withTransactionIndex(index int, err *ServiceError) *ServiceError {
	if err == nil {
		return nil
	}
	return &ServiceError{Kind: err.Kind, Message: fmt.Sprintf("transaction %d: %s", index+1, err.Message)}
}

func planHasBoundedAdminKeyOperation(plan *PlanResult) bool {
	if plan == nil {
		return false
	}
	for _, item := range plan.BoundedItems {
		if item != nil && item.Path == boundedPathAdminKeyRekey {
			return true
		}
	}
	return false
}

func planHasBoundedSentrySpend(plan *PlanResult) bool {
	if plan == nil {
		return false
	}
	for _, item := range plan.BoundedItems {
		if item != nil && item.Path == boundedPathPureSpend && item.Metadata != nil && item.Metadata.Sentry != nil {
			return true
		}
	}
	return false
}

func planHasBoundedAdminOperation(plan *PlanResult) bool {
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
