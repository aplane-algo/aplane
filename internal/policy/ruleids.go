// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import "fmt"

const (
	RejectForeignRekeyRuleID     = "reject_foreign_rekey"
	RejectCloseRemainderRuleID   = "reject_close_remainder"
	RejectAssetCloseRuleID       = "reject_asset_close"
	RejectClawbackRuleID         = "reject_clawback"
	MaxFeeExceededRuleID         = "max_fee_exceeded"
	MaxAlgoPaymentExceededRuleID = "max_algo_payment_exceeded"
	MaxASAAmountExceededRuleID   = "max_asa_amount_exceeded"
	UnknownGenesisHashRuleID     = "unknown_genesis_hash"

	// AlwaysReviewWarningsRuleID identifies the rule that forces manual review
	// when approval warning analysis finds risk markers.
	AlwaysReviewWarningsRuleID = "always_review_warnings"

	// ReviewAlgoPaymentExceededRuleID identifies a per-network ALGO payment
	// threshold that forces manual review.
	ReviewAlgoPaymentExceededRuleID = "review_algo_payment_exceeded"

	// ReviewASAAmountExceededRuleID identifies a per-network ASA transfer
	// threshold that forces manual review.
	ReviewASAAmountExceededRuleID = "review_asa_amount_exceeded"

	// ReviewUnknownGenesisHashRuleID identifies requests that cannot be checked
	// against configured review thresholds because the transaction genesis hash
	// is not mapped to a network token.
	ReviewUnknownGenesisHashRuleID = "review_unknown_genesis_hash"

	// AutoApproveSelfNoOpTransferRuleID identifies the narrow rule that can
	// auto-approve a single 0-value self-transfer request.
	AutoApproveSelfNoOpTransferRuleID = "auto_approve_self_noop_transfer"

	TransferRoutingBlockedDestinationRuleID = "transfer_policy:blocked_destination"
	TransferRoutingRouteMissRuleID          = "transfer_policy:route_miss"
	TransferRoutingUnknownGenesisRuleID     = "transfer_policy:unknown_genesis_hash"
	TransferRoutingCloseRouteMissRuleID     = "transfer_policy:close_route_miss"
	TransferRoutingClawbackRouteMissRuleID  = "transfer_policy:clawback_route_miss"
	TransferRoutingCloseRejectedRuleID      = "transfer_policy:close_rejected"
	TransferRoutingClawbackRejectedRuleID   = "transfer_policy:clawback_rejected"
)

const (
	TransferRoutingCloseRejectedOutcome    = "close_rejected"
	TransferRoutingClawbackRejectedOutcome = "clawback_rejected"
	TransferRoutingRejectAboveOutcome      = "reject_above"
	TransferRoutingReviewAboveOutcome      = "review_above"
)

// TransferRoutingRouteRuleID builds dynamic per-route rule IDs using the
// documented grammar transfer_policy:<route_id>:<outcome>.
func TransferRoutingRouteRuleID(routeID, outcome string) string {
	return fmt.Sprintf("transfer_policy:%s:%s", routeID, outcome)
}
