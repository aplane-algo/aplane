// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import "testing"

func TestStablePolicyRuleIDs(t *testing.T) {
	ruleIDs := map[string]string{
		"RejectForeignRekeyRuleID":                RejectForeignRekeyRuleID,
		"RejectCloseRemainderRuleID":              RejectCloseRemainderRuleID,
		"RejectAssetCloseRuleID":                  RejectAssetCloseRuleID,
		"RejectClawbackRuleID":                    RejectClawbackRuleID,
		"MaxFeeExceededRuleID":                    MaxFeeExceededRuleID,
		"MaxAlgoPaymentExceededRuleID":            MaxAlgoPaymentExceededRuleID,
		"MaxASAAmountExceededRuleID":              MaxASAAmountExceededRuleID,
		"UnknownGenesisHashRuleID":                UnknownGenesisHashRuleID,
		"AlwaysReviewWarningsRuleID":              AlwaysReviewWarningsRuleID,
		"ReviewAlgoPaymentExceededRuleID":         ReviewAlgoPaymentExceededRuleID,
		"ReviewASAAmountExceededRuleID":           ReviewASAAmountExceededRuleID,
		"ReviewUnknownGenesisHashRuleID":          ReviewUnknownGenesisHashRuleID,
		"AutoApproveSelfNoOpTransferRuleID":       AutoApproveSelfNoOpTransferRuleID,
		"TransferRoutingBlockedDestinationRuleID": TransferRoutingBlockedDestinationRuleID,
		"TransferRoutingRouteMissRuleID":          TransferRoutingRouteMissRuleID,
		"TransferRoutingUnknownGenesisRuleID":     TransferRoutingUnknownGenesisRuleID,
		"TransferRoutingCloseRouteMissRuleID":     TransferRoutingCloseRouteMissRuleID,
		"TransferRoutingClawbackRouteMissRuleID":  TransferRoutingClawbackRouteMissRuleID,
		"TransferRoutingCloseRejectedRuleID":      TransferRoutingCloseRejectedRuleID,
		"TransferRoutingClawbackRejectedRuleID":   TransferRoutingClawbackRejectedRuleID,
		"AttestationPolicyMissingRuleID":          AttestationPolicyMissingRuleID,
		"AttestationTransferPolicyRequiredRuleID": AttestationTransferPolicyRequiredRuleID,
		"AttestationDeterministicRoutingRuleID":   AttestationDeterministicRoutingRuleID,
		"AttestationNonTransferRuleID":            AttestationNonTransferRuleID,
		"AttestationRekeyRuleID":                  AttestationRekeyRuleID,
	}
	want := map[string]string{
		"RejectForeignRekeyRuleID":                "reject_foreign_rekey",
		"RejectCloseRemainderRuleID":              "reject_close_remainder",
		"RejectAssetCloseRuleID":                  "reject_asset_close",
		"RejectClawbackRuleID":                    "reject_clawback",
		"MaxFeeExceededRuleID":                    "max_fee_exceeded",
		"MaxAlgoPaymentExceededRuleID":            "max_algo_payment_exceeded",
		"MaxASAAmountExceededRuleID":              "max_asa_amount_exceeded",
		"UnknownGenesisHashRuleID":                "unknown_genesis_hash",
		"AlwaysReviewWarningsRuleID":              "always_review_warnings",
		"ReviewAlgoPaymentExceededRuleID":         "review_algo_payment_exceeded",
		"ReviewASAAmountExceededRuleID":           "review_asa_amount_exceeded",
		"ReviewUnknownGenesisHashRuleID":          "review_unknown_genesis_hash",
		"AutoApproveSelfNoOpTransferRuleID":       "auto_approve_self_noop_transfer",
		"TransferRoutingBlockedDestinationRuleID": "transfer_policy:blocked_destination",
		"TransferRoutingRouteMissRuleID":          "transfer_policy:route_miss",
		"TransferRoutingUnknownGenesisRuleID":     "transfer_policy:unknown_genesis_hash",
		"TransferRoutingCloseRouteMissRuleID":     "transfer_policy:close_route_miss",
		"TransferRoutingClawbackRouteMissRuleID":  "transfer_policy:clawback_route_miss",
		"TransferRoutingCloseRejectedRuleID":      "transfer_policy:close_rejected",
		"TransferRoutingClawbackRejectedRuleID":   "transfer_policy:clawback_rejected",
		"AttestationPolicyMissingRuleID":          "attestation_policy:missing",
		"AttestationTransferPolicyRequiredRuleID": "attestation_policy:transfer_policy_required",
		"AttestationDeterministicRoutingRuleID":   "attestation_policy:deterministic_routing_required",
		"AttestationNonTransferRuleID":            "attestation_policy:non_transfer",
		"AttestationRekeyRuleID":                  "attestation_policy:reject_rekey",
	}
	for name, wantID := range want {
		if ruleIDs[name] != wantID {
			t.Fatalf("%s = %q, want %q", name, ruleIDs[name], wantID)
		}
	}
	seen := make(map[string]string, len(ruleIDs))
	for name, ruleID := range ruleIDs {
		if prior := seen[ruleID]; prior != "" {
			t.Fatalf("duplicate rule ID %q in %s and %s", ruleID, prior, name)
		}
		seen[ruleID] = name
	}
}

func TestTransferRoutingRouteRuleID(t *testing.T) {
	tests := []struct {
		name    string
		outcome string
		want    string
	}{
		{"close", TransferRoutingCloseRejectedOutcome, "transfer_policy:payroll_algo:close_rejected"},
		{"clawback", TransferRoutingClawbackRejectedOutcome, "transfer_policy:payroll_algo:clawback_rejected"},
		{"reject threshold", TransferRoutingRejectAboveOutcome, "transfer_policy:payroll_algo:reject_above"},
		{"review threshold", TransferRoutingReviewAboveOutcome, "transfer_policy:payroll_algo:review_above"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := TransferRoutingRouteRuleID("payroll_algo", tc.outcome); got != tc.want {
				t.Fatalf("TransferRoutingRouteRuleID = %q, want %q", got, tc.want)
			}
		})
	}
}
