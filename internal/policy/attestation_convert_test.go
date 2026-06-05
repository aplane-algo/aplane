// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestConvertSigningPolicyToAttestationDropsReviewAndPreservesHardBounds(t *testing.T) {
	raw := `
always_review_warnings: true
review_algo_payments:
  testnet: 10
max_algo_payments:
  testnet: 100
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  close_on_no_route: reject
  clawback_on_no_route: reject
  routes:
    - id: payroll
      networks: [testnet]
      sources: ["*"]
      assets: [algo]
      destinations: ["*"]
      limits:
        review_above: 10
        reject_above: 100
      limits_by_network:
        testnet:
          review_above: 20
          reject_above: 200
`
	stored, err := ParseStoredConfig([]byte(raw))
	if err != nil {
		t.Fatalf("ParseStoredConfig() error = %v", err)
	}

	converted, err := ConvertSigningPolicyToAttestation(stored)
	if err != nil {
		t.Fatalf("ConvertSigningPolicyToAttestation() error = %v", err)
	}
	if converted.RejectRekey == nil || !*converted.RejectRekey {
		t.Fatal("RejectRekey = nil/false, want true")
	}
	if got := converted.MaxAlgoPayments["testnet"]; got != 100 {
		t.Fatalf("MaxAlgoPayments[testnet] = %d, want 100", got)
	}
	if len(converted.ReviewAlgoPayments) > 0 {
		t.Fatalf("ReviewAlgoPayments = %#v, want omitted", converted.ReviewAlgoPayments)
	}
	route := converted.TransferPolicy.Routes[0]
	if route.Limits == nil || route.Limits.RejectAbove == nil || *route.Limits.RejectAbove != 100 {
		t.Fatalf("route limits = %#v, want reject_above 100", route.Limits)
	}
	if route.Limits.ReviewAbove != nil {
		t.Fatalf("route limits.review_above = %d, want nil", *route.Limits.ReviewAbove)
	}
	if got := route.LimitsByNetwork["testnet"].ReviewAbove; got != nil {
		t.Fatalf("limits_by_network review_above = %d, want nil", *got)
	}

	data, err := MarshalStoredAttestationConfig(converted)
	if err != nil {
		t.Fatalf("MarshalStoredAttestationConfig() error = %v", err)
	}
	if strings.Contains(string(data), "review_") || strings.Contains(string(data), "attestation:") {
		t.Fatalf("converted attestation YAML contains review fields or wrapper:\n%s", data)
	}
	if _, err := ParseStoredAttestationConfig(data); err != nil {
		t.Fatalf("ParseStoredAttestationConfig(converted) error = %v\nyaml:\n%s", err, data)
	}
}

func TestConvertSigningPolicyToAttestationUsesClientSigningOverlay(t *testing.T) {
	raw := `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: review
  routes:
    - id: inherited
      networks: [testnet]
      sources: ["*"]
      assets: [algo]
      destinations: ["*"]
client_signing:
  transfer_policy:
    schema_version: 1
    enabled: true
    on_no_route: reject
    routes:
      - id: client_only
        networks: [testnet]
        sources: ["*"]
        assets: [algo]
        destinations: ["*"]
`
	stored, err := ParseStoredConfig([]byte(raw))
	if err != nil {
		t.Fatalf("ParseStoredConfig() error = %v", err)
	}

	converted, err := ConvertSigningPolicyToAttestation(stored)
	if err != nil {
		t.Fatalf("ConvertSigningPolicyToAttestation() error = %v", err)
	}
	if got := converted.TransferPolicy.Routes[0].ID; got != "client_only" {
		t.Fatalf("converted route ID = %q, want client_only", got)
	}
}

func TestConvertSigningPolicyToAttestationRejectsUnrepresentableRouteMiss(t *testing.T) {
	raw := `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: review
`
	stored, err := ParseStoredConfig([]byte(raw))
	if err != nil {
		t.Fatalf("ParseStoredConfig() error = %v", err)
	}

	_, err = ConvertSigningPolicyToAttestation(stored)
	if err == nil {
		t.Fatal("ConvertSigningPolicyToAttestation() error = nil, want route-miss rejection")
	}
	if !strings.Contains(err.Error(), "cannot be converted") {
		t.Fatalf("ConvertSigningPolicyToAttestation() error = %v, want cannot be converted", err)
	}
}

func TestConvertSigningPolicyToAttestationRejectsKeyOverrides(t *testing.T) {
	addr := types.Address{1}.String()
	raw := `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
key_overrides:
  ` + addr + `:
    max_fee_microalgos: 1000
`
	stored, err := ParseStoredConfig([]byte(raw))
	if err != nil {
		t.Fatalf("ParseStoredConfig() error = %v", err)
	}

	_, err = ConvertSigningPolicyToAttestation(stored)
	if err == nil {
		t.Fatal("ConvertSigningPolicyToAttestation() error = nil, want key_overrides rejection")
	}
	if !strings.Contains(err.Error(), "key_overrides cannot be converted") {
		t.Fatalf("ConvertSigningPolicyToAttestation() error = %v, want key_overrides rejection", err)
	}
}
