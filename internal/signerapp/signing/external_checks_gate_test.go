// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/txnutil"
)

// A cosigner document with external checks signs nothing while the checks
// cannot run: a transfer its routes allow is refused before any key is used,
// under the check's rule ID. A transfer the routes refuse keeps the policy's
// own rule, since the checks judge only what the policy would sign.
func TestCosignerRefusesWhileExternalChecksCannotRun(t *testing.T) {
	source := types.Address{25}.String()
	allowed := types.Address{26}.String()
	other := types.Address{27}.String()
	cfg := cosignerRoutePolicy(t, source, allowed)
	cfg.ExternalSources = map[string]policy.ExternalSourceV1{"ops": {BaseURL: "http://127.0.0.1:1"}}
	cfg.ExternalChecks = []policy.ExternalCheckV1{{ID: "ops-switch", Source: "ops", Scope: policy.ExternalScopeRequest, NetworkWildcard: true}}

	sign := func(destination string) (*ServiceError, *componentKeyStore) {
		store := &componentKeyStore{}
		txn := testnetPaymentTransaction(t, source, destination, 1)
		_, err := cosignerTestService(t, cfg).signComponentWithContext(context.Background(), componentPlanRequest{
			RequestID:     "cmp-cosigner-external",
			ComponentKey:  testFalconComponentSelector(t, 0xab),
			Group:         componentTestGroup(t, []string{txnutil.EncodeWithPrefixHex(txn)}),
			TargetIndices: []int{0},
		}, newComponentKeySession(store))
		return err, store
	}

	err, store := sign(allowed)
	if err == nil || err.Kind != ErrorForbidden {
		t.Fatalf("error = %#v, want forbidden", err)
	}
	wantRule := policy.ExternalCheckRuleID("ops-switch", policy.ExternalCheckUnavailableOutcome)
	if !strings.Contains(err.Message, wantRule) {
		t.Fatalf("error = %q, want rule %s", err.Message, wantRule)
	}
	if store.calls != 0 {
		t.Fatalf("store calls = %d, want none before the refusal", store.calls)
	}

	err, _ = sign(other)
	if err == nil || !strings.Contains(err.Message, policy.TransferRoutingRouteMissRuleID) {
		t.Fatalf("error = %#v, want the policy's route miss", err)
	}
	if strings.Contains(err.Message, "external_check") {
		t.Fatalf("error = %q names an external check for a request the policy refused", err.Message)
	}

	// Without checks the same allowed transfer passes the gates.
	cfg.ExternalChecks = nil
	if err, _ = sign(allowed); err != nil && strings.Contains(err.Message, "external") {
		t.Fatalf("error = %q without checks", err.Message)
	}
}
