// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package productruntime

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/asaset"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
)

// Readers see the policy and the ASA set from the same update, never one
// update's policy with another's set.
func TestPolicyStateIsOneConsistentView(t *testing.T) {
	ir := &Runtime{}
	type state struct {
		policy *policyruntime.NodePolicy
		set    *asaset.Set
	}
	states := []state{{&policyruntime.NodePolicy{}, asaset.Empty()}, {&policyruntime.NodePolicy{}, asaset.Empty()}}
	pairs := map[*policyruntime.NodePolicy]*asaset.Set{states[0].policy: states[0].set, states[1].policy: states[1].set}
	ir.SetVerifiedPolicyState(states[0].policy, states[0].set, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 20000; i++ {
			s := states[i%2]
			ir.SetVerifiedPolicyState(s.policy, s.set, nil)
		}
	}()
	for {
		select {
		case <-done:
			return
		default:
		}
		policy, set := ir.PolicyState()
		if pairs[policy] != set {
			t.Fatal("PolicyState() returned one update's policy with another's set")
		}
	}
}
