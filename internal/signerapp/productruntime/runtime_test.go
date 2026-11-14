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

// The unsaved settings are reported in key order, which admin_settings
// carries as is and apadmin shows without sorting again; a save clears its
// setting.
func TestUnsavedSettingsAreReportedInKeyOrder(t *testing.T) {
	cfg := NewRuntimeConfig(false, false, 0, 0)
	for _, key := range []string{"user_auto_approve", "lock_on_disconnect", "require_contained"} {
		cfg.SetUnsaved(key, true)
	}
	cfg.SetUnsaved("require_contained", false)
	if got := cfg.UnsavedSettings(); len(got) != 2 || got[0] != "lock_on_disconnect" || got[1] != "user_auto_approve" {
		t.Fatalf("UnsavedSettings = %v, want [lock_on_disconnect user_auto_approve]", got)
	}
	if !cfg.IsUnsaved("user_auto_approve") || cfg.IsUnsaved("require_contained") {
		t.Fatal("IsUnsaved disagrees with UnsavedSettings")
	}
}
