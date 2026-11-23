// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/aplane-algo/aplane/internal/cosigner/cosignerrefs"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
)

// changingLock is a mutation lock whose first Lock runs change first, as a
// template change holding the lock completes before the next waiter gets it.
type changingLock struct {
	mu     sync.Mutex
	change func()
}

func (l *changingLock) Lock() {
	if change := l.change; change != nil {
		l.change = nil
		change()
	}
	l.mu.Lock()
}

func (l *changingLock) Unlock() { l.mu.Unlock() }

// replacePrepareTemplate re-registers keyType as setupPrepareTest's template
// with a different fee limit, as a template reload would.
func replacePrepareTemplate(t *testing.T, keyType, family, maxFee string) {
	t.Helper()
	prepared, err := composeddsa.PrepareKeystoreTemplateRegistration(keyType, []byte(`
schema_version: 2
derivation_version: 3
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: strict
publisher: test
family: `+family+`
version: 1
display_name: Prepare Test
valid_rekey_target: true
max_opcode_cost: 20000
bounded:
  contract: bounded2
  spend_effects: [pay]
  max_fee: `+maxFee+`
  rekey: refused
  cosigner:
    contract: cosigner1
    required_on: [spend]
teal: |
  pushint 1
  assert
`))
	if err != nil {
		t.Fatal(err)
	}
	lsigprovider.Unregister(keyType)
	lsigprovider.RegisterIfAbsent(prepared.Provider)
}

// A creation request is resolved under the store mutation lock, which a
// template change holds too, so a template that changed while the request
// waited for the lock is the one its review describes and its checks judge.
func TestCreationResolvesTheTemplateInForceUnderTheLock(t *testing.T) {
	const keyType = "test.resolve-under-lock.v1"
	const family = "resolve-under-lock"
	ir, _, _ := setupPrepareTest(t, keyType, family)
	params := map[string]string{cosignerrefs.ParamCosignerName: prepareTestReference}

	before, err := Service{Runtime: ir}.PrepareGenerateKey(keyType, params)
	if err != nil {
		t.Fatalf("PrepareGenerateKey() error = %#v", err)
	}
	if before.Bounded == nil || before.Bounded.MaxFee == nil || *before.Bounded.MaxFee != 10000 {
		t.Fatalf("setup: Bounded = %+v, want the 10000 fee limit", before.Bounded)
	}

	lock := &changingLock{change: func() { replacePrepareTemplate(t, keyType, family, "20000") }}
	after, err := Service{Runtime: ir, MutationLock: lock}.PrepareGenerateKey(keyType, params)
	if err != nil {
		t.Fatalf("PrepareGenerateKey() across a template change error = %#v", err)
	}
	if after.Bounded == nil || after.Bounded.MaxFee == nil || *after.Bounded.MaxFee != 20000 {
		t.Fatalf("Bounded = %+v, want the 20000 fee limit of the template in force under the lock", after.Bounded)
	}
	if want := lsigprovider.TemplateFingerprintForKeyType(keyType); after.Fingerprint != want || after.Fingerprint == before.Fingerprint {
		t.Fatalf("Fingerprint = %q, want the changed template's %q", after.Fingerprint, want)
	}

	// The review of the earlier template no longer matches the one in force.
	lock = &changingLock{change: func() { replacePrepareTemplate(t, keyType, family, "30000") }}
	_, genErr := Service{Runtime: ir, MutationLock: lock}.GenerateReviewedKey(context.Background(), keyType, after.Parameters,
		ReviewedValues{Fingerprint: after.ReviewFingerprint})
	if genErr == nil || genErr.Kind != ErrorInvalidInput || !strings.Contains(genErr.Message, "changed after this request was reviewed") {
		t.Fatalf("GenerateReviewedKey() across a template change error = %#v, want the changed-definition refusal", genErr)
	}
	assertNoKeys(t, Service{Runtime: ir})
}
