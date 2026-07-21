// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/signerapi"
)

// TestGuardedSignerCacheViewDelegation pins the engine→guarded cache-view
// wiring: each SignerCacheView method must surface the matching signer-cache
// field. A transposed or mistargeted delegation here would only fail at
// guarded submit time ("missing sentry_component_key_type metadata" or wrong
// dummy budgeting), so it is asserted directly.
func TestGuardedSignerCacheViewDelegation(t *testing.T) {
	addr := testAddress(1).String()
	sentryHex := testSentryPublicKeyHex(0xd6)

	signerCache := cache.NewSignerCache()
	signerCache.AddAddress(addr, keytypes.GuardedFalcon1024SentryFalcon1024V1)
	signerCache.SetSigningFlowForAddress(addr, signerapi.SigningFlowSentry1)
	signerCache.SetSentryComponentKeyTypeForAddress(addr, keytypes.SentryComponentFalcon1024V1)
	signerCache.SetSentryPublicKeyForAddress(addr, sentryHex)
	signerCache.SetLsigSize(addr, 1500)

	eng, err := NewEngine("testnet", WithSignerCache(signerCache))
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	view := guardedSignerCacheView{eng.Core}

	if got := view.SigningFlow(addr); got != signerapi.SigningFlowSentry1 {
		t.Fatalf("SigningFlow() = %q, want %q", got, signerapi.SigningFlowSentry1)
	}
	if got, ok := view.SentryComponentKeyType(addr); !ok || got != keytypes.SentryComponentFalcon1024V1 {
		t.Fatalf("SentryComponentKeyType() = %q/%v, want %s/true", got, ok, keytypes.SentryComponentFalcon1024V1)
	}
	if got, ok := view.SentryPublicKey(addr); !ok || got != sentryHex {
		t.Fatalf("SentryPublicKey() = %q/%v, want %s/true", got, ok, sentryHex)
	}
	if got := view.LsigSize(addr); got != 1500 {
		t.Fatalf("LsigSize() = %d, want 1500", got)
	}

	unknown := testAddress(9).String()
	if got := view.SigningFlow(unknown); got != "" {
		t.Fatalf("SigningFlow(unknown) = %q, want empty", got)
	}
	if _, ok := view.SentryComponentKeyType(unknown); ok {
		t.Fatal("SentryComponentKeyType(unknown) ok = true, want false")
	}
	if got := view.LsigSize(unknown); got != 0 {
		t.Fatalf("LsigSize(unknown) = %d, want 0", got)
	}
}
