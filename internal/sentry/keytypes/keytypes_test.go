// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keytypes

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/witness"
)

func TestSentryKeyTypeClassifiers(t *testing.T) {
	if !IsGuardedAccountKeyType(GuardedFalcon1024Sentry1024V1) {
		t.Fatal("Falcon guarded account key type was not classified as guarded")
	}
	if IsGuardedAccountKeyType("aplane.corridor.v1") {
		t.Fatal("bounded Corridor template was classified as a legacy guarded account")
	}
	if !IsSentryKeyType(witness.Falcon1024V1) {
		t.Fatal("witness key type was not classified as sentry-owned")
	}
	if IsSentryKeyType("aplane.falcon1024.v1") {
		t.Fatal("ordinary Falcon key type classified as sentry key type")
	}
}

func TestSentryComponentKeyTypeForGuardedAccount(t *testing.T) {
	for _, keyType := range []string{GuardedFalcon1024Sentry1024V1} {
		got, ok := SentryComponentKeyTypeForGuardedAccount(keyType)
		if !ok || got != witness.Falcon1024V1 {
			t.Fatalf("SentryComponentKeyTypeForGuardedAccount(%q) = (%q, %v)", keyType, got, ok)
		}
	}
	if got, ok := SentryComponentKeyTypeForGuardedAccount("aplane.corridor.v1"); ok || got != "" {
		t.Fatalf("bounded Corridor template unexpectedly classified as guarded account: (%q, %v)", got, ok)
	}
	if got, ok := SentryComponentKeyTypeForGuardedAccount(witness.Falcon1024V1); ok || got != "" {
		t.Fatalf("witness key unexpectedly classified as guarded account: (%q, %v)", got, ok)
	}
}
