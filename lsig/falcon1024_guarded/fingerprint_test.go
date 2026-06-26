// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package falcon1024guarded

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
)

// TestGuardedFingerprintShapeExcludesIdentity pins the behavior-only canonical
// spec: it must hash exactly base_primitive + salt + arg layout, with no
// identity/display fields. If an identity field (key_type/family/version) leaks
// back into the spec, the provider hash will diverge from this reconstruction.
func TestGuardedFingerprintShapeExcludesIdentity(t *testing.T) {
	type expectedSpec struct {
		BasePrimitive string `json:"base_primitive"`
		SaltStyle     string `json:"salt_style"`
		Arg0          string `json:"arg0"`
		Arg1          string `json:"arg1"`
	}

	cases := []struct {
		name     string
		provider *Provider
		arg1     string
	}{
		{name: "ed25519 sentry", provider: NewProviderV1(), arg1: "sentry_ed25519_component_signature"},
		{name: "falcon1024 sentry", provider: NewFalconSentryProviderV1(), arg1: "sentry_falcon1024_component_signature"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := lsigprovider.HashCompatibilitySpec(expectedSpec{
				BasePrimitive: "falcon1024-v1",
				SaltStyle:     string(lsigsalt.StylePushbytes),
				Arg0:          "user_falcon1024_component_signature",
				Arg1:          tc.arg1,
			})
			got := tc.provider.CompatibilityFingerprint()
			if got != want {
				t.Fatalf("CompatibilityFingerprint() = %q, want %q", got, want)
			}
			if !strings.HasPrefix(got, "1:") {
				t.Fatalf("CompatibilityFingerprint() = %q, want a \"1:\" prefix", got)
			}
		})
	}
}

// TestGuardedFingerprintSentryVariantSensitive proves the sentry component
// signature layout (arg1) is behavior-bearing: the two guarded variants must
// fingerprint differently.
func TestGuardedFingerprintSentryVariantSensitive(t *testing.T) {
	if NewProviderV1().CompatibilityFingerprint() == NewFalconSentryProviderV1().CompatibilityFingerprint() {
		t.Fatal("ed25519-sentry and falcon-sentry guarded providers share a fingerprint")
	}
}
