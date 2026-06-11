// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keytypes_test

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

// TestFalconSizesMatchFamily pins the literal Falcon-1024 sizes declared in
// keytypes (kept local so the vocabulary package has no algorithm-family
// imports) to the authoritative constants in lsig/falcon1024/family.
func TestFalconSizesMatchFamily(t *testing.T) {
	pub, ok := keytypes.ComponentPublicKeySize(keytypes.SentryComponentFalcon1024V1)
	if !ok || pub != falconfamily.PublicKeySize {
		t.Fatalf("ComponentPublicKeySize = %d, %v; want %d", pub, ok, falconfamily.PublicKeySize)
	}
	priv, ok := keytypes.ComponentPrivateKeySize(keytypes.SentryComponentFalcon1024V1)
	if !ok || priv != falconfamily.PrivateKeySize {
		t.Fatalf("ComponentPrivateKeySize = %d, %v; want %d", priv, ok, falconfamily.PrivateKeySize)
	}
}
