// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"errors"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/rotatingkey"
)

// TestRotatingPayloadRequiresRegisteredCodec pins the fail-closed default:
// a binary that does not register the rotating family can neither write nor
// read its key files. lsig/rotatinghybrid/signerreg covers the registered
// path.
func TestRotatingPayloadRequiresRegisteredCodec(t *testing.T) {
	payload := NewRotatingLSigPayload(
		rotatingkey.RotatingHybridV1,
		make([]byte, rotatingkey.RotatingSeedSize),
		make([]byte, rotatingkey.RotatingGenesisHashSize),
		make([]byte, rotatingkey.RotatingStagePublicKeySize),
	)
	defer payload.ZeroSecrets()
	_, err := MarshalPayload(payload)
	if !errors.Is(err, ErrIncompatibleKeyFormat) || !strings.Contains(err.Error(), "not registered") {
		t.Fatalf("MarshalPayload error = %v, want unregistered rotating key type", err)
	}
	if _, err := payload.Selector(); err == nil {
		t.Fatal("Selector derived an address without a registered codec")
	}
}

func TestRotatingPayloadIsAccountCredential(t *testing.T) {
	class, err := ManagedCredentialClassForCategory(CategoryRotatingLsig)
	if err != nil || class != ManagedCredentialAccount {
		t.Fatalf("class = %q, err = %v", class, err)
	}
}
