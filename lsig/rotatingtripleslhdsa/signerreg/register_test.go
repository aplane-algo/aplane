// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerreg

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/keys"
)

func fixedPayload(t *testing.T) (*keys.Payload, string) {
	t.Helper()
	Register()
	var seed rotatinghybrid.Seed
	for i := range seed {
		seed[i] = byte(i)
	}
	defer seed.Zero()
	var genesisHash [rotatinghybrid.GenesisHashSize]byte
	for i := range genesisHash {
		genesisHash[i] = byte(0xA0 + i)
	}
	payload, address, err := NewKeyPayload(&seed, genesisHash)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(payload.ZeroSecrets)
	return payload, address
}
