// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerreg

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/racetest"
)

// The golden stage 0 address of lsig/rotatingtriplexmss/signerops for the
// fixed seed 0..63 on genesis 0xA0...
const goldenAddress = "PQ4C2LV5LRJQLAVLQMIJFH2KKS3YR4OVAEZN52WVSC7GELBAKJHN7CVNXA"

func fixedPayload(t *testing.T) (*keys.Payload, string) {
	t.Helper()
	racetest.SkipFullTree(t)
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
