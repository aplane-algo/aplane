// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerreg

import (
	"fmt"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto/wotsc"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/lsig/rotatingfamily/rotatingtest"
	"github.com/aplane-algo/aplane/lsig/rotatingtriplewotsc/signerops"
	"github.com/aplane-algo/aplane/lsig/rotatingtriplewotsc/stage"
)

// goldenAddress is the account of FixedSeed on FixedGenesis.
const goldenAddress = "DKPKHH5SWTPRHLTHD5VJMMKEQWNOJOVQQH3QOURLM6K46IFQWPH4Z67E44"

// TestContract runs the rotating key type contract against the WOTS+C triple.
func TestContract(t *testing.T) {
	rotatingtest.Run(t, rotatingtest.Scheme{
		KeyType:       rotatingkey.RotatingTripleWotscV1,
		Family:        rotatingkey.RotatingTripleWotscFamily,
		Register:      Register,
		NewKeyPayload: NewKeyPayload,
		GoldenAddress: goldenAddress,
		StageOps:      signerops.StageOps{},
		Leaf:          func(i uint64) uint32 { return uint32((i + 5) % wotsc.Leaves) },
		Verify: func(program, message []byte, args [][]byte) error {
			keys, _, err := stage.Parse(program)
			if err != nil {
				return err
			}
			if len(args) != 3 {
				return fmt.Errorf("%d arguments, want 3", len(args))
			}
			return signerops.Verify(keys, message, args[0], args[1], args[2])
		},
		// The stage 0 record is public seed, root, Falcon-1024 key, Ed25519 key.
		RecordFields: map[string]int{
			"public seed":        3,
			"root":               stage.HashSize + 3,
			"falcon public key":  2*stage.HashSize + 8,
			"ed25519 public key": packedSize - 1,
		},
	})
}
