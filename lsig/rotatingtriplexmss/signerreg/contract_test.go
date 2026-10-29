// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerreg

import (
	"fmt"
	"testing"

	"github.com/aplane-algo/aplane/internal/racetest"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/lsig/rotatingfamily/rotatingtest"
	"github.com/aplane-algo/aplane/lsig/rotatingtriplexmss/signerops"
	"github.com/aplane-algo/aplane/lsig/rotatingtriplexmss/stage"
)

// TestContract runs the rotating key type contract against the XMSS triple.
// Its stage ops are the package's one StageOps, whose tree cache key
// generation, validation and signing share. Tree 0's root is the one record
// field the codec compares only while the tree is cached, so the suite also
// checks that a cold cache stays cold through validation.
func TestContract(t *testing.T) {
	const tagEnd = signerops.AccountTagSize
	const falconEnd = tagEnd + stage.FalconPublicKeySize
	const rootEnd = falconEnd + stage.ConstantSize
	const seedEnd = rootEnd + stage.ConstantSize
	rotatingtest.Run(t, rotatingtest.Scheme{
		KeyType:       rotatingkey.RotatingTripleXmssV1,
		Family:        rotatingkey.RotatingTripleXmssFamily,
		Register:      Register,
		NewKeyPayload: NewKeyPayload,
		GoldenAddress: goldenAddress,
		StageOps:      StageOps(),
		TreeOps:       true,
		Leaf: func(i uint64) uint32 {
			_, lo, _ := stage.RangeFor(i)
			return uint32(lo) + 5
		},
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
		// The stage 0 record is account tag, Falcon-1024 key, tree 0's root
		// and public seed, Ed25519 key.
		RecordFields: map[string]int{
			"account tag":        0,
			"falcon public key":  tagEnd + 10,
			"root":               falconEnd,
			"public seed":        rootEnd,
			"ed25519 public key": seedEnd,
		},
		CachedFields: []string{"root"},
		Cold: func(t *testing.T, key *signing.RotatingKeyMaterial) {
			if err := StageOps().Forget(key); err != nil {
				t.Fatal(err)
			}
		},
		CacheSize: StageOps().CachedTrees,
		SkipSlow:  racetest.SkipFullTree,
	})
}
