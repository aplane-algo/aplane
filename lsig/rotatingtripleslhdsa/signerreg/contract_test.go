// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerreg

import (
	"fmt"
	"testing"

	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/lsig/rotatingfamily/rotatingtest"
	"github.com/aplane-algo/aplane/lsig/rotatingtripleslhdsa/signerops"
	"github.com/aplane-algo/aplane/lsig/rotatingtripleslhdsa/stage"
)

// TestContract runs the rotating key type contract against the SLH-DSA
// triple, at the hypertree height the binary is built with.
func TestContract(t *testing.T) {
	rotatingtest.Run(t, rotatingtest.Scheme{
		KeyType:       rotatingkey.RotatingTripleSlhdsaV1,
		Family:        rotatingkey.RotatingTripleSlhdsaFamily,
		Register:      Register,
		NewKeyPayload: NewKeyPayload,
		// The golden stage 0 addresses of lsig/rotatingtripleslhdsa/signerops.
		GoldenAddress: map[int]string{
			22: "UVL3MPUS3YTDF3YSVHNWN3UIQJGJ4OID6AIAEBN3MJLYAQFDD5ENE3FYHY",
			63: "PGDSQUZ7TMOZ5DHTC64M4INDEF4I7QENPBZP7VB64YVEERMLGNE4IAYOVI",
		}[rotatingkey.RotatingSlhdsaHeight],
		StageOps: signerops.StageOps{},
		Verify: func(program, message []byte, args [][]byte) error {
			keys, _, err := stage.Parse(program)
			if err != nil {
				return err
			}
			chunks := len(stage.ChunkSizes)
			if len(args) != chunks+2 {
				return fmt.Errorf("%d arguments, want %d", len(args), chunks+2)
			}
			var slhSig []byte
			for i, n := range stage.ChunkSizes {
				if len(args[i]) != n {
					return fmt.Errorf("argument %d is %d bytes, want %d", i, len(args[i]), n)
				}
				slhSig = append(slhSig, args[i]...)
			}
			return signerops.Verify(keys, message, slhSig, args[chunks], args[chunks+1])
		},
		// The stage 0 record is SLH-DSA public seed, root, Falcon-1024 key,
		// Ed25519 key.
		RecordFields: map[string]int{
			"slh public seed":    3,
			"slh root":           stage.HashSize + 3,
			"falcon public key":  2*stage.HashSize + 8,
			"ed25519 public key": packedSize - 1,
		},
	})
}
