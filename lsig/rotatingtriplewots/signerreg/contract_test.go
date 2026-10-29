// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerreg

import (
	"fmt"
	"testing"

	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/lsig/rotatingfamily/rotatingtest"
	"github.com/aplane-algo/aplane/lsig/rotatingtriplewots/signerops"
	"github.com/aplane-algo/aplane/lsig/rotatingtriplewots/stage"
)

// TestContract runs the rotating key type contract against the WOTS triple.
func TestContract(t *testing.T) {
	rotatingtest.Run(t, rotatingtest.Scheme{
		KeyType:       rotatingkey.RotatingTripleWotsV1,
		Family:        rotatingkey.RotatingTripleWotsFamily,
		Register:      Register,
		NewKeyPayload: NewKeyPayload,
		// The golden stage 0 address of lsig/rotatingtriplewots/signerops.
		GoldenAddress: "YX62PQ4VBCVBAA5577SHXSYDYCC6DMYOUTUVPVN4QTSIZQ6KVPFVCC64XA",
		StageOps:      signerops.StageOps{},
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
		// The stage 0 record is tweak, Falcon-1024 key, WOTS key, Ed25519 key.
		RecordFields: map[string]int{
			"tweak":              3,
			"falcon public key":  stage.ConstantSize + 8,
			"wots public key":    stage.ConstantSize + stage.FalconPublicKeySize + 3,
			"ed25519 public key": packedSize - 1,
		},
	})
}
