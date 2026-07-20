// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa_test

import (
	"encoding/binary"
	"testing"

	"github.com/aplane-algo/aplane/lsig/composeddsa"
	ecdsav1 "github.com/aplane-algo/aplane/lsig/ecdsak1/v1"
	ed25519v1 "github.com/aplane-algo/aplane/lsig/ed25519lsig/v1"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	falconv1 "github.com/aplane-algo/aplane/lsig/falcon1024/v1"
	falconhybrid "github.com/aplane-algo/aplane/lsig/falcon1024_ed25519"
)

func TestBoundedBaseSignatureLayoutsMatchPackedArguments(t *testing.T) {
	hybridSignature := make([]byte, 2+1+64)
	binary.BigEndian.PutUint16(hybridSignature[:2], 1)
	hybridSignature[2] = 1

	tests := []struct {
		name      string
		ops       composeddsa.BoundedCapableDSAOps
		signature []byte
	}{
		{name: "Falcon-1024", ops: falconv1.NewFalconOps(nil), signature: []byte{1}},
		{name: "Ed25519", ops: ed25519v1.NewOps(), signature: make([]byte, 64)},
		{name: "ECDSA secp256k1", ops: ecdsav1.NewECDSAK1Ops(nil), signature: make([]byte, 64)},
		{name: "Falcon-1024 plus Ed25519", ops: falconhybrid.NewOps(), signature: hybridSignature},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args, err := tt.ops.BuildSignatureArgs(tt.signature)
			if err != nil {
				t.Fatalf("BuildSignatureArgs() error = %v", err)
			}
			layout := tt.ops.SignatureArgLayout()
			if len(args) != layout.Count || len(layout.MaxSizes) != layout.Count {
				t.Fatalf("args/layout = %d/%+v", len(args), layout)
			}
			for i, arg := range args {
				if len(arg) == 0 || len(arg) > layout.MaxSizes[i] {
					t.Fatalf("arg %d length %d exceeds layout %+v", i, len(arg), layout)
				}
			}
		})
	}
	if got := falconv1.NewFalconOps(nil).SignatureArgLayout().MaxSizes[0]; got != family.MaxSignatureSize {
		t.Fatalf("Falcon max arg size = %d, want %d", got, family.MaxSignatureSize)
	}
}
