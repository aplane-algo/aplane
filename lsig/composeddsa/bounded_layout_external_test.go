// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa_test

import (
	"fmt"
	"testing"

	"github.com/aplane-algo/aplane/lsig/composeddsa"
	ed25519v1 "github.com/aplane-algo/aplane/lsig/ed25519lsig/v1"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	falconv1 "github.com/aplane-algo/aplane/lsig/falcon1024/v1"
)

type splitSignatureOps struct{}

func (splitSignatureOps) PublicKeySize() int       { return 32 }
func (splitSignatureOps) CryptoSignatureSize() int { return 64 }
func (splitSignatureOps) MnemonicScheme() string   { return "test" }
func (splitSignatureOps) MnemonicWordCount() int   { return 0 }
func (splitSignatureOps) DisplayColor() string     { return "" }
func (splitSignatureOps) BuildVerifyTEAL([]byte) (string, error) {
	return "txn TxID\narg 0\narg 1\n", nil
}
func (splitSignatureOps) TEALVersion() int { return 12 }
func (splitSignatureOps) BuildSignatureArgs(signature []byte) ([][]byte, error) {
	if len(signature) != 64 {
		return nil, fmt.Errorf("signature length %d, want 64", len(signature))
	}
	return [][]byte{signature[:32], signature[32:]}, nil
}
func (splitSignatureOps) SignatureArgLayout() composeddsa.SignatureArgLayout {
	return composeddsa.SignatureArgLayout{Count: 2, MaxSizes: []int{32, 32}}
}

func TestBoundedBaseSignatureLayoutsMatchPackedArguments(t *testing.T) {
	tests := []struct {
		name      string
		ops       composeddsa.BoundedCapableDSAOps
		signature []byte
	}{
		{name: "Falcon-1024", ops: falconv1.NewFalconOps(nil), signature: []byte{1}},
		{name: "Ed25519", ops: ed25519v1.NewOps(), signature: make([]byte, 64)},
		{name: "synthetic split signature", ops: splitSignatureOps{}, signature: make([]byte, 64)},
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
