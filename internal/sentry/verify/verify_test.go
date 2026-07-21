// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package verify

import (
	"testing"

	"github.com/algorandfoundation/falcon-signatures/falcongo"
)

func TestVerifyFalcon1024(t *testing.T) {
	seed := make([]byte, 48)
	for i := range seed {
		seed[i] = byte(i)
	}
	kp, err := falcongo.GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	msg := []byte("message")
	sig, err := kp.Sign(msg)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if err := VerifyFalcon1024(kp.PublicKey[:], msg, sig); err != nil {
		t.Fatalf("VerifyFalcon1024() error = %v", err)
	}
	tampered := append([]byte(nil), sig...)
	tampered[0] ^= 0xff
	if err := VerifyFalcon1024(kp.PublicKey[:], msg, tampered); err == nil {
		t.Fatal("VerifyFalcon1024() accepted tampered signature")
	}
}
