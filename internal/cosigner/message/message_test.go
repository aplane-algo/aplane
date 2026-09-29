// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package message

import (
	"encoding/hex"
	"testing"
)

func TestComponentMessageSeparatesRoles(t *testing.T) {
	var txid [32]byte
	for i := range txid {
		txid[i] = byte(i)
	}

	user := ComponentMessage(RoleUser, txid)
	cosigner := ComponentMessage(RoleCosigner, txid)
	if user == cosigner {
		t.Fatal("user and cosigner component messages are identical")
	}
}

func TestComponentMessageBytesValidation(t *testing.T) {
	if _, err := ComponentMessageBytes(RoleUser, make([]byte, 31)); err == nil {
		t.Fatal("ComponentMessageBytes accepted short txid")
	}
	if _, err := ComponentMessageBytes(Role(99), make([]byte, 32)); err == nil {
		t.Fatal("ComponentMessageBytes accepted invalid role")
	}
}

func TestComponentMessageKnownVectors(t *testing.T) {
	txid := make([]byte, 32)
	for i := range txid {
		txid[i] = byte(i)
	}

	tests := []struct {
		name string
		role Role
		want string
	}{
		{name: "user", role: RoleUser, want: "4151748ba3b61e6df4a8f3ab3f240f47a80bd8b05bda039ffe331c2f29f1a291"},
		{name: "cosigner", role: RoleCosigner, want: "fb26b88a40894de1c59e3f64a8a10349f7eb32092630e39b2d610fe098b9ebce"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ComponentMessageBytes(tt.role, txid)
			if err != nil {
				t.Fatalf("ComponentMessageBytes() error = %v", err)
			}
			if hex.EncodeToString(got[:]) != tt.want {
				t.Fatalf("ComponentMessageBytes() = %s, want %s", hex.EncodeToString(got[:]), tt.want)
			}
		})
	}
}
