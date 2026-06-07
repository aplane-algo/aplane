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
	sentry := ComponentMessage(RoleSentry, txid)
	if user == sentry {
		t.Fatal("user and sentry component messages are identical")
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
		{name: "user", role: RoleUser, want: "e8ce9c0b8b69f3c13b1a0966e9e316c82fa267d0ed2ca084335a15eb305a542c"},
		{name: "sentry", role: RoleSentry, want: "05f256f9d6e07d0f8b6740c26c752714d8a4c7efb7bccc600499b64ceffa2bf6"},
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
