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
	attestor := ComponentMessage(RoleSentry, txid)
	if user == attestor {
		t.Fatal("user and attestor component messages are identical")
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
		{name: "user", role: RoleUser, want: "eeb719b688a256347512dfb24927716eed2946662df69cfe12f9b269d3afe3aa"},
		{name: "attestor", role: RoleSentry, want: "85b33fc0777d98012d0b2b6a23f3fd797ccf3674b3c01dcda139e564298ac7db"},
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
