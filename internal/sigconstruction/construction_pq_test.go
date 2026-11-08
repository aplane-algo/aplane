// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sigconstruction

import "testing"

func TestPostQuantumFollowsThePrimitives(t *testing.T) {
	if !Falcon1024().PostQuantum() || Ed25519().PostQuantum() {
		t.Fatalf("Falcon-1024 PostQuantum = %v, Ed25519 = %v", Falcon1024().PostQuantum(), Ed25519().PostQuantum())
	}
	hybrid, err := New(Definition{ID: "test.falcon-ed25519", Components: []ComponentSpec{
		{Name: "falcon", Primitive: PrimitiveFalcon1024}, {Name: "ed25519", Primitive: PrimitiveEd25519},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !hybrid.PostQuantum() {
		t.Fatal("a construction with a post-quantum component is not post-quantum")
	}
}
