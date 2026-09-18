// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package enrollment

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/aplane-algo/aplane/internal/endpointrefs"
	"github.com/aplane-algo/aplane/internal/witness"
)

func TestEnrollmentV1ContractFixtureIsCanonical(t *testing.T) {
	publicKey := bytes.Repeat([]byte{0x36}, witness.Falcon1024PublicKeySize)
	witnessKeyID, err := witness.ID(witness.Falcon1024V1, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := witness.NewPublicReference(
		witness.Falcon1024V1,
		witnessKeyID,
		fmt.Sprintf("%x", publicKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	want, err := Marshal(Envelope{
		Schema:  Schema,
		Witness: reference,
		Endpoint: &endpointrefs.Envelope{
			Schema:     endpointrefs.Schema,
			URL:        "ssh://sentry.example:2223",
			SignerPort: 11270,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	fixturePath := filepath.Join(filepath.Dir(sourceFile), "..", "..", "..", "test", "contracts", "sentry", "enrollment_v1.json")
	got, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture %s: %v\nFIXTURE_BEGIN\n%sFIXTURE_END", fixturePath, err, want)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("fixture %s is not the canonical aplane.sentry-enrollment.v1 encoding", fixturePath)
	}
	if _, err := Parse(got); err != nil {
		t.Fatalf("parse fixture %s: %v", fixturePath, err)
	}
}
