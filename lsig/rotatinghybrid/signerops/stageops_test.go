// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerops

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/lsig/rotatinghybrid/stage"
)

func vectorMaterial(t *testing.T) (*signing.RotatingKeyMaterial, vectorFile) {
	t.Helper()
	data, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	d, seed := vectorDeriver(t)
	d.Zero()
	gh, err := base64.StdEncoding.DecodeString(v.GenesisHash)
	if err != nil {
		t.Fatal(err)
	}
	key := &signing.RotatingKeyMaterial{Seed: bytes.Clone(seed[:]), GenesisHash: gh}
	seed.Zero()
	t.Cleanup(key.Zero)
	return key, v
}

func TestStageOpsAddressesMatchVectors(t *testing.T) {
	key, v := vectorMaterial(t)
	for _, sv := range v.Stages {
		addr, err := StageOps{}.StageAddress(key, sv.Index)
		if err != nil {
			t.Fatal(err)
		}
		if addr.String() != sv.Address {
			t.Fatalf("stage %d address %s, want %s", sv.Index, addr, sv.Address)
		}
	}
}

func TestStageOpsSignAndOpenCheck(t *testing.T) {
	key, v := vectorMaterial(t)
	if err := (StageOps{}).CheckStageOpens(key, 3); err != nil {
		t.Fatal(err)
	}
	message := []byte("TX-id-stand-in-32-bytes-long-msg")
	sig, err := StageOps{}.SignStage(key, 2, message)
	if err != nil {
		t.Fatal(err)
	}
	program, _ := hex.DecodeString(v.Stages[2].Program)
	if !bytes.Equal(sig.Program, program) {
		t.Fatal("signed program is not stage 2's program")
	}
	if len(sig.Args) != 2 || len(sig.Args[0]) == 0 || len(sig.Args[0]) > stage.FalconSignatureMaxSize || len(sig.Args[1]) != stage.Ed25519SignatureSize {
		t.Fatalf("argument shape %d args", len(sig.Args))
	}
	keys, _, err := stage.Parse(sig.Program)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(keys, message, sig.Args[0], sig.Args[1]); err != nil {
		t.Fatal(err)
	}
}

func TestStageOpsRejectBadMaterial(t *testing.T) {
	for _, key := range []*signing.RotatingKeyMaterial{
		nil,
		{Seed: make([]byte, 32), GenesisHash: make([]byte, 32)},
		{Seed: make([]byte, 64), GenesisHash: make([]byte, 31)},
	} {
		if _, err := (StageOps{}).StageAddress(key, 0); err == nil {
			t.Fatal("bad key material accepted")
		}
	}
}
