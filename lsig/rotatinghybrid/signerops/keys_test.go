// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerops

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/lsig/rotatinghybrid/stage"
)

const (
	vectorsPath = "testdata/vectors.json"

	// captureVectorsEnv rewrites testdata/vectors.json from the current code.
	// Use it only to create the file or after a reviewed, intentional change
	// to the frozen derivation, which also requires a new key type.
	captureVectorsEnv = "ROTATING_HYBRID_CAPTURE_VECTORS"

	vectorMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon " +
		"abandon abandon abandon abandon abandon abandon abandon abandon " +
		"abandon abandon abandon abandon abandon abandon abandon art"

	// vectorGenesisHash is Algorand TestNet's genesis hash.
	vectorGenesisHash = "SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI="

	minVectorStages = 4
)

type vectorFile struct {
	Description string        `json:"description"`
	Mnemonic    string        `json:"mnemonic"`
	GenesisHash string        `json:"genesis_hash"`
	BIP39Seed   string        `json:"bip39_seed"`
	Stages      []stageVector `json:"stages"`
}

type stageVector struct {
	Index                 uint64 `json:"index"`
	FalconSeed            string `json:"falcon_seed"`
	Ed25519Seed           string `json:"ed25519_seed"`
	FalconPublicKeySHA256 string `json:"falcon_public_key_sha256"`
	Ed25519PublicKey      string `json:"ed25519_public_key"`
	Salted                bool   `json:"salted"`
	Salt                  int    `json:"salt"`
	Program               string `json:"program"`
	Address               string `json:"address"`
}

func vectorDeriver(t *testing.T) (*rotatinghybrid.Deriver, rotatinghybrid.Seed) {
	t.Helper()
	seed, err := rotatinghybrid.SeedFromMnemonic(strings.Fields(vectorMnemonic))
	if err != nil {
		t.Fatal(err)
	}
	genesisBytes, err := base64.StdEncoding.DecodeString(vectorGenesisHash)
	if err != nil {
		t.Fatal(err)
	}
	var genesis [rotatinghybrid.GenesisHashSize]byte
	copy(genesis[:], genesisBytes)
	d, err := rotatinghybrid.NewDeriver(&seed, genesis)
	if err != nil {
		t.Fatal(err)
	}
	return d, seed
}

func computeStageVector(t *testing.T, d *rotatinghybrid.Deriver, i uint64) stageVector {
	t.Helper()
	seeds, err := d.Stage(i)
	if err != nil {
		t.Fatal(err)
	}
	defer seeds.Zero()
	keys, program, err := DeriveStage(d, i)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Zero()
	pub := keys.PublicKeys()
	falconHash := sha256.Sum256(pub.Falcon[:])
	return stageVector{
		Index:                 i,
		FalconSeed:            hex.EncodeToString(seeds.Falcon[:]),
		Ed25519Seed:           hex.EncodeToString(seeds.Ed25519[:]),
		FalconPublicKeySHA256: hex.EncodeToString(falconHash[:]),
		Ed25519PublicKey:      hex.EncodeToString(pub.Ed25519[:]),
		Salted:                program.Salted,
		Salt:                  int(program.Salt),
		Program:               hex.EncodeToString(program.Bytecode),
		Address:               program.Address.String(),
	}
}

func computeVectors(t *testing.T) vectorFile {
	t.Helper()
	d, seed := vectorDeriver(t)
	defer d.Zero()
	defer seed.Zero()

	out := vectorFile{
		Description: "aplane.rotating-hybrid.v1 known-answer vectors: stages 0-3, extended until both salted and unsalted stages appear",
		Mnemonic:    vectorMnemonic,
		GenesisHash: vectorGenesisHash,
		BIP39Seed:   hex.EncodeToString(seed[:]),
	}
	seen := map[bool]bool{}
	for i := uint64(0); i < minVectorStages || !seen[true] || !seen[false]; i++ {
		v := computeStageVector(t, d, i)
		seen[v.Salted] = true
		out.Stages = append(out.Stages, v)
	}
	return out
}

// TestKnownAnswerVectors pins the derivation, Falcon key generation and
// program bytes. Falcon key generation must be bit-identical on every
// supported platform; a mismatch here on one platform breaks recovery.
func TestKnownAnswerVectors(t *testing.T) {
	got := computeVectors(t)

	if os.Getenv(captureVectorsEnv) != "" {
		data, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(vectorsPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vectorsPath, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Skipf("captured %d stages to %s", len(got.Stages), vectorsPath)
	}

	data, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read vectors: %v (capture with %s=1)", err, captureVectorsEnv)
	}
	var want vectorFile
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatal(err)
	}
	if got.BIP39Seed != want.BIP39Seed {
		t.Fatal("BIP-39 seed differs from vectors")
	}
	if len(got.Stages) != len(want.Stages) {
		t.Fatalf("got %d stages, vectors have %d", len(got.Stages), len(want.Stages))
	}
	for i := range want.Stages {
		if got.Stages[i] != want.Stages[i] {
			t.Errorf("stage %d differs from vectors:\n got  %+v\n want %+v", i, got.Stages[i], want.Stages[i])
		}
	}
}

func TestSignVerifyAgainstProgramKeys(t *testing.T) {
	d, seed := vectorDeriver(t)
	defer d.Zero()
	defer seed.Zero()

	keys, program, err := DeriveStage(d, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Zero()

	embedded, _, err := stage.Parse(program.Bytecode)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if embedded != keys.PublicKeys() {
		t.Fatal("program embeds keys other than the stage keys")
	}

	txID := sha256.Sum256([]byte("transaction id stand-in"))
	falconSig, edSig, err := keys.Sign(txID[:])
	if err != nil {
		t.Fatal(err)
	}
	if len(falconSig) > stage.FalconSignatureMaxSize || len(edSig) != stage.Ed25519SignatureSize {
		t.Fatalf("signature sizes %d/%d exceed the program's argument budget", len(falconSig), len(edSig))
	}
	if err := Verify(embedded, txID[:], falconSig, edSig); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	other := sha256.Sum256([]byte("another transaction"))
	if err := Verify(embedded, other[:], falconSig, edSig); err == nil {
		t.Fatal("Verify() accepted signatures over a different message")
	}
	badEd := bytes.Clone(edSig)
	badEd[0] ^= 0x01
	if err := Verify(embedded, txID[:], falconSig, badEd); err == nil {
		t.Fatal("Verify() accepted a corrupted Ed25519 signature")
	}
	badFalcon := bytes.Clone(falconSig)
	badFalcon[len(badFalcon)-1] ^= 0x01
	if err := Verify(embedded, txID[:], badFalcon, edSig); err == nil {
		t.Fatal("Verify() accepted a corrupted Falcon signature")
	}
}

func TestStageKeysDeterministicAndZeroed(t *testing.T) {
	d, seed := vectorDeriver(t)
	defer d.Zero()
	defer seed.Zero()

	first, p1, err := DeriveStage(d, 2)
	if err != nil {
		t.Fatal(err)
	}
	second, p2, err := DeriveStage(d, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Zero()
	if !bytes.Equal(p1.Bytecode, p2.Bytecode) || first.PublicKeys() != second.PublicKeys() {
		t.Fatal("stage derivation is not deterministic")
	}

	first.Zero()
	if !bytes.Equal(first.falcon.PrivateKey[:], make([]byte, len(first.falcon.PrivateKey))) ||
		!bytes.Equal(first.ed25519, make([]byte, len(first.ed25519))) {
		t.Fatal("Zero() left private key bytes behind")
	}
}
