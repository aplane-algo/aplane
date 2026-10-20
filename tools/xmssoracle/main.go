// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Command xmssoracle regenerates internal/crypto/xmss/testdata/vectors.json
// from an independent RFC 8391 implementation (github.com/bwesterb/go-xmssmt,
// itself checked against the XMSS reference implementation's test vectors).
// It is a separate module so the oracle never becomes a dependency of the
// product.
//
//	cd tools/xmssoracle && go run . ../../internal/crypto/xmss/testdata/vectors.json
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	xmssmt "github.com/bwesterb/go-xmssmt"
)

const paramSet = "XMSS-SHA2_16_256"

type vectorCase struct {
	Index     uint32 `json:"index"`
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

type vectorFile struct {
	ParamSet string       `json:"param_set"`
	Oracle   string       `json:"oracle"`
	SKSeed   string       `json:"sk_seed"`
	SKPRF    string       `json:"sk_prf"`
	PubSeed  string       `json:"pub_seed"`
	Root     string       `json:"root"`
	Cases    []vectorCase `json:"cases"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: xmssoracle <out.json>")
		os.Exit(2)
	}
	// The seeds the reference implementation's test vectors use: bytes
	// 0..95, split sk_seed | sk_prf | pub_seed.
	seed := make([]byte, 96)
	for i := range seed {
		seed[i] = byte(i)
	}
	skSeed, skPrf, pubSeed := seed[:32], seed[32:64], seed[64:]

	dir, err := os.MkdirTemp("", "xmssoracle")
	if err != nil {
		fail(err)
	}
	defer os.RemoveAll(dir)

	ctx := xmssmt.NewContextFromName(paramSet)
	if ctx == nil {
		fail(fmt.Errorf("unknown parameter set %s", paramSet))
	}
	sk, pk, derr := ctx.Derive(filepath.Join(dir, "key"), pubSeed, skSeed, skPrf)
	if derr != nil {
		fail(derr)
	}
	defer sk.Close()
	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		fail(err)
	}
	out := vectorFile{
		ParamSet: paramSet,
		Oracle:   "github.com/bwesterb/go-xmssmt v1.6.1",
		SKSeed:   hex.EncodeToString(skSeed),
		SKPRF:    hex.EncodeToString(skPrf),
		PubSeed:  hex.EncodeToString(pubSeed),
		Root:     hex.EncodeToString(pkBytes[4:36]),
	}
	if hex.EncodeToString(pkBytes[36:68]) != out.PubSeed {
		fail(fmt.Errorf("oracle public seed mismatch"))
	}

	// Indices: the first two leaves, a stage-range boundary pair (63, 64),
	// the end of the second range (127), the reference vector's index
	// (2^(h-1)) and the highest leaf the oracle signs. Messages are 32 bytes, like a TxID,
	// except the reference vector's one-byte message.
	type want struct {
		index uint32
		msg   []byte
	}
	// The oracle's key container only hands out ascending indices, so the
	// cases are listed in ascending order.
	wants := []want{}
	for _, idx := range []uint32{0, 1, 63, 64, 127} {
		m := sha256.Sum256([]byte(fmt.Sprintf("aplane xmss vector %d", idx)))
		wants = append(wants, want{idx, m[:]})
	}
	wants = append(wants, want{1 << 15, []byte{37}})
	// go-xmssmt treats the last leaf as unusable (MaxSignatureSeqNo), so
	// the highest oracle case is 65534; the product's own tests cover 65535.
	last := sha256.Sum256([]byte("aplane xmss vector 65534"))
	wants = append(wants, want{65534, last[:]})
	for _, w := range wants {
		sk.DangerousSetSeqNo(xmssmt.SignatureSeqNo(w.index))
		sig, serr := sk.Sign(w.msg)
		if serr != nil {
			fail(serr)
		}
		sigBytes, err := sig.MarshalBinary()
		if err != nil {
			fail(err)
		}
		ok, verr := pk.Verify(sig, w.msg)
		if verr != nil || !ok {
			fail(fmt.Errorf("oracle rejected its own signature at %d: %v", w.index, verr))
		}
		out.Cases = append(out.Cases, vectorCase{
			Index:     w.index,
			Message:   hex.EncodeToString(w.msg),
			Signature: hex.EncodeToString(sigBytes[4:]), // strip the OID
		})
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		fail(err)
	}
	if err := os.WriteFile(os.Args[1], append(data, '\n'), 0o644); err != nil {
		fail(err)
	}
	fmt.Printf("wrote %s: %d cases\n", os.Args[1], len(out.Cases))
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "xmssoracle:", err)
	os.Exit(1)
}
