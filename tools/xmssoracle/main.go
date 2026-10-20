// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Command xmssoracle regenerates internal/crypto/xmss/testdata/vectors.json
// from an independent RFC 8391 implementation (github.com/bwesterb/go-xmssmt,
// itself checked against the XMSS reference implementation's test vectors).
// It is a separate module so the oracle never becomes a dependency of the
// product; it imports the product's xmss package (replace directive) only
// to run the checksum-bounded signer and have the oracle verify its
// output, so the file also records that every bounded signature, searched
// randomizer or not, is an RFC 8391 signature to an independent verifier.
//
//	cd tools/xmssoracle && go run . ../../internal/crypto/xmss/testdata/vectors.json
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aplane-algo/aplane/internal/crypto/xmss"

	xmssmt "github.com/bwesterb/go-xmssmt"
)

const paramSet = "XMSS-SHA2_16_256"

type vectorCase struct {
	Index     uint32 `json:"index"`
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

// boundedCase is a signature the product's checksum-bounded signer
// (xmss.SignBounded) produced and the oracle verified as an ordinary RFC
// 8391 signature. Searched reports that the RFC randomizer did not meet the
// cap and a later counter was used, so the signature differs from Sign's.
type boundedCase struct {
	Index     uint32 `json:"index"`
	Message   string `json:"message"`
	Signature string `json:"signature"`
	Searched  bool   `json:"searched"`
}

type vectorFile struct {
	ParamSet string       `json:"param_set"`
	Oracle   string       `json:"oracle"`
	SKSeed   string       `json:"sk_seed"`
	SKPRF    string       `json:"sk_prf"`
	PubSeed  string       `json:"pub_seed"`
	Root     string       `json:"root"`
	Cases    []vectorCase `json:"cases"`
	// BoundedCases were produced by the product's bounded signer and every
	// one verified under the oracle: the bounded signer emits nothing
	// outside RFC 8391.
	BoundedCases []boundedCase `json:"bounded_cases"`
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
	// The oracle's own parameter encoding, which precedes its signatures
	// in place of the RFC OID; reused to hand it the product's signatures.
	var paramPrefix []byte
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
		paramPrefix = append(paramPrefix[:0], sigBytes[:4]...)
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
	// The product's bounded signer: every signature it emits must verify
	// under the oracle, including those that needed a randomizer search.
	var seeds xmss.Seeds
	copy(seeds.SKSeed[:], skSeed)
	copy(seeds.SKPRF[:], skPrf)
	copy(seeds.PubSeed[:], pubSeed)
	tree := xmss.GenerateTree(&seeds)
	if root := tree.Root(); hex.EncodeToString(root[:]) != out.Root {
		fail(fmt.Errorf("product tree root differs from the oracle's"))
	}
	oid := append([]byte(nil), paramPrefix...)
	searched := 0
	for i := range uint32(32) {
		index := i*2048 + 5 // spread over the tree, inside stage ranges
		m := sha256.Sum256([]byte(fmt.Sprintf("aplane xmss bounded %d", index)))
		bounded, err := xmss.SignBounded(&seeds, tree, index, m[:], xmss.MaxBoundedChecksum)
		if err != nil {
			fail(err)
		}
		plain, err := xmss.Sign(&seeds, tree, index, m[:])
		if err != nil {
			fail(err)
		}
		var parsed xmssmt.Signature
		if err := parsed.UnmarshalBinary(append(append([]byte(nil), oid...), bounded...)); err != nil {
			fail(fmt.Errorf("oracle could not parse bounded signature at %d: %v", index, err))
		}
		ok, verr := pk.Verify(&parsed, m[:])
		if verr != nil || !ok {
			fail(fmt.Errorf("oracle rejected the bounded signature at %d: %v", index, verr))
		}
		c := boundedCase{Index: index, Message: hex.EncodeToString(m[:]), Signature: hex.EncodeToString(bounded), Searched: !bytes.Equal(bounded, plain)}
		if c.Searched {
			searched++
		}
		out.BoundedCases = append(out.BoundedCases, c)
	}
	if searched == 0 {
		fail(fmt.Errorf("no bounded case needed a randomizer search; add cases"))
	}
	fmt.Printf("bounded: %d signatures verified by the oracle, %d of them searched\n", len(out.BoundedCases), searched)

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
