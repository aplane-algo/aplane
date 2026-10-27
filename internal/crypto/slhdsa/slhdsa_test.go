// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package slhdsa

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

type acvpVectors struct {
	Source string `json:"source"`
	KeyGen []struct {
		TcID   int    `json:"tcId"`
		SKSeed string `json:"skSeed"`
		SKPrf  string `json:"skPrf"`
		PKSeed string `json:"pkSeed"`
		SK     string `json:"sk"`
		PK     string `json:"pk"`
	} `json:"keyGen"`
	SigGen []struct {
		TcID          int    `json:"tcId"`
		Interface     string `json:"interface"`
		Deterministic bool   `json:"deterministic"`
		SK            string `json:"sk"`
		PK            string `json:"pk"`
		Message       string `json:"message"`
		Context       string `json:"context"`
		AddRand       string `json:"additionalRandomness"`
		Signature     string `json:"signature"`
	} `json:"sigGen"`
	SigVer []struct {
		TcID       int    `json:"tcId"`
		Interface  string `json:"interface"`
		TestPassed bool   `json:"testPassed"`
		Reason     string `json:"reason"`
		PK         string `json:"pk"`
		Message    string `json:"message"`
		Context    string `json:"context"`
		Signature  string `json:"signature"`
	} `json:"sigVer"`
}

// sets are the two parameter sets every generic test runs under.
var sets = []*Params{&SHA2128s, &Rescaled128}

func loadVectors(t testing.TB) *acvpVectors {
	t.Helper()
	data, err := os.ReadFile("testdata/acvp_sha2_128s.json")
	if err != nil {
		t.Fatal(err)
	}
	v := new(acvpVectors)
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatal(err)
	}
	return v
}

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func unhexN(t testing.TB, s string) *[N]byte {
	t.Helper()
	b := unhex(t, s)
	if len(b) != N {
		t.Fatalf("want %d bytes, got %d", N, len(b))
	}
	var out [N]byte
	copy(out[:], b)
	return &out
}

func fillRandom(t testing.TB, dst []byte) {
	t.Helper()
	if _, err := rand.Read(dst); err != nil {
		t.Fatal(err)
	}
}

func randomKey(t testing.TB, p *Params) *SigningKey {
	t.Helper()
	var skSeed, skPrf, pkSeed [N]byte
	fillRandom(t, skSeed[:])
	fillRandom(t, skPrf[:])
	fillRandom(t, pkSeed[:])
	return p.KeyGenFromSeeds(&skSeed, &skPrf, &pkSeed)
}

func TestSizes(t *testing.T) {
	if Len != 35 || Len1 != 32 || mdSize != 21 || ForsSignatureSize != 2912 {
		t.Fatalf("Len = %d, Len1 = %d, md = %d, FORS = %d", Len, Len1, mdSize, ForsSignatureSize)
	}
	for _, tc := range []struct {
		p                               *Params
		hPrime                          uint32
		m, idxTree, idxLeaf, xmss, size int
	}{
		{&SHA2128s, 9, 30, 7, 2, 704, 7856},
		{&Rescaled128, 11, 25, 2, 2, 736, 4400},
	} {
		t.Log(tc.p.String())
		p := tc.p
		if p.HPrime != tc.hPrime || p.M != tc.m || p.idxTreeSize != tc.idxTree || p.idxLeafSize != tc.idxLeaf {
			t.Fatalf("%s: digest split = %d/%d/%d (m=%d) h'=%d", p.Name, mdSize, p.idxTreeSize, p.idxLeafSize, p.M, p.HPrime)
		}
		if p.XmssSignatureSize != tc.xmss || p.HtSignatureSize != int(p.D)*tc.xmss || p.SignatureSize != tc.size {
			t.Fatalf("%s: sizes %d/%d/%d", p.Name, p.XmssSignatureSize, p.HtSignatureSize, p.SignatureSize)
		}
	}
}

func TestNewParamsRejectsBadShapes(t *testing.T) {
	for _, tc := range []struct{ h, d uint32 }{{0, 1}, {20, 0}, {21, 2}, {64, 2}, {66, 2}, {128, 2}, {255, 5}} {
		if _, err := NewParams("bad", tc.h, tc.d); !errors.Is(err, ErrParams) {
			t.Errorf("h=%d d=%d: err = %v, want ErrParams", tc.h, tc.d, err)
		}
	}
	if p, err := NewParams(SHA2128s.Name, 63, 7); err != nil || p != SHA2128s {
		t.Fatalf("standard shape: %+v, %v", p, err)
	}
}

func TestACVPKeyGen(t *testing.T) {
	v := loadVectors(t)
	for _, tc := range v.KeyGen {
		sk := SHA2128s.KeyGenFromSeeds(unhexN(t, tc.SKSeed), unhexN(t, tc.SKPrf), unhexN(t, tc.PKSeed))
		if got, want := sk.Bytes(), unhex(t, tc.SK); !bytes.Equal(got, want) {
			t.Errorf("tc %d: sk mismatch", tc.TcID)
		}
		if got, want := sk.Public.Bytes(), unhex(t, tc.PK); !bytes.Equal(got, want) {
			t.Errorf("tc %d: pk mismatch", tc.TcID)
		}
		sk.Zero()
	}
}

func TestACVPSigGen(t *testing.T) {
	v := loadVectors(t)
	p := &SHA2128s
	for _, tc := range v.SigGen {
		sk, err := ParseSigningKey(unhex(t, tc.SK))
		if err != nil {
			t.Fatal(err)
		}
		msg := unhex(t, tc.Message)
		want := unhex(t, tc.Signature)
		var optRand *[N]byte
		if !tc.Deterministic {
			optRand = unhexN(t, tc.AddRand)
		}
		var got []byte
		switch tc.Interface {
		case "internal":
			if optRand == nil {
				optRand = &sk.Public.Seed
			}
			got = p.SignInternal(sk, msg, optRand)
		case "external":
			got, err = p.Sign(sk, msg, unhex(t, tc.Context), optRand)
			if err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatalf("unknown interface %q", tc.Interface)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("tc %d (%s, det=%v): signature mismatch", tc.TcID, tc.Interface, tc.Deterministic)
		}
		pk, _ := ParsePublicKey(unhex(t, tc.PK))
		if tc.Interface == "internal" {
			err = p.VerifyInternal(pk, msg, got)
		} else {
			err = p.Verify(pk, msg, got, unhex(t, tc.Context))
		}
		if err != nil {
			t.Errorf("tc %d: own signature does not verify: %v", tc.TcID, err)
		}
	}
}

func TestACVPSigVer(t *testing.T) {
	v := loadVectors(t)
	p := &SHA2128s
	for _, tc := range v.SigVer {
		pk, err := ParsePublicKey(unhex(t, tc.PK))
		if err != nil {
			t.Fatal(err)
		}
		msg, sig := unhex(t, tc.Message), unhex(t, tc.Signature)
		if tc.Interface == "internal" {
			err = p.VerifyInternal(pk, msg, sig)
		} else {
			err = p.Verify(pk, msg, sig, unhex(t, tc.Context))
		}
		if (err == nil) != tc.TestPassed {
			t.Errorf("tc %d (%s): got err=%v, want pass=%v", tc.TcID, tc.Reason, err, tc.TestPassed)
		}
	}
}

// TestRescaledGoldenVectors pins the rescaled set's behavior on fixed
// seeds: the root and a deterministic signature. Any change here changes
// every rotating SLH-DSA stage identity.
func TestRescaledGoldenVectors(t *testing.T) {
	var skSeed, skPrf, pkSeed [N]byte
	for i := range N {
		skSeed[i], skPrf[i], pkSeed[i] = byte(i), byte(0x10+i), byte(0x20+i)
	}
	sk := Rescaled128.KeyGenFromSeeds(&skSeed, &skPrf, &pkSeed)
	msg := []byte("rescaled slh-dsa golden message")
	sig, err := Rescaled128.Sign(sk, msg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Rescaled128.Verify(&sk.Public, msg, sig, nil); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(sig)
	got := map[string]string{
		"root":       hex.EncodeToString(sk.Public.Root[:]),
		"r":          hex.EncodeToString(sig[:N]),
		"sig_sha256": hex.EncodeToString(sum[:]),
	}
	want := map[string]string{
		"root":       "317939f1c00b159d4279590b1085c20f",
		"r":          "50b8fa4334373d1c4e1d7ca8b4889e83",
		"sig_sha256": "93bfdf379381be25884dda3f31b91796b51dc411376a4c85410f4b5e5c087422",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %s, want %s", k, got[k], v)
		}
	}
	// The standard set on the same seeds has a different root: the tree
	// shape is part of the key.
	std := SHA2128s.KeyGenFromSeeds(&skSeed, &skPrf, &pkSeed)
	if std.Public.Root == sk.Public.Root {
		t.Fatal("rescaled root equals the standard root")
	}
	if Rescaled128.VerifyInternal(&std.Public, msg, sig) == nil {
		t.Fatal("rescaled signature verified under the standard key")
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	for _, p := range sets {
		t.Run(p.Name, func(t *testing.T) {
			sk := randomKey(t, p)
			msg := make([]byte, 32)
			fillRandom(t, msg)
			sig := p.SignInternal(sk, msg, &sk.Public.Seed)
			if err := p.VerifyInternal(&sk.Public, msg, sig); err != nil {
				t.Fatal(err)
			}
			// Flip one bit in every region of the signature.
			for _, off := range []int{0, N, N + ForsSignatureSize - 1, N + ForsSignatureSize, N + ForsSignatureSize + p.XmssSignatureSize, p.SignatureSize - 1} {
				bad := bytes.Clone(sig)
				bad[off] ^= 0x01
				if err := p.VerifyInternal(&sk.Public, msg, bad); !errors.Is(err, ErrVerify) {
					t.Errorf("flip at %d: err = %v, want ErrVerify", off, err)
				}
			}
			if err := p.VerifyInternal(&sk.Public, msg, sig[:len(sig)-1]); !errors.Is(err, ErrSignatureSize) {
				t.Errorf("short: err = %v", err)
			}
			if err := p.VerifyInternal(&sk.Public, append(bytes.Clone(msg), 0), sig); !errors.Is(err, ErrVerify) {
				t.Errorf("message: err = %v", err)
			}
			badPK := sk.Public
			badPK.Root[0] ^= 1
			if err := p.VerifyInternal(&badPK, msg, sig); !errors.Is(err, ErrVerify) {
				t.Errorf("root: err = %v", err)
			}
			// A signature of one shape is the wrong size for the other.
			other := &Rescaled128
			if p == other {
				other = &SHA2128s
			}
			if err := other.VerifyInternal(&sk.Public, msg, sig); !errors.Is(err, ErrSignatureSize) {
				t.Errorf("other set: err = %v", err)
			}
		})
	}
}

func TestContextTooLong(t *testing.T) {
	sk := randomKey(t, &Rescaled128)
	if _, err := Rescaled128.Sign(sk, []byte("m"), make([]byte, 256), nil); !errors.Is(err, ErrContextSize) {
		t.Fatalf("err = %v", err)
	}
}

// TestVerifyStatsProfile pins the hash profile of verification, which the
// TEAL cost model is built from. The chain count varies with the message;
// the rest is fixed by the parameter set.
func TestVerifyStatsProfile(t *testing.T) {
	check := func(t *testing.T, p *Params, name string, st Stats) {
		t.Helper()
		if st.HMsg != 2 || st.PRF != 0 || st.TLen != 1+int(p.D) || st.H != K*A+int(p.D*p.HPrime) {
			t.Errorf("%s: fixed profile %+v", name, st)
		}
		if st.F != K+st.Chain {
			t.Errorf("%s: F=%d, chain=%d, K=%d", name, st.F, st.Chain, K)
		}
		if st.Chain > int(p.D)*Len*(W-1) {
			t.Errorf("%s: chain %d exceeds bound", name, st.Chain)
		}
		t.Logf("%s: hashes=%d chain=%d (%+v)", name, st.Hashes(), st.Chain, st)
	}
	v := loadVectors(t)
	for _, tc := range v.SigGen {
		if tc.Interface != "internal" {
			continue
		}
		pk, _ := ParsePublicKey(unhex(t, tc.PK))
		st, err := SHA2128s.VerifyStats(pk, unhex(t, tc.Message), unhex(t, tc.Signature))
		if err != nil {
			t.Fatal(err)
		}
		check(t, &SHA2128s, "acvp tc "+hex.EncodeToString([]byte{byte(tc.TcID)}), st)
	}
	sk := randomKey(t, &Rescaled128)
	for i := range 4 {
		msg := make([]byte, 32)
		fillRandom(t, msg)
		sig := Rescaled128.SignInternal(sk, msg, &sk.Public.Seed)
		st, err := Rescaled128.VerifyStats(&sk.Public, msg, sig)
		if err != nil {
			t.Fatal(err)
		}
		check(t, &Rescaled128, "rescaled random "+string(rune('0'+i)), st)
	}
}

func TestRandomRoundTrip(t *testing.T) {
	for _, p := range sets {
		t.Run(p.Name, func(t *testing.T) {
			sk := randomKey(t, p)
			msg := []byte("rotating stage transaction id")
			sig, err := p.Sign(sk, msg, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(sig) != p.SignatureSize {
				t.Fatalf("signature is %d bytes, want %d", len(sig), p.SignatureSize)
			}
			if err := p.Verify(&sk.Public, msg, sig, nil); err != nil {
				t.Fatal(err)
			}
			sig2, _ := p.Sign(sk, msg, nil, nil)
			if !bytes.Equal(sig, sig2) {
				t.Fatal("deterministic signing differs")
			}
			var r [N]byte
			fillRandom(t, r[:])
			sig3, _ := p.Sign(sk, msg, nil, &r)
			if bytes.Equal(sig, sig3) {
				t.Fatal("randomized signing equals deterministic")
			}
			if err := p.Verify(&sk.Public, msg, sig3, nil); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestRescaledLeafIndices checks that the digest split of the rescaled set
// spreads signatures over the whole 2^22-leaf hypertree: both the tree and
// the leaf index take every bit of their fields over many messages.
func TestRescaledLeafIndices(t *testing.T) {
	p := &Rescaled128
	sk := randomKey(t, p)
	var treeBits uint64
	var leafBits uint32
	for range 256 {
		msg := make([]byte, 32)
		fillRandom(t, msg)
		var r [N]byte
		fillRandom(t, r[:])
		_, idxTree, idxLeaf := p.splitDigest(hashMsg(p, &r, &sk.Public, msg, nil))
		if idxTree >= 1<<(p.H-p.HPrime) || idxLeaf >= 1<<p.HPrime {
			t.Fatalf("index out of range: tree %d leaf %d", idxTree, idxLeaf)
		}
		treeBits |= idxTree
		leafBits |= idxLeaf
	}
	if treeBits != 1<<(p.H-p.HPrime)-1 || leafBits != 1<<p.HPrime-1 {
		t.Fatalf("index bits seen: tree %b leaf %b", treeBits, leafBits)
	}
}

func BenchmarkKeyGen(b *testing.B) {
	for _, p := range sets {
		b.Run(p.Name, func(b *testing.B) {
			var skSeed, skPrf, pkSeed [N]byte
			fillRandom(b, skSeed[:])
			fillRandom(b, skPrf[:])
			fillRandom(b, pkSeed[:])
			b.ReportAllocs()
			for b.Loop() {
				p.KeyGenFromSeeds(&skSeed, &skPrf, &pkSeed)
			}
		})
	}
}

func BenchmarkSign(b *testing.B) {
	for _, p := range sets {
		b.Run(p.Name, func(b *testing.B) {
			sk := randomKey(b, p)
			msg := make([]byte, 32)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				fillRandom(b, msg)
				p.SignInternal(sk, msg, &sk.Public.Seed)
			}
		})
	}
}

func BenchmarkVerify(b *testing.B) {
	for _, p := range sets {
		b.Run(p.Name, func(b *testing.B) {
			sk := randomKey(b, p)
			msg := make([]byte, 32)
			fillRandom(b, msg)
			sig := p.SignInternal(sk, msg, &sk.Public.Seed)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if err := p.VerifyInternal(&sk.Public, msg, sig); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
