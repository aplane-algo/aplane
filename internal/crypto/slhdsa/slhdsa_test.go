// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package slhdsa

import (
	"bytes"
	"crypto/rand"
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

func TestSizes(t *testing.T) {
	t.Log(String())
	if SignatureSize != 7856 {
		t.Fatalf("SignatureSize = %d, want 7856", SignatureSize)
	}
	if M != 30 || mdSize != 21 || idxTreeSize != 7 || idxLeafSize != 2 {
		t.Fatalf("digest split = %d/%d/%d (m=%d)", mdSize, idxTreeSize, idxLeafSize, M)
	}
	if Len != 35 || Len1 != 32 {
		t.Fatalf("Len = %d, Len1 = %d", Len, Len1)
	}
}

func TestACVPKeyGen(t *testing.T) {
	v := loadVectors(t)
	for _, tc := range v.KeyGen {
		sk := KeyGenFromSeeds(unhexN(t, tc.SKSeed), unhexN(t, tc.SKPrf), unhexN(t, tc.PKSeed))
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
			got = SignInternal(sk, msg, optRand)
		case "external":
			got, err = Sign(sk, msg, unhex(t, tc.Context), optRand)
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
			err = VerifyInternal(pk, msg, got)
		} else {
			err = Verify(pk, msg, got, unhex(t, tc.Context))
		}
		if err != nil {
			t.Errorf("tc %d: own signature does not verify: %v", tc.TcID, err)
		}
	}
}

func TestACVPSigVer(t *testing.T) {
	v := loadVectors(t)
	for _, tc := range v.SigVer {
		pk, err := ParsePublicKey(unhex(t, tc.PK))
		if err != nil {
			t.Fatal(err)
		}
		msg, sig := unhex(t, tc.Message), unhex(t, tc.Signature)
		if tc.Interface == "internal" {
			err = VerifyInternal(pk, msg, sig)
		} else {
			err = Verify(pk, msg, sig, unhex(t, tc.Context))
		}
		if (err == nil) != tc.TestPassed {
			t.Errorf("tc %d (%s): got err=%v, want pass=%v", tc.TcID, tc.Reason, err, tc.TestPassed)
		}
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	v := loadVectors(t)
	tc := v.SigGen[0]
	for _, c := range v.SigGen {
		if c.Interface == "internal" {
			tc = c
			break
		}
	}
	pk, _ := ParsePublicKey(unhex(t, tc.PK))
	msg, sig := unhex(t, tc.Message), unhex(t, tc.Signature)
	if err := VerifyInternal(pk, msg, sig); err != nil {
		t.Fatal(err)
	}
	// Flip one bit in every region of the signature.
	for _, off := range []int{0, N, N + ForsSignatureSize - 1, N + ForsSignatureSize, SignatureSize - 1} {
		bad := bytes.Clone(sig)
		bad[off] ^= 0x01
		if err := VerifyInternal(pk, msg, bad); !errors.Is(err, ErrVerify) {
			t.Errorf("flip at %d: err = %v, want ErrVerify", off, err)
		}
	}
	if err := VerifyInternal(pk, msg, sig[:len(sig)-1]); !errors.Is(err, ErrSignatureSize) {
		t.Errorf("short: err = %v", err)
	}
	if err := VerifyInternal(pk, append(bytes.Clone(msg), 0), sig); !errors.Is(err, ErrVerify) {
		t.Errorf("message: err = %v", err)
	}
	badPK := *pk
	badPK.Root[0] ^= 1
	if err := VerifyInternal(&badPK, msg, sig); !errors.Is(err, ErrVerify) {
		t.Errorf("root: err = %v", err)
	}
}

func TestContextTooLong(t *testing.T) {
	v := loadVectors(t)
	sk, _ := ParseSigningKey(unhex(t, v.SigGen[0].SK))
	if _, err := Sign(sk, []byte("m"), make([]byte, 256), nil); !errors.Is(err, ErrContextSize) {
		t.Fatalf("err = %v", err)
	}
}

// TestVerifyStatsProfile pins the hash profile of verification, which the
// TEAL cost model is built from. The chain count varies with the message;
// the rest is fixed by the parameter set.
func TestVerifyStatsProfile(t *testing.T) {
	v := loadVectors(t)
	for _, tc := range v.SigGen {
		if tc.Interface != "internal" {
			continue
		}
		pk, _ := ParsePublicKey(unhex(t, tc.PK))
		st, err := VerifyStats(pk, unhex(t, tc.Message), unhex(t, tc.Signature))
		if err != nil {
			t.Fatal(err)
		}
		if st.HMsg != 2 || st.PRF != 0 || st.TLen != 1+D || st.H != K*A+D*HPrime {
			t.Errorf("tc %d: fixed profile %+v", tc.TcID, st)
		}
		if st.F != K+st.Chain {
			t.Errorf("tc %d: F=%d, chain=%d, K=%d", tc.TcID, st.F, st.Chain, K)
		}
		if st.Chain > D*Len*(W-1) {
			t.Errorf("tc %d: chain %d exceeds bound", tc.TcID, st.Chain)
		}
		t.Logf("tc %d: hashes=%d chain=%d (%+v)", tc.TcID, st.Hashes(), st.Chain, st)
	}
}

func TestRandomRoundTrip(t *testing.T) {
	var skSeed, skPrf, pkSeed [N]byte
	for _, s := range []*[N]byte{&skSeed, &skPrf, &pkSeed} {
		if _, err := rand.Read(s[:]); err != nil {
			t.Fatal(err)
		}
	}
	sk := KeyGenFromSeeds(&skSeed, &skPrf, &pkSeed)
	msg := []byte("rotating stage transaction id")
	sig, err := Sign(sk, msg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(&sk.Public, msg, sig, nil); err != nil {
		t.Fatal(err)
	}
	sig2, _ := Sign(sk, msg, nil, nil)
	if !bytes.Equal(sig, sig2) {
		t.Fatal("deterministic signing differs")
	}
	var r [N]byte
	fillRandom(t, r[:])
	sig3, _ := Sign(sk, msg, nil, &r)
	if bytes.Equal(sig, sig3) {
		t.Fatal("randomized signing equals deterministic")
	}
	if err := Verify(&sk.Public, msg, sig3, nil); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkKeyGen(b *testing.B) {
	var skSeed, skPrf, pkSeed [N]byte
	fillRandom(b, skSeed[:])
	fillRandom(b, skPrf[:])
	fillRandom(b, pkSeed[:])
	b.ReportAllocs()
	for b.Loop() {
		KeyGenFromSeeds(&skSeed, &skPrf, &pkSeed)
	}
}

func BenchmarkSign(b *testing.B) {
	var skSeed, skPrf, pkSeed [N]byte
	fillRandom(b, skSeed[:])
	fillRandom(b, skPrf[:])
	fillRandom(b, pkSeed[:])
	sk := KeyGenFromSeeds(&skSeed, &skPrf, &pkSeed)
	msg := make([]byte, 32)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		fillRandom(b, msg)
		SignInternal(sk, msg, &sk.Public.Seed)
	}
}

func BenchmarkVerify(b *testing.B) {
	var skSeed, skPrf, pkSeed [N]byte
	fillRandom(b, skSeed[:])
	fillRandom(b, skPrf[:])
	fillRandom(b, pkSeed[:])
	sk := KeyGenFromSeeds(&skSeed, &skPrf, &pkSeed)
	msg := make([]byte, 32)
	fillRandom(b, msg)
	sig := SignInternal(sk, msg, &sk.Public.Seed)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := VerifyInternal(&sk.Public, msg, sig); err != nil {
			b.Fatal(err)
		}
	}
}
