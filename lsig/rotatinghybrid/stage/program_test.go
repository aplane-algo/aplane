// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package stage

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/algo"
	"github.com/aplane-algo/aplane/internal/lsigsalt"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

func randomKeys(t *testing.T) PublicKeys {
	t.Helper()
	var keys PublicKeys
	if _, err := rand.Read(keys.Falcon[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(keys.Ed25519[:]); err != nil {
		t.Fatal(err)
	}
	return keys
}

// keysWithSalt returns random keys whose program is salted (or not). About
// half of all programs need salt, so this terminates quickly.
func keysWithSalt(t *testing.T, salted bool) (PublicKeys, Program) {
	t.Helper()
	for range 256 {
		keys := randomKeys(t)
		program, err := Build(keys)
		if err != nil {
			t.Fatal(err)
		}
		if program.Salted == salted {
			return keys, program
		}
	}
	t.Fatalf("no program with salted=%v in 256 tries", salted)
	return PublicKeys{}, Program{}
}

func TestProgramSizes(t *testing.T) {
	if UnsaltedProgramSize != 1870 || SaltedProgramSize != 1873 {
		t.Fatalf("program sizes = %d/%d, want 1870/1873", UnsaltedProgramSize, SaltedProgramSize)
	}
	if MaxArgumentBytes != 1487 {
		t.Fatalf("MaxArgumentBytes = %d, want 1487", MaxArgumentBytes)
	}
	if OpcodeCost != 3627 {
		t.Fatalf("OpcodeCost = %d, want 3627", OpcodeCost)
	}
}

func TestBuildParseRoundTrip(t *testing.T) {
	for _, salted := range []bool{false, true} {
		t.Run(fmt.Sprintf("salted=%v", salted), func(t *testing.T) {
			keys, program := keysWithSalt(t, salted)
			wantLen := UnsaltedProgramSize
			if salted {
				wantLen = SaltedProgramSize
			}
			if len(program.Bytecode) != wantLen {
				t.Fatalf("len = %d, want %d", len(program.Bytecode), wantLen)
			}
			if lsigsalt.IsOnCurve(program.Address) {
				t.Fatal("program address is on-curve")
			}
			addr, err := Address(program.Bytecode)
			if err != nil || addr != program.Address {
				t.Fatalf("Address() = %v, %v; want %v", addr, err, program.Address)
			}

			gotKeys, gotProgram, err := Parse(program.Bytecode)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if gotKeys != keys || gotProgram.Address != program.Address || gotProgram.Salt != program.Salt {
				t.Fatal("Parse() is not the inverse of Build()")
			}
		})
	}
}

func TestSaltedProgramNeedsSalt(t *testing.T) {
	_, program := keysWithSalt(t, true)
	unsalted, err := Address(program.Bytecode[:UnsaltedProgramSize])
	if err != nil {
		t.Fatal(err)
	}
	if !lsigsalt.IsOnCurve(unsalted) {
		t.Fatal("salt applied to a program that was already off-curve")
	}
	tail := program.Bytecode[UnsaltedProgramSize:]
	if tail[0] != 0x20 || tail[1] != 0x01 || tail[2] >= SaltSearchLimit {
		t.Fatalf("salt tail = %x, want 20 01 <0..127>", tail)
	}
	for salt := range program.Salt {
		candidate := bytes.Clone(program.Bytecode)
		candidate[UnsaltedProgramSize+2] = salt
		addr, _ := Address(candidate)
		if !lsigsalt.IsOnCurve(addr) {
			t.Fatalf("salt %d is off-curve but Build chose %d", salt, program.Salt)
		}
	}
}

func TestParseRejectsNonCanonicalPrograms(t *testing.T) {
	_, unsalted := keysWithSalt(t, false)
	_, salted := keysWithSalt(t, true)

	flipped := bytes.Clone(unsalted.Bytecode)
	flipped[suffixOffset+3] ^= 0x01

	unneededSalt := append(bytes.Clone(unsalted.Bytecode), 0x20, 0x01, 0x00)

	missingSalt := bytes.Clone(salted.Bytecode[:UnsaltedProgramSize])

	laterSalt := bytes.Clone(salted.Bytecode)
	for salt := salted.Salt + 1; salt < SaltSearchLimit; salt++ {
		laterSalt[UnsaltedProgramSize+2] = salt
		if addr, _ := Address(laterSalt); !lsigsalt.IsOnCurve(addr) {
			break
		}
	}

	for name, bytecode := range map[string][]byte{
		"empty":         nil,
		"truncated":     unsalted.Bytecode[:UnsaltedProgramSize-1],
		"template byte": flipped,
		"unneeded salt": unneededSalt,
		"missing salt":  missingSalt,
		"later salt":    laterSalt,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Parse(bytecode); !errors.Is(err, ErrInvalidProgram) {
				t.Fatalf("Parse() error = %v, want ErrInvalidProgram", err)
			}
		})
	}
}

// tealSource renders the documented TEAL for keys.
func tealSource(keys PublicKeys) string {
	return fmt.Sprintf(`#pragma version 13
txn TxID
arg 0
pushbytes 0x%s
falcon_verify
assert
txn TxID
arg 1
pushbytes 0x%s
ed25519verify_bare
assert
txn RekeyTo
global ZeroAddress
!=
assert
txn RekeyTo
txn Sender
!=
assert
txn CloseRemainderTo
global ZeroAddress
==
assert
txn LastValid
txn FirstValid
-
pushint 100
<=
assert
pushint 1
`, hex.EncodeToString(keys.Falcon[:]), hex.EncodeToString(keys.Ed25519[:]))
}

// TestBuildMatchesStockAssembler compiles the documented TEAL with a stock
// algod and requires byte equality with Build, for both unsalted and salted
// programs. Set TEAL_COMPILE_ALGOD_URL to use a local node.
func TestBuildMatchesStockAssembler(t *testing.T) {
	client, err := algod.MakeClient(algo.ResolveTEALCompileAlgodURL(), algo.ResolveTEALCompileAlgodToken())
	if err != nil {
		t.Skipf("algod client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := client.HealthCheck().Do(ctx); err != nil {
		t.Skipf("algod unreachable: %v", err)
	}

	const perKind = 4
	counts := map[bool]int{}
	for tries := 0; counts[false] < perKind || counts[true] < perKind; tries++ {
		if tries > 64 {
			t.Fatalf("could not find %d programs of each kind; got %v", perKind, counts)
		}
		keys := randomKeys(t)
		want, err := Build(keys)
		if err != nil {
			t.Fatal(err)
		}
		if counts[want.Salted] >= perKind {
			continue
		}
		counts[want.Salted]++

		result, err := client.TealCompile([]byte(tealSource(keys))).Do(ctx)
		if err != nil {
			t.Fatalf("TealCompile() error = %v", err)
		}
		got, err := base64.StdEncoding.DecodeString(result.Result)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want.Bytecode) {
			t.Fatalf("salted=%v: local bytecode differs from algod\nlocal: %x\nalgod: %x", want.Salted, want.Bytecode, got)
		}
		if result.Hash != want.Address.String() {
			t.Fatalf("algod hash %s, local address %s", result.Hash, want.Address)
		}
	}
}
