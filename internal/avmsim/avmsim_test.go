// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package avmsim

import (
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"testing"
)

// TestAVMSimOpcodes pins the interpreter's reading of the opcodes whose
// semantics are easy to get backwards, so a verifier result is evidence about
// the verifier and not about the interpreter.
func TestAVMSimOpcodes(t *testing.T) {
	run := func(src string) (bool, error) {
		p, err := Assemble(src)
		if err != nil {
			t.Fatal(err)
		}
		return p.Run(Txn{}, nil, Hooks{})
	}
	digest := sha512.Sum512_256([]byte{0xab})
	pass := []struct{ name, src string }{
		{"extract zero length reads to the end", "pushbytes 0x010203\nextract 1 0\npushbytes 0x0203\n==\nreturn"},
		{"extract3", "pushbytes 0x01020304\npushint 1\npushint 2\nextract3\npushbytes 0x0203\n==\nreturn"},
		{"replace2 overwrites in place", "pushbytes 0x01020304\npushbytes 0xaabb\nreplace2 1\npushbytes 0x01aabb04\n==\nreturn"},
		{"select picks the second when true", "pushint 7\npushint 9\npushint 1\nselect\npushint 9\n==\nreturn"},
		{"select picks the first when false", "pushint 7\npushint 9\npushint 0\nselect\npushint 7\n==\nreturn"},
		{"shl wraps", "pushint 0x8000000000000001\npushint 1\nshl\npushint 2\n==\nreturn"},
		{"switch falls through out of range", "pushint 5\nswitch a b\npushint 1\nreturn\na:\npushint 0\nreturn\nb:\npushint 0\nreturn"},
		{"switch jumps", "pushint 1\nswitch a b\npushint 0\nreturn\na:\npushint 0\nreturn\nb:\npushint 1\nreturn"},
		{"getbyte and setbyte", "pushbytes 0x0102\npushint 1\npushint 9\nsetbyte\npushint 1\ngetbyte\npushint 9\n==\nreturn"},
		{"subroutine", "callsub f\nreturn\nf:\npushint 1\nretsub"},
		{"btoi", "pushbytes 0x0102\nbtoi\npushint 258\n==\nreturn"},
		{"int is pushint", "int 3\npushint 3\n==\nreturn"},
		{"bnz jumps on nonzero", "pushint 2\nbnz yes\npushint 0\nreturn\nyes:\npushint 1\nreturn"},
		{"bnz falls through on zero", "pushint 0\nbnz no\npushint 1\nreturn\nno:\npushint 0\nreturn"},
		{"bz jumps on zero", "pushint 0\nbz yes\npushint 0\nreturn\nyes:\npushint 1\nreturn"},
		{"! of zero", "pushint 0\n!\nreturn"},
		{"! of nonzero", "pushint 7\n!\n!\nreturn"},
		{"&&", "pushint 2\npushint 3\n&&\npushint 1\npushint 0\n&&\n!\n&&\nreturn"},
		{"||", "pushint 0\npushint 3\n||\npushint 0\npushint 0\n||\n!\n&&\nreturn"},
		{"> is strict", "pushint 3\npushint 2\n>\npushint 2\npushint 2\n>\n!\n&&\nreturn"},
		{">= admits equality", "pushint 2\npushint 2\n>=\npushint 1\npushint 2\n>=\n!\n&&\nreturn"},
		{"b< compares big-endian unsigned", "pushbytes 0x00ff\npushbytes 0x0100\nb<\npushbytes 0x02\npushbytes 0x0001\nb<\n!\n&&\nreturn"},
		{"b< is strict", "pushbytes 0x01\npushbytes 0x01\nb<\n!\nreturn"},
		{"dup", "pushint 4\ndup\n==\nreturn"},
		{"dup2 keeps the order", "pushint 1\npushint 2\ndup2\npushint 2\n==\nassert\npushint 1\n==\nassert\npushint 2\n==\nassert\npushint 1\n==\nreturn"},
		{"pop", "pushint 1\npushint 0\npop\nreturn"},
		{"sha512_256", "pushbytes 0xab\nsha512_256\npushbytes 0x" + hex.EncodeToString(digest[:]) + "\n==\nreturn"},
		{"falls off the end with one true value", "pushint 1"},
	}
	for _, tc := range pass {
		if ok, err := run(tc.src); !ok || err != nil {
			t.Errorf("%s: ok %v, err %v", tc.name, ok, err)
		}
	}
	rejects := []struct{ name, src string }{
		{"err", "err\npushint 1\nreturn"},
		{"failed assert", "pushint 0\nassert\npushint 1\nreturn"},
		{"zero return", "pushint 0\nreturn"},
	}
	for _, tc := range rejects {
		if ok, err := run(tc.src); ok || err != nil {
			t.Errorf("%s: ok %v, err %v, want a plain rejection", tc.name, ok, err)
		}
	}
	if ok, err := run("pushint 1\npushint 1"); ok || !errors.Is(err, ErrReject) {
		t.Errorf("two values left: ok %v, err %v, want ErrReject", ok, err)
	}
	faults := []struct{ name, src string }{
		{"add overflow", "pushint 18446744073709551615\npushint 1\n+\nreturn"},
		{"sub underflow", "pushint 1\npushint 2\n-\nreturn"},
		{"shift by 64", "pushint 1\npushint 64\nshr\nreturn"},
		{"concat past 4096", "pushint 4096\nbzero\npushbytes 0x00\nconcat\nreturn"},
		{"extract out of range", "pushbytes 0x01\nextract 0 2\nreturn"},
		{"replace2 out of range", "pushbytes 0x01\npushbytes 0x0203\nreplace2 0\nreturn"},
		{"type confusion", "pushbytes 0x01\npushint 1\n==\nreturn"},
		{"b< past 64 bytes", "pushint 65\nbzero\npushbytes 0x01\nb<\nreturn"},
		{"b< on integers", "pushint 1\npushint 2\nb<\nreturn"},
		{"! on bytes", "pushbytes 0x00\n!\nreturn"},
		{"dup on an empty stack", "dup\nreturn"},
		{"dup2 on one value", "pushint 1\ndup2\nreturn"},
		{"pop on an empty stack", "pop\npushint 1\nreturn"},
		{"arg out of range", "arg 0\nlen\nreturn"},
		{"unknown opcode", "bitlen\nreturn"},
	}
	for _, tc := range faults {
		if ok, err := run(tc.src); ok || err == nil {
			t.Errorf("%s: ok %v, err %v, want a fault", tc.name, ok, err)
		}
	}
	// An opcode the interpreter does not know is not an AVM fault: it must
	// surface as unsupported so a harness can refuse to read it as a rejection.
	_, err := run("bitlen\nreturn")
	var unsupported *UnsupportedError
	if !errors.As(err, &unsupported) {
		t.Errorf("unknown opcode error = %v, want an unsupported-by-the-interpreter error", err)
	}
	// Literal formats the interpreter does not understand are likewise
	// unsupported, not faults: base64 and string byte literals, named and
	// malformed integer constants, instructions missing an immediate, and a
	// transaction field the test did not supply.
	for _, src := range []string{
		"pushint 1\nb nowhere",
		"pushint 1\nbnz nowhere",
		"global Round\nreturn",
		"pushbytes base64(AQ==)\nbtoi\nreturn",
		`pushbytes "a"` + "\nbtoi\nreturn",
		"pushbytes 0xZZ\nreturn",
		"pushbytes 0x0\nreturn",
		"pushint NoOp\nreturn",
		"int pay\nreturn",
		"pushint 18446744073709551616\nreturn",
		"pushint\nreturn",
		"int\nreturn",
		"pushbytes\nreturn",
		"callsub\nreturn",
		"bnz\nreturn",
		"txn Fee\nreturn",
		"pushbytes 0x00\npushbytes 0x00\npushbytes 0x00\nfalcon_verify\nreturn",
	} {
		if _, err := run(src); !errors.As(err, &unsupported) {
			t.Errorf("%q: error = %v, want unsupported", src, err)
		}
	}
}

// TestAVMSimTransactionFields checks that the program sees exactly the fields
// the test supplies, with their types.
func TestAVMSimTransactionFields(t *testing.T) {
	p, err := Assemble("txn Fee\npushint 1000\n==\nassert\ntxn Sender\nlen\npushint 32\n==\nassert\ntxn Receiver\nglobal ZeroAddress\n==")
	if err != nil {
		t.Fatal(err)
	}
	sender := make([]byte, 32)
	sender[0] = 1
	txn := Txn{"Fee": U(1000), "Sender": B(sender), "Receiver": B(make([]byte, 32))}
	if txn["Fee"].Uint() != 1000 || len(txn["Sender"].Bytes()) != 32 {
		t.Fatal("field constructors do not round-trip")
	}
	if ok, err := p.Run(txn, nil, Hooks{}); !ok || err != nil {
		t.Fatalf("ok %v, err %v", ok, err)
	}
	txn["Receiver"] = B(sender)
	if ok, err := p.Run(txn, nil, Hooks{}); ok || !errors.Is(err, ErrReject) {
		t.Fatalf("a nonzero receiver: ok %v, err %v, want ErrReject", ok, err)
	}
	// A bytes field supplied as an integer is a modeled type fault.
	txn["Sender"] = U(1)
	if ok, err := p.Run(txn, nil, Hooks{}); ok || err == nil {
		t.Fatalf("a mistyped field: ok %v, err %v, want a fault", ok, err)
	}
}

// TestAVMSimSignatureHooks checks the hooks receive data, signature and key in
// the AVM's operand order.
func TestAVMSimSignatureHooks(t *testing.T) {
	p, err := Assemble("pushbytes 0x01\narg 0\npushbytes 0x03\nfalcon_verify\nassert\npushbytes 0x04\narg 1\npushbytes 0x06\ned25519verify_bare")
	if err != nil {
		t.Fatal(err)
	}
	var seen [][3]string
	record := func(data, sig, key []byte) bool {
		seen = append(seen, [3]string{hex.EncodeToString(data), hex.EncodeToString(sig), hex.EncodeToString(key)})
		return true
	}
	ok, err := p.Run(Txn{}, [][]byte{{0x02}, {0x05}}, Hooks{Falcon: record, Ed25519: record})
	if !ok || err != nil {
		t.Fatalf("ok %v, err %v", ok, err)
	}
	if want := [][3]string{{"01", "02", "03"}, {"04", "05", "06"}}; len(seen) != 2 || seen[0] != want[0] || seen[1] != want[1] {
		t.Fatalf("hooks saw %v, want %v", seen, want)
	}
	var equal [2]Value
	q, err := Assemble("pushint 7\npushint 7\n==")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := q.Run(Txn{}, nil, Hooks{Equal: func(a, b Value) { equal = [2]Value{a, b} }}); !ok || err != nil {
		t.Fatalf("ok %v, err %v", ok, err)
	}
	if equal[0].Uint() != 7 || equal[1].Uint() != 7 || equal[0].Bytes() != nil {
		t.Fatalf("Equal hook saw %+v", equal)
	}
}
