// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package avmsim

import (
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
	}
	for _, tc := range pass {
		if ok, err := run(tc.src); !ok || err != nil {
			t.Errorf("%s: ok %v, err %v", tc.name, ok, err)
		}
	}
	faults := []struct{ name, src string }{
		{"add overflow", "pushint 18446744073709551615\npushint 1\n+\nreturn"},
		{"sub underflow", "pushint 1\npushint 2\n-\nreturn"},
		{"shift by 64", "pushint 1\npushint 64\nshr\nreturn"},
		{"concat past 4096", "pushint 4096\nbzero\npushbytes 0x00\nconcat\nreturn"},
		{"extract out of range", "pushbytes 0x01\nextract 0 2\nreturn"},
		{"replace2 out of range", "pushbytes 0x01\npushbytes 0x0203\nreplace2 0\nreturn"},
		{"type confusion", "pushbytes 0x01\npushint 1\n==\nreturn"},
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
	// malformed integer constants, and instructions missing an immediate.
	for _, src := range []string{
		"pushint 1\nb nowhere",
		"global Round\nreturn",
		"pushbytes base64(AQ==)\nbtoi\nreturn",
		`pushbytes "a"` + "\nbtoi\nreturn",
		"pushbytes 0xZZ\nreturn",
		"pushbytes 0x0\nreturn",
		"pushint NoOp\nreturn",
		"pushint 18446744073709551616\nreturn",
		"pushint\nreturn",
		"pushbytes\nreturn",
		"callsub\nreturn",
	} {
		if _, err := run(src); !errors.As(err, &unsupported) {
			t.Errorf("%q: error = %v, want unsupported", src, err)
		}
	}
}
