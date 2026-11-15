// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package stageprog_test

import (
	"bytes"
	"testing"

	"github.com/aplane-algo/aplane/lsig/rotatingfamily/stageprog"
	slhstage "github.com/aplane-algo/aplane/lsig/rotatingtripleslhdsa/stage"
	wotscstage "github.com/aplane-algo/aplane/lsig/rotatingtriplewotsc/stage"
	xmssstage "github.com/aplane-algo/aplane/lsig/rotatingtriplexmss/stage"
)

// rotationGuard is what every rotating stage program shares after its
// version byte and the stage prefix's constant, assembled by TEAL v13:
//
//	txn RekeyTo; global ZeroAddress; !=; assert        a spend must rekey
//	txn RekeyTo; txn Sender; !=; assert                but not to itself
//	txn CloseRemainderTo; global ZeroAddress; ==; assert   and not close out
//	txn LastValid; txn FirstValid; -; pushint 100; <=; assert  window <= 100
//
// The templates are frozen and define addresses, so the guard cannot be
// shared code; this test keeps the copies identical.
var rotationGuard = []byte{
	0x31, 0x20, 0x32, 0x03, 0x13, 0x44,
	0x31, 0x20, 0x31, 0x00, 0x13, 0x44,
	0x31, 0x09, 0x32, 0x03, 0x12, 0x44,
	0x31, 0x04, 0x31, 0x02, 0x09, 0x81, 0x64, 0x0e, 0x44,
}

func TestEveryStageProgramOpensWithTheRotationGuard(t *testing.T) {
	xmss, err := xmssstage.Build(&xmssstage.PublicKeys{Stage: 0, Lo: 0, Hi: xmssstage.IndicesPerStage})
	if err != nil {
		t.Fatal(err)
	}
	slh, err := slhstage.Build(&slhstage.PublicKeys{})
	if err != nil {
		t.Fatal(err)
	}
	wotsc, err := wotscstage.Build(&wotscstage.PublicKeys{})
	if err != nil {
		t.Fatal(err)
	}
	// guardAt is where the guard begins: after the version byte, or after the
	// stage prefix in a program that carries its stage number.
	for name, c := range map[string]struct {
		program []byte
		guardAt int
	}{
		"XMSS":    {xmss.Bytecode, stageprog.PrefixSize},
		"SLH-DSA": {slh.Bytecode, 1},
		"WOTS+C":  {wotsc.Bytecode, 1},
	} {
		if c.program[0] != 0x0d || !bytes.HasPrefix(c.program[c.guardAt:], rotationGuard) {
			t.Errorf("the %s stage program does not open with the rotation guard: % x", name, c.program[:c.guardAt+len(rotationGuard)])
		}
	}
	if xmssstage.MaxValidityWindow != 100 || slhstage.MaxValidityWindow != 100 || wotscstage.MaxValidityWindow != 100 {
		t.Error("a stage package's validity window differs from the guard's 100 rounds")
	}
}
