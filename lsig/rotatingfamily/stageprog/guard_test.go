// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package stageprog_test

import (
	"bytes"
	"testing"

	slhstage "github.com/aplane-algo/aplane/lsig/rotatingtripleslhdsa/stage"
	wotsstage "github.com/aplane-algo/aplane/lsig/rotatingtriplewots/stage"
	xmssstage "github.com/aplane-algo/aplane/lsig/rotatingtriplexmss/stage"
)

// rotationGuard is the opening every rotating stage program shares, assembled
// by TEAL v13:
//
//	#pragma version 13
//	txn RekeyTo; global ZeroAddress; !=; assert        a spend must rekey
//	txn RekeyTo; txn Sender; !=; assert                but not to itself
//	txn CloseRemainderTo; global ZeroAddress; ==; assert   and not close out
//	txn LastValid; txn FirstValid; -; pushint 100; <=; assert  window <= 100
//
// The templates are frozen and define addresses, so the guard cannot be
// shared code; this test keeps the three copies identical.
var rotationGuard = []byte{
	0x0d,
	0x31, 0x20, 0x32, 0x03, 0x13, 0x44,
	0x31, 0x20, 0x31, 0x00, 0x13, 0x44,
	0x31, 0x09, 0x32, 0x03, 0x12, 0x44,
	0x31, 0x04, 0x31, 0x02, 0x09, 0x81, 0x64, 0x0e, 0x44,
}

func TestEveryStageProgramOpensWithTheRotationGuard(t *testing.T) {
	wots, err := wotsstage.Build(&wotsstage.PublicKeys{})
	if err != nil {
		t.Fatal(err)
	}
	xmss, err := xmssstage.Build(&xmssstage.PublicKeys{Lo: 0, Hi: xmssstage.IndicesPerStage})
	if err != nil {
		t.Fatal(err)
	}
	slh, err := slhstage.Build(&slhstage.PublicKeys{})
	if err != nil {
		t.Fatal(err)
	}
	for name, program := range map[string][]byte{
		"WOTS":    wots.Bytecode,
		"XMSS":    xmss.Bytecode,
		"SLH-DSA": slh.Bytecode,
	} {
		if !bytes.HasPrefix(program, rotationGuard) {
			t.Errorf("the %s stage program does not open with the rotation guard: % x", name, program[:len(rotationGuard)])
		}
	}
	if wotsstage.MaxValidityWindow != 100 || xmssstage.MaxValidityWindow != 100 || slhstage.MaxValidityWindow != 100 {
		t.Error("a stage package's validity window differs from the guard's 100 rounds")
	}
}
