// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package stageprog_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/aplane-algo/aplane/lsig/rotatingfamily/stageprog"
	slhstage "github.com/aplane-algo/aplane/lsig/rotatingtripleslhdsa/stage"
	wotscstage "github.com/aplane-algo/aplane/lsig/rotatingtriplewotsc/stage"
	xmssstage "github.com/aplane-algo/aplane/lsig/rotatingtriplexmss/stage"
)

// rotationGuard is what every rotating stage program shares after the stage
// prefix (#pragma version 13; pushbytes <stage>; pop), assembled by TEAL v13:
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

// stagePrograms builds stage n of each rotating key type with zero keys.
func stagePrograms(t *testing.T, n uint64) map[string][]byte {
	t.Helper()
	_, lo, hi := xmssstage.RangeFor(n)
	xmss, err := xmssstage.Build(&xmssstage.PublicKeys{Stage: n, Lo: lo, Hi: hi})
	if err != nil {
		t.Fatal(err)
	}
	slh, err := slhstage.Build(&slhstage.PublicKeys{Stage: n})
	if err != nil {
		t.Fatal(err)
	}
	wotsc, err := wotscstage.Build(&wotscstage.PublicKeys{Stage: n})
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{"XMSS": xmss.Bytecode, "SLH-DSA": slh.Bytecode, "WOTS+C": wotsc.Bytecode}
}

func TestEveryStageProgramOpensWithTheRotationGuard(t *testing.T) {
	for name, program := range stagePrograms(t, 0) {
		if !bytes.HasPrefix(program[stageprog.PrefixSize:], rotationGuard) {
			t.Errorf("the %s stage program does not open with the rotation guard after the stage prefix: % x", name, program[:stageprog.PrefixSize+len(rotationGuard)])
		}
	}
	if xmssstage.MaxValidityWindow != 100 || slhstage.MaxValidityWindow != 100 || wotscstage.MaxValidityWindow != 100 {
		t.Error("a stage package's validity window differs from the guard's 100 rounds")
	}
}

// TestReadStageReadsEveryStageProgram checks the one reader of the stage
// number against every key type's program, and that the same program without
// the stage prefix, as stage programs were laid out before it, is refused.
func TestReadStageReadsEveryStageProgram(t *testing.T) {
	for _, n := range []uint64{0, 418, 1 << 40} {
		for name, program := range stagePrograms(t, n) {
			if got, err := stageprog.ReadStage(program); err != nil || got != n {
				t.Errorf("%s stage %d: ReadStage returned %d, %v", name, n, got, err)
			}
			without := append([]byte{program[0]}, program[stageprog.PrefixSize:]...)
			if _, err := stageprog.ReadStage(without); !errors.Is(err, stageprog.ErrInvalidProgram) {
				t.Errorf("%s stage %d without the stage prefix: %v", name, n, err)
			}
		}
	}
}
