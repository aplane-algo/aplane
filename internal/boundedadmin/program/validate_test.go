// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package program

import (
	"encoding/binary"
	"strings"
	"testing"

	boundedmessage "github.com/aplane-algo/aplane/internal/boundedadmin/message"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	sentrymessage "github.com/aplane-algo/aplane/internal/sentry/message"
)

type testProgramBuilder struct {
	program        []byte
	labels         map[string]int
	fixups         map[int]testProgramFixup
	varintBranches bool
}

type testProgramFixup struct {
	label  string
	base   int
	pc     int
	varint bool
}

func newTestProgramBuilderWithBranches(varintBranches bool) *testProgramBuilder {
	return &testProgramBuilder{
		program:        []byte{byte(bounded1ContractManifest.TEALVersion)},
		labels:         map[string]int{},
		fixups:         map[int]testProgramFixup{},
		varintBranches: varintBranches,
	}
}

func (b *testProgramBuilder) op(opcode byte, immediate ...byte) {
	b.program = append(b.program, opcode)
	b.program = append(b.program, immediate...)
}

func (b *testProgramBuilder) pushInt(value uint64) {
	b.program = append(b.program, 0x81)
	b.program = binary.AppendUvarint(b.program, value)
}

func (b *testProgramBuilder) pushBytes(value []byte) {
	b.program = append(b.program, 0x80)
	b.program = binary.AppendUvarint(b.program, uint64(len(value)))
	b.program = append(b.program, value...)
}

func (b *testProgramBuilder) arg(index int) {
	if index >= 0 && index <= 3 {
		b.op(byte(0x2d + index))
		return
	}
	b.op(0x2c, byte(index))
}

func (b *testProgramBuilder) label(name string) { b.labels[name] = len(b.program) }

func (b *testProgramBuilder) branch(opcode byte, label string) {
	pc := len(b.program)
	if !b.varintBranches {
		b.op(opcode, 0, 0)
		b.fixups[pc+1] = testProgramFixup{label: label, base: pc + 3}
		return
	}
	// Fixed-width overlong encodings keep test label positions stable while
	// exercising TEAL v13's signed-varint branch decoder.
	b.op(opcode, 0x80, 0x80, 0x80, 0x80, 0)
	b.fixups[pc+1] = testProgramFixup{label: label, base: pc + 6, pc: pc, varint: true}
}

func (b *testProgramBuilder) branchVector(opcode byte, labels ...string) {
	pc := len(b.program)
	b.op(opcode, byte(len(labels)))
	base := pc + 2 + 2*len(labels)
	for _, label := range labels {
		offsetAt := len(b.program)
		b.program = append(b.program, 0, 0)
		b.fixups[offsetAt] = testProgramFixup{label: label, base: base}
	}
}

func (b *testProgramBuilder) finish(t *testing.T) []byte {
	t.Helper()
	for offsetAt, fixup := range b.fixups {
		target, ok := b.labels[fixup.label]
		if !ok {
			t.Fatalf("missing label %q", fixup.label)
		}
		offset := target - fixup.base
		if fixup.varint {
			if target < fixup.pc {
				offset = target - fixup.pc
			}
			putFixedVarint5(b.program[offsetAt:offsetAt+5], int64(offset))
			continue
		}
		binary.BigEndian.PutUint16(b.program[offsetAt:offsetAt+2], uint16(int16(offset)))
	}
	return b.program
}

func putFixedVarint5(dst []byte, value int64) {
	u := uint64(value) << 1
	if value < 0 {
		u = uint64(^value)<<1 | 1
	}
	for i := 0; i < 4; i++ {
		dst[i] = byte(u) | 0x80
		u >>= 7
	}
	dst[4] = byte(u)
}

func testExpectedProgram(t *testing.T) ([]byte, Expected) {
	return testExpectedProgramWithLayer3(t, func(b *testProgramBuilder) {
		b.pushInt(1)
		b.branch(0x42, "accept")
	})
}

func testExpectedProgramWithLayer3(t *testing.T, layer3 func(*testProgramBuilder)) ([]byte, Expected) {
	return testExpectedProgramWithAdminArg(t, 1, layer3)
}

func testExpectedProgramWithAdminArg(t *testing.T, adminArgIndex int, layer3 func(*testProgramBuilder)) ([]byte, Expected) {
	return testExpectedProgramWithOptions(t, adminArgIndex, false, layer3)
}

func testExpectedSentryProgram(t *testing.T) ([]byte, Expected) {
	return testExpectedProgramWithOptions(t, 2, true, func(b *testProgramBuilder) {
		b.pushInt(1)
		b.branch(0x42, "accept")
	})
}

func testExpectedProgramWithOptions(t *testing.T, adminArgIndex int, withSentry bool, layer3 func(*testProgramBuilder)) ([]byte, Expected) {
	return testExpectedProgramWithBranchEncoding(t, adminArgIndex, withSentry, true, layer3)
}

func testExpectedProgramWithBranchEncoding(t *testing.T, adminArgIndex int, withSentry, varintBranches bool, layer3 func(*testProgramBuilder)) ([]byte, Expected) {
	t.Helper()
	spendingKey := make([]byte, 1793)
	adminKey := make([]byte, 1793)
	sentryKey := make([]byte, 1793)
	binding := make([]byte, 32)
	for i := range spendingKey {
		spendingKey[i] = 0x11
		adminKey[i] = 0x22
		sentryKey[i] = 0x44
	}
	for i := range binding {
		binding[i] = 0x33
	}
	prefix, err := boundedmessage.Prefix(boundedmessage.OperationRekey, binding)
	if err != nil {
		t.Fatal(err)
	}

	b := newTestProgramBuilderWithBranches(varintBranches)
	// Falcon spending authentication.
	b.op(0x31, 23)
	b.op(0x2d)
	b.pushBytes(spendingKey)
	b.op(0x85)
	b.op(0x44)
	// Fee and rekey dispatch.
	b.op(0x31, 1)
	b.pushInt(10_000)
	b.op(0x0e)
	b.op(0x44)
	b.op(0x31, 32)
	b.op(0x32, 3)
	b.op(0x13)
	b.branch(0x40, "rekey")
	// Pure-spend effect and type gate.
	for _, field := range []byte{9, 21, 19} {
		b.op(0x31, field)
		b.op(0x32, 3)
		b.op(0x12)
		b.op(0x44)
	}
	b.op(0x31, 16)
	b.pushInt(1)
	b.op(0x12)
	b.branch(0x40, "pay")
	b.op(0x31, 16)
	b.pushInt(4)
	b.op(0x12)
	b.branch(0x40, "axfer")
	b.op(0x00)
	b.label("pay")
	b.branch(0x42, "spend")
	b.label("axfer")
	b.op(0x31, 18)
	b.pushInt(0)
	b.op(0x12)
	b.op(0x31, 20)
	b.op(0x31, 0)
	b.op(0x12)
	b.op(0x10)
	b.branch(0x40, "optin")
	b.branch(0x42, "spend")
	b.label("optin")
	b.branch(0x42, "spend")
	// Pure rekey and external Falcon authority.
	b.label("rekey")
	b.op(0x31, 16)
	b.pushInt(1)
	b.op(0x12)
	b.op(0x44)
	b.op(0x31, 8)
	b.pushInt(0)
	b.op(0x12)
	b.op(0x44)
	b.op(0x31, 7)
	b.op(0x31, 0)
	b.op(0x12)
	b.op(0x44)
	b.op(0x31, 32)
	b.op(0x32, 3)
	b.op(0x13)
	b.op(0x44)
	for _, field := range []byte{9, 21, 19} {
		b.op(0x31, field)
		b.op(0x32, 3)
		b.op(0x12)
		b.op(0x44)
	}
	b.arg(adminArgIndex)
	b.op(0x15)
	b.pushInt(0)
	b.op(0x0d)
	b.op(0x44)
	b.arg(adminArgIndex)
	b.op(0x15)
	b.pushInt(uint64(boundedmeta.FalconAdminSignatureSize))
	b.op(0x0e)
	b.op(0x44)
	b.pushBytes(prefix)
	b.op(0x31, 23)
	b.op(0x50)
	b.op(0x03)
	b.arg(adminArgIndex)
	b.pushBytes(adminKey)
	b.op(0x85)
	b.op(0x44)
	b.branch(0x42, "accept")
	// Opaque Layer 3 has no return and reaches the shared accept block.
	b.label("spend")
	if withSentry {
		sentryArgIndex := adminArgIndex - 1
		b.arg(sentryArgIndex)
		b.op(0x15)
		b.pushInt(0)
		b.op(0x0d)
		b.op(0x44)
		b.arg(sentryArgIndex)
		b.op(0x15)
		b.pushInt(uint64(boundedmeta.SentrySignatureMaxSizeV1))
		b.op(0x0e)
		b.op(0x44)
		b.pushBytes([]byte(sentrymessage.DomainTagV1))
		b.pushBytes([]byte{byte(sentrymessage.RoleSentry)})
		b.op(0x50)
		b.op(0x31, 23)
		b.op(0x50)
		b.op(0x03)
		b.arg(sentryArgIndex)
		b.pushBytes(sentryKey)
		b.op(0x85)
		b.op(0x44)
		b.branch(0x42, "layer3")
		b.label("layer3")
	}
	layer3(b)
	b.label("accept")
	b.pushInt(1)
	b.op(0x43)

	expected := Expected{
		SpendingPublicKey: spendingKey,
		AdminPublicKey:    adminKey,
		ProgramBinding:    binding,
		BaseArgCount:      1,
		AdminArgIndex:     adminArgIndex,
		MaxFee:            10_000,
		SpendEffects:      []string{"pay", "axfer", "asset_opt_in"},
	}
	if withSentry {
		expected.SentryPublicKey = sentryKey
		expected.SentryArgIndex = adminArgIndex - 1
	}
	return b.finish(t), expected
}

func TestValidateAcceptsArg3AdminSlot(t *testing.T) {
	program, expected := testExpectedProgramWithAdminArg(t, 3, func(b *testProgramBuilder) {
		b.pushInt(1)
		b.branch(0x42, "accept")
	})
	if err := Validate(program, expected); err != nil {
		t.Fatalf("Validate() rejected arg_3 contract-admin slot: %v", err)
	}
}

func TestDecodeVariableVectorRejectsBranchOpcodes(t *testing.T) {
	for _, opcode := range []byte{0x8d, 0x8e} {
		if _, err := decodeVariableVector([]byte{opcode, 0}, 0, opcode); err == nil || !strings.Contains(err.Error(), "unsupported variable-vector opcode") {
			t.Fatalf("decodeVariableVector(0x%02x) error = %v, want unsupported opcode", opcode, err)
		}
	}
}

func TestValidateRejectsLayer3ControlFlowEscapes(t *testing.T) {
	tests := []struct {
		name   string
		layer3 func(*testProgramBuilder)
	}{
		{
			name: "unconditional branch",
			layer3: func(b *testProgramBuilder) {
				b.branch(0x42, "rekey")
				b.branch(0x42, "accept")
			},
		},
		{
			name: "switch",
			layer3: func(b *testProgramBuilder) {
				b.pushInt(0)
				b.branchVector(0x8d, "rekey")
				b.branch(0x42, "accept")
			},
		},
		{
			name: "match",
			layer3: func(b *testProgramBuilder) {
				b.branchVector(0x8e, "rekey")
				b.branch(0x42, "accept")
			},
		},
		{
			name: "callsub",
			layer3: func(b *testProgramBuilder) {
				b.branch(0x88, "rekey")
				b.branch(0x42, "accept")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			program, expected := testExpectedProgramWithLayer3(t, test.layer3)
			err := Validate(program, expected)
			if err == nil || !strings.Contains(err.Error(), "escapes Layer 3") {
				t.Fatalf("Validate() error = %v, want Layer-3 escape rejection", err)
			}
		})
	}
}

func TestValidateAcceptsFrozenStructure(t *testing.T) {
	program, expected := testExpectedProgram(t)
	if err := Validate(program, expected); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateAcceptsDeployedV13FixedWidthBranches(t *testing.T) {
	program, expected := testExpectedProgramWithBranchEncoding(t, 1, false, false, func(b *testProgramBuilder) {
		b.pushInt(1)
		b.branch(0x42, "accept")
	})
	if err := Validate(program, expected); err != nil {
		t.Fatalf("Validate() rejected deployed v13 branch encoding: %v", err)
	}
}

func TestDecodeProgramUnambiguouslyRejectsDivergentV13BranchInterpretations(t *testing.T) {
	// Under signed-varint branches this is:
	//
	//     b +0; err; op_01; return
	//
	// Under fixed-width branches it is:
	//
	//     b +1; return
	//
	// Both streams are syntactically valid, but their instruction boundaries
	// and branch targets differ. Bounded validation must never choose whichever
	// interpretation happens to satisfy its structural contract.
	program := []byte{13, 0x42, 0x00, 0x01, 0x43}

	_, err := decodeProgramUnambiguously(program, 13)
	if err == nil || !strings.Contains(err.Error(), "ambiguous AVM v13 branch encoding") {
		t.Fatalf("decodeProgramUnambiguously() error = %v, want ambiguity rejection", err)
	}
}

func TestValidateAcceptsFrozenSentryStructure(t *testing.T) {
	program, expected := testExpectedSentryProgram(t)
	if err := Validate(program, expected); err != nil {
		t.Fatalf("Validate() rejected bounded sentry structure: %v", err)
	}

	wrongKey := expected
	wrongKey.SentryPublicKey = append([]byte(nil), expected.SentryPublicKey...)
	wrongKey.SentryPublicKey[0] ^= 0xff
	if err := Validate(program, wrongKey); err == nil || !strings.Contains(err.Error(), "sentry verification region") {
		t.Fatalf("Validate() error = %v, want sentry-key rejection", err)
	}
}

func TestValidateRejectsUnreportedSentryStructure(t *testing.T) {
	program, expected := testExpectedSentryProgram(t)
	expected.SentryPublicKey = nil
	expected.SentryArgIndex = 0

	err := Validate(program, expected)
	if err == nil || !strings.Contains(err.Error(), "present without sentry metadata") {
		t.Fatalf("Validate() error = %v, want unreported sentry rejection", err)
	}
}

func TestValidateAllowsLayer3DenyBranches(t *testing.T) {
	program, expected := testExpectedProgram(t)
	// Replace Layer 3's constant predicate with err. The shared accept branch
	// remains present; an author-owned denial cannot widen authority.
	for i := len(program) - 7; i >= 0; i-- {
		if program[i] == 0x81 && program[i+1] == 0x01 && program[i+2] == 0x42 {
			program[i] = 0x00
			program[i+1] = 0x48
			break
		}
	}
	if err := Validate(program, expected); err != nil {
		t.Fatalf("Validate() rejected Layer-3 err denial: %v", err)
	}
}

func TestValidateRejectsWrongOperandsAndControlFlow(t *testing.T) {
	program, expected := testExpectedProgram(t)
	tests := []struct {
		name   string
		mutate func([]byte, *Expected)
		want   string
	}{
		{name: "wrong admin key", mutate: func(_ []byte, expected *Expected) { expected.AdminPublicKey[0] ^= 0xff }, want: "verification region"},
		{name: "wrong max fee", mutate: func(_ []byte, expected *Expected) { expected.MaxFee-- }, want: "fee gate"},
		{name: "wrong spend effects", mutate: func(_ []byte, expected *Expected) { expected.SpendEffects = []string{"pay"} }, want: "effect/type gate"},
		{name: "truncated", mutate: func(value []byte, _ *Expected) { value[len(value)-1] = 0xff }, want: "opcode"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutatedProgram := append([]byte(nil), program...)
			mutatedExpected := expected
			mutatedExpected.SpendingPublicKey = append([]byte(nil), expected.SpendingPublicKey...)
			mutatedExpected.AdminPublicKey = append([]byte(nil), expected.AdminPublicKey...)
			mutatedExpected.SpendEffects = append([]string(nil), expected.SpendEffects...)
			test.mutate(mutatedProgram, &mutatedExpected)
			err := Validate(mutatedProgram, mutatedExpected)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want containing %q", err, test.want)
			}
		})
	}
}
