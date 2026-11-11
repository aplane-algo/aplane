// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

func TestCleanSubmitError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "logic rejection with struct dump",
			err:  fmt.Errorf(`HTTP 400: {"data":{"eval-states":[{}],"group-index":0,"pc":17},"message":"transaction {_struct:{} Sig:[0 0 0] Lsig:{Logic:[12 38 1]} Args:[[186 0 153]]} Txn:{Type:pay}} invalid : transaction 6XDV3KPBGTZKUWMY7B6AUXUJZKMPQORACVJFF2JU5AR2XWKX6MKQ: rejected by logic err=cannot load arg[1] of 1. Details: pc=17"}`),
			want: "transaction 6XDV3KPBGTZKUWMY7B6AUXUJZKMPQORACVJFF2JU5AR2XWKX6MKQ: rejected by logic err=cannot load arg[1] of 1. Details: pc=17",
		},
		{
			name: "overspend error",
			err:  fmt.Errorf(`HTTP 400: {"message":"transaction {_struct:{} ...} invalid : transaction TXID: overspend"}`),
			want: "transaction TXID: overspend",
		},
		{
			name: "unrelated error passes through",
			err:  fmt.Errorf("connection refused"),
			want: "connection refused",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cleanSubmitError(tt.err)
			if got.Error() != tt.want {
				t.Errorf("cleanSubmitError() = %q, want %q", got.Error(), tt.want)
			}
		})
	}
}

// dummyProgramOpcodes holds exactly the opcodes the dummy program uses: the
// immediate bytes each takes and its cost, which is 1 in every AVM version. None
// branches, so a program built only from them is straight-line and the sum of
// its opcode costs is the cost of every run. An opcode missing here fails the
// test rather than being guessed at.
var dummyProgramOpcodes = map[byte]struct {
	name       string
	immediates int
	cost       uint64
	fields     map[byte]string
}{
	0x12: {name: "==", cost: 1},
	0x31: {name: "txn", immediates: 1, cost: 1, fields: map[byte]string{32: "RekeyTo"}},
	0x32: {name: "global", immediates: 1, cost: 1, fields: map[byte]string{3: "ZeroAddress"}},
}

func TestDummyOpcodeCostMatchesEmbeddedProgram(t *testing.T) {
	program := EmbeddedDummyTealTok
	version, pc := binary.Uvarint(program)
	if pc <= 0 || version != 3 {
		t.Fatalf("dummy program version = %d (prefix %d bytes), want 3", version, pc)
	}
	var cost uint64
	var listing []string
	for pc < len(program) {
		op, ok := dummyProgramOpcodes[program[pc]]
		if !ok {
			t.Fatalf("dummy program opcode 0x%02x at pc %d has no cost in this test's table", program[pc], pc)
		}
		if pc+1+op.immediates > len(program) {
			t.Fatalf("dummy program opcode %s at pc %d is truncated", op.name, pc)
		}
		text := op.name
		if op.immediates == 1 {
			field, known := op.fields[program[pc+1]]
			if !known {
				t.Fatalf("dummy program %s field %d at pc %d is not in this test's table", op.name, program[pc+1], pc)
			}
			text += " " + field
		}
		listing = append(listing, text)
		cost += op.cost
		pc += 1 + op.immediates
	}
	if got, want := strings.Join(listing, "; "), "txn RekeyTo; global ZeroAddress; =="; got != want {
		t.Fatalf("dummy program = %q, want %q", got, want)
	}
	if cost != DummyOpcodeCost {
		t.Fatalf("dummy program costs %d, DummyOpcodeCost is %d", cost, DummyOpcodeCost)
	}
}
