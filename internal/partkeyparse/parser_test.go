// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package partkeyparse

import (
	"strings"
	"testing"
)

const basePartKeyInfo = `Parent address:            TESTPARENTADDRESS7777777777777777777777777777777777777777
Selection key:             1+bzBrUVQDWDqcv4Iuv9uRYLp4DPViih4x2MGmKcYus=
Voting key:                tAtM0mBYE1p5k5KaHOvFYho09qEUEGWzaZs1dmBFWVQ=
State proof key:           eS1o+ZVYZDkHBgFqhHAdF8Slyb190C+9aopj85xyUDB7342Pn02Fz2sUP+zGYC697vAWnZFT5SKExOG/PB+asQ==
Key dilution:              1733`

func TestParsePrefersEffectiveRounds(t *testing.T) {
	input := basePartKeyInfo + `
Effective first round:     54647336
Effective last round:      57646714
First round:               1
Last round:                2`

	info, err := Parse(input)
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}

	want := &ParsedInfo{
		ParentAddress: "TESTPARENTADDRESS7777777777777777777777777777777777777777",
		SelectionKey:  "1+bzBrUVQDWDqcv4Iuv9uRYLp4DPViih4x2MGmKcYus=",
		VoteKey:       "tAtM0mBYE1p5k5KaHOvFYho09qEUEGWzaZs1dmBFWVQ=",
		StateProofKey: "eS1o+ZVYZDkHBgFqhHAdF8Slyb190C+9aopj85xyUDB7342Pn02Fz2sUP+zGYC697vAWnZFT5SKExOG/PB+asQ==",
		VoteFirst:     54647336,
		VoteLast:      57646714,
		KeyDilution:   1733,
	}

	if *info != *want {
		t.Fatalf("Parse() = %+v, want %+v", *info, *want)
	}
}

func TestParseFallsBackToRegularRounds(t *testing.T) {
	input := basePartKeyInfo + `
First round:               1000
Last round:                2000`

	info, err := Parse(input)
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if info.VoteFirst != 1000 || info.VoteLast != 2000 {
		t.Fatalf("VoteFirst/VoteLast = %d/%d, want 1000/2000", info.VoteFirst, info.VoteLast)
	}
}

func TestParseReportsMissingRequiredField(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name: "missing parent address",
			input: `Selection key: AAAA=
Voting key: BBBB=
State proof key: CCCC=
Key dilution: 100
First round: 1
Last round: 2`,
			wantErr: "could not find 'Parent address' in input",
		},
		{
			name: "missing selection key",
			input: `Parent address: ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ2345
Voting key: BBBB=
State proof key: CCCC=
Key dilution: 100
First round: 1
Last round: 2`,
			wantErr: "could not find 'Selection key' in input",
		},
		{
			name: "missing voting key",
			input: `Parent address: ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ2345
Selection key: AAAA=
State proof key: CCCC=
Key dilution: 100
First round: 1
Last round: 2`,
			wantErr: "could not find 'Voting key' in input",
		},
		{
			name: "missing state proof key",
			input: `Parent address: ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ2345
Selection key: AAAA=
Voting key: BBBB=
Key dilution: 100
First round: 1
Last round: 2`,
			wantErr: "could not find 'State proof key' in input",
		},
		{
			name: "missing key dilution",
			input: `Parent address: ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ2345
Selection key: AAAA=
Voting key: BBBB=
State proof key: CCCC=
First round: 1
Last round: 2`,
			wantErr: "could not find 'Key dilution' in input",
		},
		{
			name: "missing all round fields",
			input: `Parent address: ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ2345
Selection key: AAAA=
Voting key: BBBB=
State proof key: CCCC=
Key dilution: 100`,
			wantErr: "could not find 'Effective first round' or 'First round' in input",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := Parse(tt.input)
			if err == nil {
				t.Fatalf("Parse() = %+v, want error containing %q", info, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want containing %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestParseRejectsInvalidRoundValue(t *testing.T) {
	input := basePartKeyInfo + `
Effective first round:     nope
Effective last round:      2000`

	_, err := Parse(input)
	if err == nil {
		t.Fatal("Parse() error = nil, want invalid round error")
	}
	if !strings.Contains(err.Error(), "could not find 'Effective first round' or 'First round' in input") {
		t.Fatalf("error = %q, want missing-round error", err.Error())
	}
}
