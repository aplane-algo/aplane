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

// Two keys pasted together are refused: the fields would otherwise be taken
// from whichever block has them first.
func TestParseRefusesMoreThanOneKey(t *testing.T) {
	first := basePartKeyInfo + `
Effective first round:     N/A
Effective last round:      N/A
First round:               1
Last round:                2`
	second := basePartKeyInfo + `
Effective first round:     54647336
Effective last round:      57646714
First round:               3
Last round:                4`

	if _, err := Parse(first + "\n\n" + second); err == nil || !strings.Contains(err.Error(), "more than one participation key") {
		t.Fatalf("two keys: %v, want them refused", err)
	}
	// The paste starts below the first key's parent address, so only one
	// parent address is present, but the first key's other fields are.
	partial := first[strings.Index(first, "Selection key:"):]
	if !strings.Contains(partial, "Voting key:") || strings.Contains(partial, "Parent address:") {
		t.Fatalf("fixture: the partial block is not what the test needs:\n%s", partial)
	}
	if _, err := Parse(partial + "\n\n" + second); err == nil || !strings.Contains(err.Error(), "more than one participation key") {
		t.Fatalf("part of one key and all of another: %v, want them refused", err)
	}
	if _, err := Parse(second); err != nil {
		t.Fatalf("one key refused: %v", err)
	}
}

// One key's round lines followed by another key in full is the same mix.
func TestParseRefusesRoundLinesFromASecondKey(t *testing.T) {
	rounds := `Effective first round:     100
Effective last round:      200
First round:               1
Last round:                2`
	complete := basePartKeyInfo + `
Effective first round:     54647336
Effective last round:      57646714
First round:               3
Last round:                4`
	if _, err := Parse(rounds + "\n\n" + complete); err == nil || !strings.Contains(err.Error(), "more than one participation key") {
		t.Fatalf("one key's rounds and another key: %v, want them refused", err)
	}
}

// Every outcome, with its exact error text.
func TestParseExactOutcomes(t *testing.T) {
	const huge = "99999999999999999999"
	rounds := "\nFirst round: 1\nLast round: 2"
	tests := []struct {
		name    string
		input   string
		want    *ParsedInfo
		wantErr string
	}{
		{
			name:  "effective first, plain last",
			input: basePartKeyInfo + "\nEffective first round: 7\nFirst round: 1\nLast round: 9",
			want: &ParsedInfo{
				ParentAddress: "TESTPARENTADDRESS7777777777777777777777777777777777777777",
				SelectionKey:  "1+bzBrUVQDWDqcv4Iuv9uRYLp4DPViih4x2MGmKcYus=",
				VoteKey:       "tAtM0mBYE1p5k5KaHOvFYho09qEUEGWzaZs1dmBFWVQ=",
				StateProofKey: "eS1o+ZVYZDkHBgFqhHAdF8Slyb190C+9aopj85xyUDB7342Pn02Fz2sUP+zGYC697vAWnZFT5SKExOG/PB+asQ==",
				VoteFirst:     7,
				VoteLast:      9,
				KeyDilution:   1733,
			},
		},
		{name: "missing last round", input: basePartKeyInfo + "\nFirst round: 1", wantErr: "could not find 'Effective last round' or 'Last round' in input"},
		{name: "key dilution overflow", input: strings.Replace(basePartKeyInfo, "1733", huge, 1) + rounds, wantErr: "invalid key dilution value: " + huge},
		{name: "effective first overflow", input: basePartKeyInfo + "\nEffective first round: " + huge + rounds, wantErr: "invalid effective first round value: " + huge},
		{name: "first overflow", input: basePartKeyInfo + "\nFirst round: " + huge + "\nLast round: 2", wantErr: "invalid first round value: " + huge},
		{name: "effective last overflow", input: basePartKeyInfo + "\nEffective last round: " + huge + rounds, wantErr: "invalid effective last round value: " + huge},
		{name: "last overflow", input: basePartKeyInfo + "\nFirst round: 1\nLast round: " + huge, wantErr: "invalid last round value: " + huge},
		{name: "voting key twice", input: basePartKeyInfo + "\nVoting key: AAAA=" + rounds, wantErr: "the input holds more than one participation key (Voting key appears 2 times); paste only the one to register"},
		{name: "key dilution twice", input: basePartKeyInfo + "\nKey dilution: 5" + rounds, wantErr: "the input holds more than one participation key (Key dilution appears 2 times); paste only the one to register"},
		{name: "last round three times", input: basePartKeyInfo + rounds + "\nLast round: 3\nLast round: 4", wantErr: "the input holds more than one participation key (its round lines repeat); paste only the one to register"},
		{name: "empty", input: "", wantErr: "could not find 'Parent address' in input"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := Parse(tt.input)
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr || info != nil {
					t.Fatalf("Parse() = (%+v, %v), want error %q", info, err, tt.wantErr)
				}
				return
			}
			if err != nil || *info != *tt.want {
				t.Fatalf("Parse() = (%+v, %v), want %+v", info, err, *tt.want)
			}
		})
	}
}
