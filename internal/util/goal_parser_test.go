// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package util

import (
	"testing"
)

func TestParsePartKeyInfo(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		check   func(t *testing.T, info *ParsedPartKeyInfo)
	}{
		{
			name: "valid partkeyinfo with effective rounds",
			input: `Registered:       Yes
			Parent address:            TESTPARENTADDRESS7777777777777777777777777777777777777777
			Selection key:             1+bzBrUVQDWDqcv4Iuv9uRYLp4DPViih4x2MGmKcYus=
			Voting key:                tAtM0mBYE1p5k5KaHOvFYho09qEUEGWzaZs1dmBFWVQ=
			State proof key:           eS1o+ZVYZDkHBgFqhHAdF8Slyb190C+9aopj85xyUDB7342Pn02Fz2sUP+zGYC697vAWnZFT5SKExOG/PB+asQ==
			Effective first round:     54647336
			Effective last round:      57646714
			Key dilution:              1733`,
			wantErr: false,
			check: func(t *testing.T, info *ParsedPartKeyInfo) {
				if info.ParentAddress != "TESTPARENTADDRESS7777777777777777777777777777777777777777" {
					t.Errorf("ParentAddress = %v, want TESTPARENTADDRESS7777777777777777777777777777777777777777", info.ParentAddress)
				}
				if info.SelectionKey != "1+bzBrUVQDWDqcv4Iuv9uRYLp4DPViih4x2MGmKcYus=" {
					t.Errorf("SelectionKey = %v, want 1+bzBrUVQDWDqcv4Iuv9uRYLp4DPViih4x2MGmKcYus=", info.SelectionKey)
				}
				if info.VoteKey != "tAtM0mBYE1p5k5KaHOvFYho09qEUEGWzaZs1dmBFWVQ=" {
					t.Errorf("VoteKey = %v, want tAtM0mBYE1p5k5KaHOvFYho09qEUEGWzaZs1dmBFWVQ=", info.VoteKey)
				}
				if info.StateProofKey != "eS1o+ZVYZDkHBgFqhHAdF8Slyb190C+9aopj85xyUDB7342Pn02Fz2sUP+zGYC697vAWnZFT5SKExOG/PB+asQ==" {
					t.Errorf("StateProofKey = %v, want eS1o+ZVYZDkHBgFqhHAdF8Slyb190C+9aopj85xyUDB7342Pn02Fz2sUP+zGYC697vAWnZFT5SKExOG/PB+asQ==", info.StateProofKey)
				}
				if info.VoteFirst != 54647336 {
					t.Errorf("VoteFirst = %v, want 54647336", info.VoteFirst)
				}
				if info.VoteLast != 57646714 {
					t.Errorf("VoteLast = %v, want 57646714", info.VoteLast)
				}
				if info.KeyDilution != 1733 {
					t.Errorf("KeyDilution = %v, want 1733", info.KeyDilution)
				}
			},
		},
		{
			name: "valid partkeyinfo with regular rounds (no effective)",
			input: `Parent address:            ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ2345
			Selection key:             AAAA=
			Voting key:                BBBB=
			State proof key:           CCCC=
			First round:               1000
			Last round:                2000
			Key dilution:              100`,
			wantErr: false,
			check: func(t *testing.T, info *ParsedPartKeyInfo) {
				if info.VoteFirst != 1000 {
					t.Errorf("VoteFirst = %v, want 1000", info.VoteFirst)
				}
				if info.VoteLast != 2000 {
					t.Errorf("VoteLast = %v, want 2000", info.VoteLast)
				}
			},
		},
		{
			name:    "missing parent address",
			input:   `Selection key: ABC=`,
			wantErr: true,
		},
		{
			name: "missing selection key",
			input: `Parent address: ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ2345
			Voting key: BBBB=`,
			wantErr: true,
		},
		{
			name: "missing voting key",
			input: `Parent address: ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ2345
			Selection key: AAAA=`,
			wantErr: true,
		},
		{
			name: "missing state proof key",
			input: `Parent address: ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ2345
			Selection key: AAAA=
			Voting key: BBBB=`,
			wantErr: true,
		},
		{
			name: "missing key dilution",
			input: `Parent address: ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ2345
			Selection key: AAAA=
			Voting key: BBBB=
			State proof key: CCCC=
			First round: 1000
			Last round: 2000`,
			wantErr: true,
		},
		{
			name: "missing round info",
			input: `Parent address: ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ2345
			Selection key: AAAA=
			Voting key: BBBB=
			State proof key: CCCC=
			Key dilution: 100`,
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := ParsePartKeyInfo(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePartKeyInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.check != nil {
				tt.check(t, info)
			}
		})
	}
}
