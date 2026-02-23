// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package repl

import (
	"bytes"
	"testing"
)

func TestParseLsigArg(t *testing.T) {
	tests := []struct {
		name      string
		token     string
		wantName  string
		wantValue []byte
		wantErr   bool
	}{
		{
			name:      "string value",
			token:     "arg:preimage=hello",
			wantName:  "preimage",
			wantValue: []byte("hello"),
		},
		{
			name:      "hex value",
			token:     "arg:preimage=0x68656c6c6f",
			wantName:  "preimage",
			wantValue: []byte("hello"),
		},
		{
			name:      "hex value that looks like a word",
			token:     "arg:preimage=0xCAFE",
			wantName:  "preimage",
			wantValue: []byte{0xca, 0xfe},
		},
		{
			name:      "string that looks like hex",
			token:     "arg:preimage=cafe",
			wantName:  "preimage",
			wantValue: []byte("cafe"),
		},
		{
			name:      "empty value",
			token:     "arg:preimage=",
			wantName:  "preimage",
			wantValue: []byte(""),
		},
		{
			name:      "empty hex value",
			token:     "arg:preimage=0x",
			wantName:  "preimage",
			wantValue: []byte(""),
		},
		{
			name:    "missing equals",
			token:   "arg:preimage",
			wantErr: true,
		},
		{
			name:    "invalid hex",
			token:   "arg:preimage=0xxyz",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, value, err := ParseLsigArg(tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseLsigArg() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if name != tt.wantName {
					t.Errorf("name = %v, want %v", name, tt.wantName)
				}
				if !bytes.Equal(value, tt.wantValue) {
					t.Errorf("value = %v, want %v", value, tt.wantValue)
				}
			}
		})
	}
}

func TestParseSendCommand(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantErr   bool
		checkFunc func(t *testing.T, p TransactionParams)
	}{
		{
			name:    "too few args",
			args:    []string{"1", "algo"},
			wantErr: true,
		},
		{
			name:    "missing from keyword",
			args:    []string{"1", "algo", "alice", "to", "bob"},
			wantErr: true,
		},
		{
			name:    "missing to keyword",
			args:    []string{"1", "algo", "from", "alice"},
			wantErr: true,
		},
		{
			name:    "basic send",
			args:    []string{"1", "algo", "from", "alice", "to", "bob"},
			wantErr: false,
			checkFunc: func(t *testing.T, p TransactionParams) {
				if p.Amount != "1" {
					t.Errorf("Amount = %v, want 1", p.Amount)
				}
				if p.Asset != "algo" {
					t.Errorf("Asset = %v, want algo", p.Asset)
				}
				if len(p.FromRaw) != 1 || p.FromRaw[0] != "alice" {
					t.Errorf("FromRaw = %v, want [alice]", p.FromRaw)
				}
				if len(p.ToRaw) != 1 || p.ToRaw[0] != "bob" {
					t.Errorf("ToRaw = %v, want [bob]", p.ToRaw)
				}
				if !p.Wait {
					t.Error("Wait should default to true")
				}
				if p.Atomic {
					t.Error("Atomic should default to false")
				}
			},
		},
		{
			name:    "send with nowait",
			args:    []string{"2.5", "usdc", "from", "alice", "to", "bob", "nowait"},
			wantErr: false,
			checkFunc: func(t *testing.T, p TransactionParams) {
				if p.Amount != "2.5" {
					t.Errorf("Amount = %v, want 2.5", p.Amount)
				}
				if p.Asset != "usdc" {
					t.Errorf("Asset = %v, want usdc", p.Asset)
				}
				if p.Wait {
					t.Error("Wait should be false with nowait flag")
				}
			},
		},
		{
			name:    "send atomic",
			args:    []string{"1", "algo", "from", "alice", "to", "bob", "atomic"},
			wantErr: false,
			checkFunc: func(t *testing.T, p TransactionParams) {
				if !p.Atomic {
					t.Error("Atomic should be true")
				}
			},
		},
		{
			name:    "send with note equals syntax",
			args:    []string{"1", "algo", "from", "alice", "to", "bob", "note=hello"},
			wantErr: false,
			checkFunc: func(t *testing.T, p TransactionParams) {
				if p.Note != "hello" {
					t.Errorf("Note = %v, want hello", p.Note)
				}
			},
		},
		{
			name:    "send with fee",
			args:    []string{"1", "algo", "from", "alice", "to", "bob", "fee=1000"},
			wantErr: false,
			checkFunc: func(t *testing.T, p TransactionParams) {
				if p.Fee != 1000 {
					t.Errorf("Fee = %v, want 1000", p.Fee)
				}
				if !p.UseFlatFee {
					t.Error("UseFlatFee should be true when fee is set")
				}
			},
		},
		{
			name:    "send with string arg",
			args:    []string{"1", "algo", "from", "alice", "to", "bob", "arg:preimage=hello"},
			wantErr: false,
			checkFunc: func(t *testing.T, p TransactionParams) {
				if !bytes.Equal(p.LsigArgs["preimage"], []byte("hello")) {
					t.Errorf("LsigArgs[preimage] = %v, want %v", p.LsigArgs["preimage"], []byte("hello"))
				}
			},
		},
		{
			name:    "send with hex arg",
			args:    []string{"1", "algo", "from", "alice", "to", "bob", "arg:preimage=0x68656c6c6f"},
			wantErr: false,
			checkFunc: func(t *testing.T, p TransactionParams) {
				if !bytes.Equal(p.LsigArgs["preimage"], []byte("hello")) {
					t.Errorf("LsigArgs[preimage] = %v, want %v", p.LsigArgs["preimage"], []byte("hello"))
				}
			},
		},
		{
			name:    "send with invalid fee",
			args:    []string{"1", "algo", "from", "alice", "to", "bob", "fee=invalid"},
			wantErr: true,
		},
		{
			name:    "send with multiple senders (bracketed)",
			args:    []string{"1", "algo", "from", "[alice", "bob", "charlie]", "to", "dave"},
			wantErr: false,
			checkFunc: func(t *testing.T, p TransactionParams) {
				if len(p.FromRaw) != 3 {
					t.Errorf("FromRaw count = %v, want 3", len(p.FromRaw))
				}
				if p.FromRaw[0] != "alice" || p.FromRaw[1] != "bob" || p.FromRaw[2] != "charlie" {
					t.Errorf("FromRaw = %v, want [alice bob charlie]", p.FromRaw)
				}
			},
		},
		{
			name:    "send with multiple receivers (bracketed)",
			args:    []string{"1", "algo", "from", "alice", "to", "[bob", "charlie]"},
			wantErr: false,
			checkFunc: func(t *testing.T, p TransactionParams) {
				if len(p.ToRaw) != 2 {
					t.Errorf("ToRaw count = %v, want 2", len(p.ToRaw))
				}
			},
		},
		{
			name:    "send with set reference",
			args:    []string{"1", "algo", "from", "alice", "to", "@friends"},
			wantErr: false,
			checkFunc: func(t *testing.T, p TransactionParams) {
				if len(p.ToRaw) != 1 || p.ToRaw[0] != "@friends" {
					t.Errorf("ToRaw = %v, want [@friends]", p.ToRaw)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := ParseSendCommand(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSendCommand() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.checkFunc != nil {
				tt.checkFunc(t, params)
			}
		})
	}
}

func TestParseOptinCommand(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantErr   bool
		checkFunc func(t *testing.T, p OptInParams)
	}{
		{
			name:    "too few args",
			args:    []string{"usdc"},
			wantErr: true,
		},
		{
			name:    "missing for keyword",
			args:    []string{"usdc", "alice"},
			wantErr: true,
		},
		{
			name:    "basic optin",
			args:    []string{"usdc", "for", "alice"},
			wantErr: false,
			checkFunc: func(t *testing.T, p OptInParams) {
				if p.ASARef != "usdc" {
					t.Errorf("ASARef = %v, want usdc", p.ASARef)
				}
				if p.From != "alice" {
					t.Errorf("From = %v, want alice", p.From)
				}
				if !p.Wait {
					t.Error("Wait should default to true")
				}
			},
		},
		{
			name:    "optin with nowait",
			args:    []string{"usdc", "for", "alice", "nowait"},
			wantErr: false,
			checkFunc: func(t *testing.T, p OptInParams) {
				if p.Wait {
					t.Error("Wait should be false with nowait flag")
				}
			},
		},
		{
			name:    "optin with fee",
			args:    []string{"usdc", "for", "alice", "fee=2000"},
			wantErr: false,
			checkFunc: func(t *testing.T, p OptInParams) {
				if p.Fee != 2000 {
					t.Errorf("Fee = %v, want 2000", p.Fee)
				}
				if !p.UseFlatFee {
					t.Error("UseFlatFee should be true when fee is set")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := ParseOptinCommand(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseOptinCommand() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.checkFunc != nil {
				tt.checkFunc(t, params)
			}
		})
	}
}

func TestParseOptoutCommand(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantErr   bool
		checkFunc func(t *testing.T, p OptOutParams)
	}{
		{
			name:    "too few args",
			args:    []string{"usdc"},
			wantErr: true,
		},
		{
			name:    "missing from keyword",
			args:    []string{"usdc", "alice"},
			wantErr: true,
		},
		{
			name:    "basic optout",
			args:    []string{"usdc", "from", "alice"},
			wantErr: false,
			checkFunc: func(t *testing.T, p OptOutParams) {
				if p.ASARef != "usdc" {
					t.Errorf("ASARef = %v, want usdc", p.ASARef)
				}
				if p.Account != "alice" {
					t.Errorf("Account = %v, want alice", p.Account)
				}
				if p.CloseTo != "" {
					t.Errorf("CloseTo = %v, want empty", p.CloseTo)
				}
				if !p.Wait {
					t.Error("Wait should default to true")
				}
			},
		},
		{
			name:    "optout with close-to",
			args:    []string{"usdc", "from", "alice", "to", "bob"},
			wantErr: false,
			checkFunc: func(t *testing.T, p OptOutParams) {
				if p.ASARef != "usdc" {
					t.Errorf("ASARef = %v, want usdc", p.ASARef)
				}
				if p.Account != "alice" {
					t.Errorf("Account = %v, want alice", p.Account)
				}
				if p.CloseTo != "bob" {
					t.Errorf("CloseTo = %v, want bob", p.CloseTo)
				}
			},
		},
		{
			name:    "optout with nowait",
			args:    []string{"usdc", "from", "alice", "nowait"},
			wantErr: false,
			checkFunc: func(t *testing.T, p OptOutParams) {
				if p.Wait {
					t.Error("Wait should be false with nowait flag")
				}
			},
		},
		{
			name:    "optout with fee",
			args:    []string{"usdc", "from", "alice", "fee=2000"},
			wantErr: false,
			checkFunc: func(t *testing.T, p OptOutParams) {
				if p.Fee != 2000 {
					t.Errorf("Fee = %v, want 2000", p.Fee)
				}
				if !p.UseFlatFee {
					t.Error("UseFlatFee should be true when fee is set")
				}
			},
		},
		{
			name:    "optout with close-to and all flags",
			args:    []string{"usdc", "from", "alice", "to", "bob", "fee=3000", "nowait"},
			wantErr: false,
			checkFunc: func(t *testing.T, p OptOutParams) {
				if p.Account != "alice" {
					t.Errorf("Account = %v, want alice", p.Account)
				}
				if p.CloseTo != "bob" {
					t.Errorf("CloseTo = %v, want bob", p.CloseTo)
				}
				if p.Fee != 3000 {
					t.Errorf("Fee = %v, want 3000", p.Fee)
				}
				if p.Wait {
					t.Error("Wait should be false with nowait flag")
				}
			},
		},
		{
			name:    "optout with ASA ID instead of name",
			args:    []string{"31566704", "from", "alice"},
			wantErr: false,
			checkFunc: func(t *testing.T, p OptOutParams) {
				if p.ASARef != "31566704" {
					t.Errorf("ASARef = %v, want 31566704", p.ASARef)
				}
			},
		},
		{
			name:    "invalid fee",
			args:    []string{"usdc", "from", "alice", "fee=invalid"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := ParseOptoutCommand(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseOptoutCommand() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.checkFunc != nil {
				tt.checkFunc(t, params)
			}
		})
	}
}

func TestParseCloseCommand(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantErr   bool
		checkFunc func(t *testing.T, p CloseParams)
	}{
		{
			name:    "too few args",
			args:    []string{"alice"},
			wantErr: true,
		},
		{
			name:    "missing to keyword",
			args:    []string{"alice", "bob"},
			wantErr: true,
		},
		{
			name:    "basic close",
			args:    []string{"alice", "to", "bob"},
			wantErr: false,
			checkFunc: func(t *testing.T, p CloseParams) {
				if p.Account != "alice" {
					t.Errorf("Account = %v, want alice", p.Account)
				}
				if p.CloseTo != "bob" {
					t.Errorf("CloseTo = %v, want bob", p.CloseTo)
				}
				if !p.Wait {
					t.Error("Wait should default to true")
				}
			},
		},
		{
			name:    "close with nowait",
			args:    []string{"alice", "to", "bob", "nowait"},
			wantErr: false,
			checkFunc: func(t *testing.T, p CloseParams) {
				if p.Wait {
					t.Error("Wait should be false with nowait flag")
				}
			},
		},
		{
			name:    "close with fee",
			args:    []string{"alice", "to", "bob", "fee=2000"},
			wantErr: false,
			checkFunc: func(t *testing.T, p CloseParams) {
				if p.Fee != 2000 {
					t.Errorf("Fee = %v, want 2000", p.Fee)
				}
				if !p.UseFlatFee {
					t.Error("UseFlatFee should be true when fee is set")
				}
			},
		},
		{
			name:    "close with all flags",
			args:    []string{"alice", "to", "bob", "fee=3000", "nowait"},
			wantErr: false,
			checkFunc: func(t *testing.T, p CloseParams) {
				if p.Account != "alice" {
					t.Errorf("Account = %v, want alice", p.Account)
				}
				if p.CloseTo != "bob" {
					t.Errorf("CloseTo = %v, want bob", p.CloseTo)
				}
				if p.Fee != 3000 {
					t.Errorf("Fee = %v, want 3000", p.Fee)
				}
				if p.Wait {
					t.Error("Wait should be false with nowait flag")
				}
			},
		},
		{
			name:    "close with full address",
			args:    []string{"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUV", "to", "ZYXWVUTSRQPONMLKJIHGFEDCBA765432ZYXWVUTSRQPONMLKJIHGFE"},
			wantErr: false,
			checkFunc: func(t *testing.T, p CloseParams) {
				if p.Account != "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUV" {
					t.Errorf("Account not set correctly")
				}
				if p.CloseTo != "ZYXWVUTSRQPONMLKJIHGFEDCBA765432ZYXWVUTSRQPONMLKJIHGFE" {
					t.Errorf("CloseTo not set correctly")
				}
			},
		},
		{
			name:    "invalid fee",
			args:    []string{"alice", "to", "bob", "fee=invalid"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := ParseCloseCommand(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCloseCommand() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.checkFunc != nil {
				tt.checkFunc(t, params)
			}
		})
	}
}

func TestParseRekeyCommand(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		isUnrekey bool
		wantErr   bool
		checkFunc func(t *testing.T, p RekeyParams)
	}{
		{
			name:      "rekey too few args",
			args:      []string{"alice"},
			isUnrekey: false,
			wantErr:   true,
		},
		{
			name:      "rekey missing to keyword",
			args:      []string{"alice", "bob", "charlie"},
			isUnrekey: false,
			wantErr:   true,
		},
		{
			name:      "basic rekey",
			args:      []string{"alice", "to", "bob"},
			isUnrekey: false,
			wantErr:   false,
			checkFunc: func(t *testing.T, p RekeyParams) {
				if p.Account != "alice" {
					t.Errorf("Account = %v, want alice", p.Account)
				}
				if p.Signer != "bob" {
					t.Errorf("Signer = %v, want bob", p.Signer)
				}
				if !p.Wait {
					t.Error("Wait should default to true")
				}
			},
		},
		{
			name:      "rekey with nowait",
			args:      []string{"alice", "to", "bob", "nowait"},
			isUnrekey: false,
			wantErr:   false,
			checkFunc: func(t *testing.T, p RekeyParams) {
				if p.Wait {
					t.Error("Wait should be false with nowait flag")
				}
			},
		},
		{
			name:      "rekey with fee",
			args:      []string{"alice", "to", "bob", "fee=3000"},
			isUnrekey: false,
			wantErr:   false,
			checkFunc: func(t *testing.T, p RekeyParams) {
				if p.Fee != 3000 {
					t.Errorf("Fee = %v, want 3000", p.Fee)
				}
				if !p.UseFlatFee {
					t.Error("UseFlatFee should be true when fee is set")
				}
			},
		},
		{
			name:      "unrekey too few args",
			args:      []string{},
			isUnrekey: true,
			wantErr:   true,
		},
		{
			name:      "basic unrekey",
			args:      []string{"alice"},
			isUnrekey: true,
			wantErr:   false,
			checkFunc: func(t *testing.T, p RekeyParams) {
				if p.Account != "alice" {
					t.Errorf("Account = %v, want alice", p.Account)
				}
				if p.Signer != "alice" {
					t.Errorf("Signer = %v, want alice (same as account for unrekey)", p.Signer)
				}
			},
		},
		{
			name:      "unrekey with nowait and fee",
			args:      []string{"alice", "nowait", "fee=1000"},
			isUnrekey: true,
			wantErr:   false,
			checkFunc: func(t *testing.T, p RekeyParams) {
				if p.Wait {
					t.Error("Wait should be false with nowait flag")
				}
				if p.Fee != 1000 {
					t.Errorf("Fee = %v, want 1000", p.Fee)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := ParseRekeyCommand(tt.args, tt.isUnrekey)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRekeyCommand() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.checkFunc != nil {
				tt.checkFunc(t, params)
			}
		})
	}
}

func TestParseTakeCommand(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantErr   bool
		checkFunc func(t *testing.T, p KeyRegParams)
	}{
		{
			name:    "too few args",
			args:    []string{"alice"},
			wantErr: true,
		},
		{
			name:    "invalid mode",
			args:    []string{"alice", "invalid"},
			wantErr: true,
		},
		{
			name:    "offline mode",
			args:    []string{"alice", "offline"},
			wantErr: false,
			checkFunc: func(t *testing.T, p KeyRegParams) {
				if p.From != "alice" {
					t.Errorf("From = %v, want alice", p.From)
				}
				if p.Online {
					t.Error("Online should be false for offline mode")
				}
				if p.Mode != "offline" {
					t.Errorf("Mode = %v, want offline", p.Mode)
				}
			},
		},
		{
			name:    "online mode missing keys",
			args:    []string{"alice", "online"},
			wantErr: true,
		},
		{
			name:    "online mode with keys",
			args:    []string{"alice", "online", "votekey=ABC", "selkey=DEF", "sproofkey=GHI"},
			wantErr: false,
			checkFunc: func(t *testing.T, p KeyRegParams) {
				if p.From != "alice" {
					t.Errorf("From = %v, want alice", p.From)
				}
				if !p.Online {
					t.Error("Online should be true")
				}
				if p.VoteKey != "ABC" {
					t.Errorf("VoteKey = %v, want ABC", p.VoteKey)
				}
				if p.SelKey != "DEF" {
					t.Errorf("SelKey = %v, want DEF", p.SelKey)
				}
				if p.SProofKey != "GHI" {
					t.Errorf("SProofKey = %v, want GHI", p.SProofKey)
				}
			},
		},
		{
			name:    "online mode with all options",
			args:    []string{"alice", "online", "votekey=ABC", "selkey=DEF", "sproofkey=GHI", "votefirst=100", "votelast=200", "keydilution=50", "eligible=true", "nowait"},
			wantErr: false,
			checkFunc: func(t *testing.T, p KeyRegParams) {
				if p.VoteFirst != 100 {
					t.Errorf("VoteFirst = %v, want 100", p.VoteFirst)
				}
				if p.VoteLast != 200 {
					t.Errorf("VoteLast = %v, want 200", p.VoteLast)
				}
				if p.KeyDilution != 50 {
					t.Errorf("KeyDilution = %v, want 50", p.KeyDilution)
				}
				if !p.IncentiveEligible {
					t.Error("IncentiveEligible should be true")
				}
				if p.Wait {
					t.Error("Wait should be false with nowait flag")
				}
			},
		},
		{
			name:    "unknown argument",
			args:    []string{"alice", "offline", "unknown=value"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := ParseTakeCommand(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseTakeCommand() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.checkFunc != nil {
				tt.checkFunc(t, params)
			}
		})
	}
}

func TestParseSweepCommand(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantErr   bool
		checkFunc func(t *testing.T, p SweepParams)
	}{
		{
			name:    "too few args",
			args:    []string{"algo"},
			wantErr: true,
		},
		{
			name:    "missing to keyword",
			args:    []string{"algo", "from", "alice"},
			wantErr: true,
		},
		{
			name:    "basic sweep without from (all signable)",
			args:    []string{"algo", "to", "treasury"},
			wantErr: false,
			checkFunc: func(t *testing.T, p SweepParams) {
				if p.Asset != "algo" {
					t.Errorf("Asset = %v, want algo", p.Asset)
				}
				if p.FromRaw != nil {
					t.Errorf("FromRaw = %v, want nil (all signable)", p.FromRaw)
				}
				if p.ToRaw != "treasury" {
					t.Errorf("ToRaw = %v, want treasury", p.ToRaw)
				}
				if p.Leaving != "0" {
					t.Errorf("Leaving = %v, want 0", p.Leaving)
				}
			},
		},
		{
			name:    "sweep with set reference",
			args:    []string{"usdc", "from", "@team", "to", "treasury"},
			wantErr: false,
			checkFunc: func(t *testing.T, p SweepParams) {
				if len(p.FromRaw) != 1 || p.FromRaw[0] != "@team" {
					t.Errorf("FromRaw = %v, want [@team]", p.FromRaw)
				}
			},
		},
		{
			name:    "sweep with bracket syntax",
			args:    []string{"algo", "from", "[", "alice", "bob", "]", "to", "treasury"},
			wantErr: false,
			checkFunc: func(t *testing.T, p SweepParams) {
				if len(p.FromRaw) != 2 {
					t.Errorf("FromRaw count = %v, want 2", len(p.FromRaw))
				}
				if p.FromRaw[0] != "alice" || p.FromRaw[1] != "bob" {
					t.Errorf("FromRaw = %v, want [alice bob]", p.FromRaw)
				}
			},
		},
		{
			name:    "sweep with leaving",
			args:    []string{"algo", "to", "treasury", "leaving", "1.5"},
			wantErr: false,
			checkFunc: func(t *testing.T, p SweepParams) {
				if p.Leaving != "1.5" {
					t.Errorf("Leaving = %v, want 1.5", p.Leaving)
				}
			},
		},
		{
			name:    "sweep with fee and nowait",
			args:    []string{"algo", "to", "treasury", "fee=2000", "nowait"},
			wantErr: false,
			checkFunc: func(t *testing.T, p SweepParams) {
				if p.Fee != 2000 {
					t.Errorf("Fee = %v, want 2000", p.Fee)
				}
				if !p.UseFlatFee {
					t.Error("UseFlatFee should be true when fee is set")
				}
				if p.Wait {
					t.Error("Wait should be false with nowait flag")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := ParseSweepCommand(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSweepCommand() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.checkFunc != nil {
				tt.checkFunc(t, params)
			}
		})
	}
}

func TestFindKeyword(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		keyword string
		want    int
	}{
		{
			name:    "keyword found",
			args:    []string{"1", "algo", "from", "alice", "to", "bob"},
			keyword: "from",
			want:    2,
		},
		{
			name:    "keyword not found",
			args:    []string{"1", "algo", "from", "alice"},
			keyword: "to",
			want:    -1,
		},
		{
			name:    "case insensitive",
			args:    []string{"1", "algo", "FROM", "alice"},
			keyword: "from",
			want:    2,
		},
		{
			name:    "empty args",
			args:    []string{},
			keyword: "from",
			want:    -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findKeyword(tt.args, tt.keyword)
			if got != tt.want {
				t.Errorf("findKeyword() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseAccountSet(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		startIdx   int
		wantErr    bool
		wantCount  int
		wantEndIdx int
	}{
		{
			name:       "valid set",
			args:       []string{"from", "[", "alice", "bob", "]", "to", "charlie"},
			startIdx:   1,
			wantErr:    false,
			wantCount:  2,
			wantEndIdx: 4,
		},
		{
			name:     "missing opening bracket",
			args:     []string{"from", "alice", "bob", "]"},
			startIdx: 1,
			wantErr:  true,
		},
		{
			name:     "missing closing bracket",
			args:     []string{"from", "[", "alice", "bob"},
			startIdx: 1,
			wantErr:  true,
		},
		{
			name:       "empty set",
			args:       []string{"from", "[", "]"},
			startIdx:   1,
			wantErr:    false,
			wantCount:  0,
			wantEndIdx: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accounts, endIdx, err := parseAccountSet(tt.args, tt.startIdx)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseAccountSet() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(accounts) != tt.wantCount {
					t.Errorf("parseAccountSet() count = %v, want %v", len(accounts), tt.wantCount)
				}
				if endIdx != tt.wantEndIdx {
					t.Errorf("parseAccountSet() endIdx = %v, want %v", endIdx, tt.wantEndIdx)
				}
			}
		})
	}
}

func TestParseUint64(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    uint64
		wantErr bool
	}{
		{"valid number", "12345", 12345, false},
		{"zero", "0", 0, false},
		{"large number", "999999999", 999999999, false},
		{"invalid string", "abc", 0, true},
		{"negative number", "-1", 0, true},
		// Note: parseUint64 uses fmt.Sscanf which parses "1" from "1.5", so it doesn't error
		{"float parses integer part", "1.5", 1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseUint64(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseUint64() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("parseUint64() = %v, want %v", got, tt.want)
			}
		})
	}
}
