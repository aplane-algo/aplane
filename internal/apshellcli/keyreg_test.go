// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/protocol"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/chzyer/readline"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
)

var (
	keyregEligible   = types.Address{41}.String()
	keyregIneligible = types.Address{42}.String()
)

const (
	keyregAlreadyEligibleLine = "✓ Account is already incentive eligible (will maintain eligibility)"
	keyregNoAdditionalFeeLine = "✓ Account is already incentive eligible (will maintain eligibility, no additional fee)"
	keyregFeeLine             = "✓ Consensus incentive eligibility enabled (2 ALGO fee)"
	keyregDisabledLine        = "  Consensus incentive eligibility disabled (standard fee)"
)

// keyregShell is a shell whose network reports keyregEligible as incentive
// eligible, and which has no signer: a keyreg is prepared, and signing it
// fails.
func keyregShell(t *testing.T, out *bytes.Buffer) *REPLState {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v2/transactions/params":
			_ = json.NewEncoder(w).Encode(models.TransactionParametersResponse{
				ConsensusVersion: string(protocol.ConsensusV43), MinFee: 1000, LastRound: 100,
				GenesisId: "testnet-v1.0", GenesisHash: make([]byte, 32),
			})
		case strings.HasPrefix(r.URL.Path, "/v2/accounts/"):
			address := strings.TrimPrefix(r.URL.Path, "/v2/accounts/")
			_ = json.NewEncoder(w).Encode(models.Account{
				Address: address, Amount: 10_000_000, MinBalance: 100_000, Status: "Online",
				IncentiveEligible: address == keyregEligible,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	client, err := algod.MakeClient(server.URL, "")
	if err != nil {
		t.Fatalf("algod.MakeClient() error = %v", err)
	}
	eng, err := engine.NewEngine("testnet", engine.WithAlgodClient(client))
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	eng.SignerCache.Keys = map[string]string{keyregEligible: "ed25519", keyregIneligible: "ed25519"}
	return &REPLState{Out: out, App: apshellapp.New(eng, config.DefaultConfig(), t.TempDir())}
}

// The command says what the registration decided about incentive
// eligibility, before it is signed: signing fails here.
func TestKeyregCommandReportsTheIncentiveDecision(t *testing.T) {
	tests := []struct {
		name     string
		account  string
		eligible bool
		want     string // the incentive line, or "" for none
	}{
		{"requested, eligible already", keyregEligible, true, keyregNoAdditionalFeeLine},
		{"not requested, eligible already", keyregEligible, false, keyregAlreadyEligibleLine},
		{"requested, not eligible yet", keyregIneligible, true, keyregFeeLine},
		{"not requested, not eligible", keyregIneligible, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			state := keyregShell(t, &out)
			args := []string{tt.account, "online",
				"votekey=tAtM0mBYE1p5k5KaHOvFYho09qEUEGWzaZs1dmBFWVQ=",
				"selkey=1+bzBrUVQDWDqcv4Iuv9uRYLp4DPViih4x2MGmKcYus=",
				"sproofkey=eS1o+ZVYZDkHBgFqhHAdF8Slyb190C+9aopj85xyUDB7342Pn02Fz2sUP+zGYC697vAWnZFT5SKExOG/PB+asQ==",
				"votefirst=1", "votelast=2000", "keydilution=1733"}
			if tt.eligible {
				args = append(args, "eligible=true")
			}
			_, err := state.cmdKeyreg(args, nil)
			if err == nil || !strings.Contains(err.Error(), "key registration failed") {
				t.Fatalf("cmdKeyreg() error = %v, want signing to fail", err)
			}
			var want []string
			if tt.want != "" {
				want = []string{tt.want}
			}
			if got := incentiveLines(out.String()); !slices.Equal(got, want) {
				t.Fatalf("incentive lines = %q, want %q", got, want)
			}
		})
	}
}

func TestKeyregOfflineEligibleIsRefusedWithoutAnIncentiveLine(t *testing.T) {
	var out bytes.Buffer
	state := keyregShell(t, &out)
	_, err := state.cmdKeyreg([]string{keyregEligible, "offline", "eligible=true"}, nil)
	if err == nil || !strings.Contains(err.Error(), "eligible applies only when going online") {
		t.Fatalf("cmdKeyreg() error = %v, want offline eligible refused", err)
	}
	if got := incentiveLines(out.String()); len(got) != 0 {
		t.Fatalf("incentive lines = %q, want none", got)
	}
}

// Paste mode asks, and then says what the registration decided.
func TestKeyregPasteModeReportsTheIncentiveDecision(t *testing.T) {
	tests := []struct {
		name    string
		account string
		answer  string
		want    string
	}{
		{"yes, eligible already", keyregEligible, "y", keyregNoAdditionalFeeLine},
		{"no, eligible already", keyregEligible, "n", keyregNoAdditionalFeeLine},
		{"yes, not eligible yet", keyregIneligible, "y", keyregFeeLine},
		{"no, not eligible", keyregIneligible, "n", keyregDisabledLine},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			state := keyregShell(t, &out)
			lines := []string{
				"Parent address:    " + tt.account,
				"Selection key:     1+bzBrUVQDWDqcv4Iuv9uRYLp4DPViih4x2MGmKcYus=",
				"Voting key:        tAtM0mBYE1p5k5KaHOvFYho09qEUEGWzaZs1dmBFWVQ=",
				"State proof key:   eS1o+ZVYZDkHBgFqhHAdF8Slyb190C+9aopj85xyUDB7342Pn02Fz2sUP+zGYC697vAWnZFT5SKExOG/PB+asQ==",
				"Key dilution:      1733",
				"First round:       1",
				"Last round:        2000",
				"", "",
				tt.answer,
			}
			state.LineReaderContext = func(context.Context) (string, error) {
				if len(lines) == 0 {
					t.Fatal("read past the scripted input")
				}
				line := lines[0]
				lines = lines[1:]
				return line, nil
			}

			err := state.keyRegPasteMode()
			if err == nil || !strings.Contains(err.Error(), "key registration failed") {
				t.Fatalf("keyRegPasteMode() error = %v, want signing to fail", err)
			}
			if got := incentiveLines(out.String()); !slices.Equal(got, []string{tt.want}) {
				t.Fatalf("incentive lines = %q, want %q", got, tt.want)
			}
		})
	}
}

// incentiveLines are the lines of out that report incentive eligibility.
func incentiveLines(out string) []string {
	var lines []string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "incentive eligib") {
			lines = append(lines, line)
		}
	}
	return lines
}

func TestKeyRegPasteModeUsesContextInteractiveLineReader(t *testing.T) {
	reads := 0
	state := &REPLState{
		Out: &bytes.Buffer{},
		LineReaderContext: func(context.Context) (string, error) {
			reads++
			return "", nil
		},
	}

	err := state.keyRegPasteMode()
	if err == nil || !strings.Contains(err.Error(), "no input provided") {
		t.Fatalf("keyRegPasteMode() error = %v, want no input", err)
	}
	if reads != 2 {
		t.Fatalf("context reader calls = %d, want 2", reads)
	}
}

func TestIncentiveEligibilityUsesEmbeddedPromptAndPropagatesCancellation(t *testing.T) {
	for _, promptErr := range []error{context.Canceled, readline.ErrInterrupt, io.EOF} {
		t.Run(promptErr.Error(), func(t *testing.T) {
			var out bytes.Buffer
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			state := &REPLState{Out: &out, currentCommandCtx: ctx}
			session := &Session{state: state}
			prompted := false
			session.SetInteractiveLinePromptContext(func(gotCtx context.Context, prompt string) (string, error) {
				prompted = true
				if gotCtx != ctx {
					t.Fatal("prompt did not receive the command context")
				}
				if prompt != "Enable consensus incentive eligibility? (2 ALGO fee) [y/N]: " {
					t.Fatalf("unexpected prompt: %q", prompt)
				}
				return "", promptErr
			})

			// Cancellation must return before querying eligibility or submitting
			// a transaction; deliberately supply no application for either step.
			requested, err := askIncentiveEligibility(state)
			if !prompted || !errors.Is(err, promptErr) || requested {
				t.Fatalf("prompted=%v, requested=%v, err=%v", prompted, requested, err)
			}
			if out.Len() != 0 {
				t.Fatalf("prompt written to captured output instead of host UI: %q", out.String())
			}
		})
	}
}
