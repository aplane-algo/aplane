// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/protocol"
	"github.com/chzyer/readline"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

const (
	keyregAlreadyEligibleLine = "Already incentive eligible: no incentive fee paid"
	keyregFeeLine             = "Incentive eligibility requested: 2 ALGO fee"
	keyregNotRequestedLine    = "Incentive eligibility not requested: ordinary fee"
)

// keyregNet is a network that reports eligible as incentive eligible and
// ineligible as not, with a signer for both that signs, or refuses when
// refuse is set, and records the fee of each transaction it is asked to sign.
type keyregNet struct {
	eligible, ineligible crypto.Account
	mu                   sync.Mutex
	fees                 []uint64
}

func keyregShell(t *testing.T, out *bytes.Buffer, refuse bool) (*REPLState, *keyregNet) {
	t.Helper()
	n := &keyregNet{eligible: crypto.GenerateAccount(), ineligible: crypto.GenerateAccount()}
	keys := map[string]crypto.Account{n.eligible.Address.String(): n.eligible, n.ineligible.Address.String(): n.ineligible}
	genesis, err := base64.StdEncoding.DecodeString(config.AlgorandTestnetGenesisHash)
	if err != nil {
		t.Fatal(err)
	}
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v2/transactions/params":
			_ = json.NewEncoder(w).Encode(models.TransactionParametersResponse{
				ConsensusVersion: string(protocol.ConsensusV43), MinFee: 1000, LastRound: 100,
				GenesisId: "testnet-v1.0", GenesisHash: genesis,
			})
		case strings.HasPrefix(r.URL.Path, "/v2/accounts/"):
			address := strings.TrimPrefix(r.URL.Path, "/v2/accounts/")
			_ = json.NewEncoder(w).Encode(models.Account{
				Address: address, Amount: 10_000_000, MinBalance: 100_000, Status: "Online",
				IncentiveEligible: address == n.eligible.Address.String(),
			})
		case r.URL.Path == "/v2/transactions" && r.Method == http.MethodPost:
			_ = json.NewEncoder(w).Encode(map[string]string{"txId": "KEYREGTX"})
		case r.URL.Path == "/v2/status":
			_ = json.NewEncoder(w).Encode(models.NodeStatus{LastRound: 100})
		case strings.HasPrefix(r.URL.Path, "/v2/transactions/pending/"):
			w.Header().Set("Content-Type", "application/msgpack")
			_, _ = w.Write(msgpack.Encode(models.PendingTransactionInfoResponse{ConfirmedRound: 101}))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(node.Close)
	signer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/keys":
			var infos []signerapi.KeyInfo
			for address := range keys {
				infos = append(infos, signerapi.KeyInfo{Address: address, KeyType: "ed25519"})
			}
			_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{Count: len(infos), Keys: infos})
		case r.Method == http.MethodPost && r.URL.Path == "/sign":
			var req signerapi.GroupSignRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			signed := make([]string, len(req.Requests))
			for i, item := range req.Requests {
				txn, err := txnutil.DecodePrefixedHex(item.TxnBytesHex)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				n.mu.Lock()
				n.fees = append(n.fees, uint64(txn.Fee))
				n.mu.Unlock()
				_, raw, err := signing.SignTransactionWithKey(keys[txn.Sender.String()].PrivateKey, txn)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				signed[i] = hex.EncodeToString(raw)
			}
			if refuse {
				http.Error(w, "test signer refuses", http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(w).Encode(signerapi.GroupSignResponse{Signed: signed})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(signer.Close)
	client, err := algod.MakeClient(node.URL, "")
	if err != nil {
		t.Fatalf("algod.MakeClient() error = %v", err)
	}
	eng, err := engine.NewEngine("testnet", engine.WithAlgodClient(client))
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	eng.Connection.SignerClient = signerclient.NewSignerClient(signer.URL)
	eng.SignerCache.Keys = map[string]string{}
	for address := range keys {
		eng.SignerCache.Keys[address] = "ed25519"
	}
	return &REPLState{Out: out, App: apshellapp.New(eng, config.DefaultConfig(), t.TempDir())}, n
}

func (n *keyregNet) signedFees() []uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]uint64(nil), n.fees...)
}

func keyregOnlineArgs(account string, eligible bool) []string {
	args := []string{account, "online",
		"votekey=tAtM0mBYE1p5k5KaHOvFYho09qEUEGWzaZs1dmBFWVQ=",
		"selkey=1+bzBrUVQDWDqcv4Iuv9uRYLp4DPViih4x2MGmKcYus=",
		"sproofkey=eS1o+ZVYZDkHBgFqhHAdF8Slyb190C+9aopj85xyUDB7342Pn02Fz2sUP+zGYC697vAWnZFT5SKExOG/PB+asQ==",
		"votefirst=1", "votelast=2000", "keydilution=1733", "nowait"}
	if eligible {
		args = append(args, "eligible=true")
	}
	return args
}

// The command's result says what the transaction carries for incentive
// eligibility, in its text after the submission and in its machine result.
func TestKeyregCommandReportsTheIncentiveFee(t *testing.T) {
	tests := []struct {
		name            string
		eligibleAccount bool
		requested       bool
		want            string // the incentive line, or "" for none
		wantFee         uint64
	}{
		{"requested, eligible already", true, true, keyregAlreadyEligibleLine, 1000},
		{"requested, not eligible yet", false, true, keyregFeeLine, 2_000_000},
		{"not requested, eligible already", true, false, "", 1000},
		{"not requested, not eligible", false, false, "", 1000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			state, n := keyregShell(t, &out, false)
			account := n.ineligible.Address.String()
			if tt.eligibleAccount {
				account = n.eligible.Address.String()
			}
			result, err := state.cmdKeyreg(keyregOnlineArgs(account, tt.requested), nil)
			if err != nil {
				t.Fatalf("cmdKeyreg() error = %v", err)
			}
			if fees := n.signedFees(); !slices.Equal(fees, []uint64{tt.wantFee}) {
				t.Fatalf("signed fees = %v, want [%d]", fees, tt.wantFee)
			}
			var text bytes.Buffer
			if err := result.RenderText(&text); err != nil {
				t.Fatalf("RenderText() error = %v", err)
			}
			var want []string
			if tt.want != "" {
				want = []string{tt.want}
			}
			if got := incentiveLines(text.String()); !slices.Equal(got, want) {
				t.Fatalf("incentive lines = %q, want %q", got, want)
			}
			if tt.want != "" && strings.Index(text.String(), tt.want) < strings.Index(text.String(), "Key registration submitted:") {
				t.Fatalf("the incentive line comes before the submission:\n%s", text.String())
			}

			machine, err := result.MarshalMachine()
			if err != nil {
				t.Fatalf("MarshalMachine() error = %v", err)
			}
			var projection keyRegProjection
			if err := json.Unmarshal(machine, &projection); err != nil {
				t.Fatalf("decode machine result %s: %v", machine, err)
			}
			if projection.IncentiveRequested != tt.requested ||
				projection.AlreadyIncentiveEligible != (tt.requested && tt.eligibleAccount) {
				t.Fatalf("machine result = %s", machine)
			}
		})
	}
}

// An agent reads the fee decision from the keyreg result.
func TestMCPKeyregResultCarriesTheIncentiveDecision(t *testing.T) {
	state, n := keyregShell(t, &bytes.Buffer{}, false)
	for account, want := range map[string]string{
		n.eligible.Address.String():   `"incentive_requested":true,"already_incentive_eligible":true`,
		n.ineligible.Address.String(): `"incentive_requested":true,"already_incentive_eligible":false`,
	} {
		result := mcpExecuteCommand(state, Command{Name: "keyreg", Args: keyregOnlineArgs(account, true)})
		if result.IsError {
			t.Fatalf("keyreg via MCP failed: %s", mcpResultText(t, result))
		}
		if got := mcpResultText(t, result); !strings.Contains(got, want) {
			t.Fatalf("MCP result = %s, want it to carry %s", got, want)
		}
	}
}

// A registration the signer refuses says nothing about the incentive fee: no
// transaction was submitted to carry it.
func TestKeyregRefusedSaysNothingOfTheIncentiveFee(t *testing.T) {
	var out bytes.Buffer
	state, n := keyregShell(t, &out, true)
	result, err := state.cmdKeyreg(keyregOnlineArgs(n.ineligible.Address.String(), true), nil)
	if err == nil || !strings.Contains(err.Error(), "key registration failed") || result != nil {
		t.Fatalf("cmdKeyreg() = %v, %v; want the signer's refusal", result, err)
	}
	if got := incentiveLines(out.String()); len(got) != 0 {
		t.Fatalf("incentive lines = %q, want none", got)
	}
}

func TestKeyregOfflineEligibleIsRefused(t *testing.T) {
	var out bytes.Buffer
	state, n := keyregShell(t, &out, false)
	_, err := state.cmdKeyreg([]string{n.eligible.Address.String(), "offline", "eligible=true"}, nil)
	if err == nil || !strings.Contains(err.Error(), "eligible applies only when going online") {
		t.Fatalf("cmdKeyreg() error = %v, want offline eligible refused", err)
	}
	if fees := n.signedFees(); len(fees) != 0 {
		t.Fatalf("the signer was asked to sign: fees %v", fees)
	}
}

// Paste mode asks, and once the registration is submitted says what its
// transaction carries; a refused one says nothing of it.
func TestKeyregPasteModeReportsTheIncentiveFee(t *testing.T) {
	tests := []struct {
		name            string
		eligibleAccount bool
		answer          string
		refuse          bool
		want            string // the incentive line, or "" for none
	}{
		{"yes, eligible already", true, "y", false, keyregAlreadyEligibleLine},
		{"yes, not eligible yet", false, "y", false, keyregFeeLine},
		{"no, eligible already", true, "n", false, keyregNotRequestedLine},
		{"no, not eligible", false, "n", false, keyregNotRequestedLine},
		{"yes, refused by the signer", false, "y", true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			state, n := keyregShell(t, &out, tt.refuse)
			account := n.ineligible.Address.String()
			if tt.eligibleAccount {
				account = n.eligible.Address.String()
			}
			lines := []string{
				"Parent address:    " + account,
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
			if tt.refuse != (err != nil) {
				t.Fatalf("keyRegPasteMode() error = %v, refused = %v", err, tt.refuse)
			}
			var want []string
			if tt.want != "" {
				want = []string{tt.want}
			}
			if got := incentiveLines(out.String()); !slices.Equal(got, want) {
				t.Fatalf("incentive lines = %q, want %q", got, want)
			}
			if tt.want != "" && strings.Index(out.String(), tt.want) < strings.Index(out.String(), "Key registration submitted:") {
				t.Fatalf("the incentive line comes before the submission:\n%s", out.String())
			}
		})
	}
}

// incentiveLines are the lines of out that report incentive eligibility.
func incentiveLines(out string) []string {
	var lines []string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(strings.ToLower(line), "incentive") {
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
				if prompt != "Request consensus incentive eligibility? (2 ALGO fee unless already eligible) [y/N]: " {
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
