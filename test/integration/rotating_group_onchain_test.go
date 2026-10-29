// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/internal/signerapp/chainread"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	ed25519signerreg "github.com/aplane-algo/aplane/internal/signing/ed25519/signerreg"
	"github.com/aplane-algo/aplane/internal/stagetable"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/txnutil"
	rotatingslhsignerreg "github.com/aplane-algo/aplane/lsig/rotatingtripleslhdsa/signerreg"
	"github.com/aplane-algo/aplane/pkg/signerapi"
	"github.com/aplane-algo/aplane/test/integration/harness"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	sdkcrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

var localnetSlhdsa = localnetRotatingType{
	keyType: rotatingkey.RotatingTripleSlhdsaV1, register: rotatingslhsignerreg.Register, newKeyPayload: rotatingslhsignerreg.NewKeyPayload,
}

// groupKeyStore serves the rotating account's seed and the held ordinary
// accounts' ed25519 keys.
type groupKeyStore struct {
	rotating *rotatingSeedStore
	address  string
	ordinary map[string]sdkcrypto.Account
}

func (s *groupKeyStore) Get(ctx context.Context, address string) (*coresigning.KeyMaterial, error) {
	if account, ok := s.ordinary[address]; ok {
		clone, err := sdkcrypto.AccountFromPrivateKey(bytes.Clone(account.PrivateKey))
		if err != nil {
			return nil, err
		}
		return &coresigning.KeyMaterial{Type: "ed25519", Category: keys.CategoryEd25519, Value: clone}, nil
	}
	return s.rotating.Get(ctx, address)
}

// rotatingGroupHarness is the signer's rotating service on LocalNet with one
// rotating account and a set of ordinary accounts it holds.
type rotatingGroupHarness struct {
	t        *testing.T
	testnet  *harness.TestnetConfig
	funder   *harness.FundTestAccount
	svc      *signersigning.Service
	session  *keystore.KeySession
	releases *signersigning.ReleaseMemory
	address  string
	account  types.Address
	genesis  [rotatinghybrid.GenesisHashSize]byte
	secret   *coresigning.RotatingKeyMaterial
	stageOps coresigning.RotatingStageOps
	store    *groupKeyStore
	held     map[string]bool
}

var registerGroupSigner sync.Once

func newRotatingGroupHarness(t *testing.T, kind localnetRotatingType) *rotatingGroupHarness {
	t.Helper()
	registerGroupSigner.Do(ed25519signerreg.RegisterSigner)
	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Fatalf("funding account: %v", err)
	}
	kind.register()
	sp, err := testnet.GetSuggestedParams()
	if err != nil {
		t.Fatal(err)
	}
	h := &rotatingGroupHarness{t: t, testnet: testnet, funder: funder, held: map[string]bool{}}
	copy(h.genesis[:], sp.GenesisHash)
	var seed rotatinghybrid.Seed
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(seed.Zero)
	payload, address, err := kind.newKeyPayload(&seed, h.genesis)
	if err != nil {
		t.Fatal(err)
	}
	payload.ZeroSecrets()
	h.address = address
	h.account, _ = types.DecodeAddress(address)
	if err := funder.FundMicroAlgosAndWait(address, 1_000_000); err != nil {
		t.Fatalf("fund rotating account: %v", err)
	}
	rk, _ := rotatingkey.Lookup(kind.keyType)
	argumentBytes := uint64(rk.MaxArgumentBytes)
	profile, err := lsigresource.Materialize(uint64(rk.MaxProgramBytes), &argumentBytes, nil,
		lsigresource.DefaultOpcodeProfile(uint64(rk.MaxOpcodeCost)))
	if err != nil {
		t.Fatal(err)
	}
	h.stageOps, err = coresigning.GetRotatingStageOps(kind.keyType)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := apconfig.NewGenesisHashNetworkResolver(map[string]string{
		base64.StdEncoding.EncodeToString(h.genesis[:]): "itestnet",
	})
	if err != nil {
		resolver = apconfig.DefaultGenesisHashNetworkResolver()
	}
	reader := chainread.Reader{
		Resolver: func() apconfig.GenesisHashNetworkResolver { return resolver },
		AlgodConfig: func(string) (*apconfig.AlgodNetworkConfig, error) {
			return &apconfig.AlgodNetworkConfig{Server: testnet.AlgodURL, Token: testnet.AlgodToken}, nil
		},
		MakeClient: func(server, token string) (*algod.Client, error) { return algod.MakeClient(server, token) },
	}
	h.store = &groupKeyStore{
		rotating: &rotatingSeedStore{keyType: kind.keyType, seed: bytes.Clone(seed[:]), genesis: h.genesis[:]},
		address:  address,
		ordinary: map[string]sdkcrypto.Account{},
	}
	h.session = keystore.NewKeySession(h.store)
	h.session.InitializeSession()
	approve := true
	h.releases = &signersigning.ReleaseMemory{}
	h.svc = &signersigning.Service{
		Planner: &signersigning.Planner{GenesisHashResolver: resolver, Snapshot: func() signersigning.PlannerRuntimeSnapshot {
			snap := signersigning.PlannerRuntimeSnapshot{
				KeyFiles:    map[string]string{address: "keys/" + address + ".key"},
				KeyTypes:    map[string]string{address: kind.keyType},
				KeyMetadata: map[string]signersigning.PlannerKeyMetadata{address: {Category: keys.CategoryRotatingLsig, LogicSigResources: &profile}},
			}
			for held := range h.held {
				snap.KeyFiles[held] = "keys/" + held + ".key"
				snap.KeyTypes[held] = "ed25519"
				snap.KeyMetadata[held] = signersigning.PlannerKeyMetadata{Category: keys.CategoryEd25519}
			}
			return snap
		}},
		Approval:                      &signersigning.ApprovalService{UserAutoApprove: &approve},
		Executor:                      &signersigning.Executor{DecodeRuntimeArgs: signersigning.DecodeHexRuntimeArgs},
		GenerateTxnDescriptionFromTxn: func(types.Transaction) string { return "rotating group member" },
		IsUnlocked:                    func() bool { return true },
		PolicyFor:                     func(string) *policy.Config { return policy.DefaultConfig() },
		Rotating: &signersigning.RotatingDeps{
			Chain:    reader,
			Tables:   stagetable.NewStore(storepaths.NewPaths(t.TempDir())),
			Locks:    &signersigning.RotatingLocks{},
			Releases: h.releases,
		},
	}
	h.secret = &coresigning.RotatingKeyMaterial{Seed: bytes.Clone(seed[:]), GenesisHash: h.genesis[:]}
	t.Cleanup(h.secret.Zero)
	return h
}

// holdAccount funds a fresh ed25519 account and gives its key to the signer.
func (h *rotatingGroupHarness) holdAccount(funding uint64) sdkcrypto.Account {
	h.t.Helper()
	account := sdkcrypto.GenerateAccount()
	if err := h.funder.FundMicroAlgosAndWait(account.Address.String(), funding); err != nil {
		h.t.Fatalf("fund held account: %v", err)
	}
	h.store.ordinary[account.Address.String()] = account
	h.held[account.Address.String()] = true
	return account
}

// header is a transaction header on the current round with the given
// window length, the same for every member of a rotating group.
func (h *rotatingGroupHarness) header(sender types.Address, window uint64) types.Header {
	h.t.Helper()
	sp, err := h.testnet.GetSuggestedParams()
	if err != nil {
		h.t.Fatal(err)
	}
	return types.Header{
		Sender: sender, Fee: types.MicroAlgos(sp.MinFee),
		FirstValid: sp.FirstRoundValid, LastValid: sp.FirstRoundValid + types.Round(window),
		GenesisID: sp.GenesisID, GenesisHash: h.genesis,
	}
}

func (h *rotatingGroupHarness) prepare(requests []signerapi.SignRequest) *signerapi.RotatingPrepareResponse {
	h.t.Helper()
	prep, svcErr := h.svc.PrepareRotatingWithContext(context.Background(), signerapi.RotatingPrepareRequest{Account: h.address, Requests: requests}, h.session)
	if svcErr != nil {
		h.t.Fatalf("prepare: %v", svcErr)
	}
	return prep
}

func (h *rotatingGroupHarness) sign(prep *signerapi.RotatingPrepareResponse, sent []signerapi.SignRequest) *signerapi.RotatingSignResponse {
	h.t.Helper()
	requests := make([]signerapi.SignRequest, len(sent))
	for i := range sent {
		requests[i] = sent[i]
		requests[i].TxnBytesHex = prep.Transactions[i]
	}
	signed, svcErr := h.svc.SignRotatingWithContext(context.Background(), signerapi.RotatingSignRequest{Account: h.address, Requests: requests}, h.session)
	if svcErr != nil {
		h.t.Fatalf("sign: %v", svcErr)
	}
	return signed
}

func (h *rotatingGroupHarness) submit(signed *signerapi.RotatingSignResponse) error {
	h.t.Helper()
	var raw bytes.Buffer
	for _, s := range signed.Signed {
		b, err := hex.DecodeString(s)
		if err != nil {
			h.t.Fatal(err)
		}
		raw.Write(b)
	}
	_, err := h.testnet.Client.SendRawTransaction(raw.Bytes()).Do(context.Background())
	return err
}

func (h *rotatingGroupHarness) authorizerIs(stage uint64) {
	h.t.Helper()
	want, err := h.stageOps.StageAddress(h.secret, stage)
	if err != nil {
		h.t.Fatal(err)
	}
	info, err := h.testnet.Client.AccountInformation(h.address).Do(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	// Stage 0's program address is the account itself: the chain reports
	// no authorizer until the first rotation lands.
	wantAuth := want.String()
	if want == h.account {
		wantAuth = ""
	}
	if info.AuthAddr != wantAuth {
		h.t.Fatalf("authorizer %q, want stage %d %s", info.AuthAddr, stage, want)
	}
}

func (h *rotatingGroupHarness) balance(addr types.Address) uint64 {
	h.t.Helper()
	info, err := h.testnet.Client.AccountInformation(addr.String()).Do(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	return info.Amount
}

func (h *rotatingGroupHarness) rotatingSpend(window uint64, receiver types.Address, amount uint64) types.Transaction {
	return types.Transaction{Type: types.PaymentTx, Header: h.header(h.account, window),
		PaymentTxnFields: types.PaymentTxnFields{Receiver: receiver, Amount: types.MicroAlgos(amount)}}
}

func groupRequests(txns ...types.Transaction) []signerapi.SignRequest {
	out := make([]signerapi.SignRequest, len(txns))
	for i, txn := range txns {
		out[i] = signerapi.SignRequest{TxnBytesHex: txnutil.EncodeWithPrefixHex(txn)}
	}
	return out
}

func TestRotatingTripleOwnedGroupOnChain(t *testing.T) {
	runRotatingOwnedGroupOnChain(t, localnetTriple)
}
func TestRotatingXmssOwnedGroupOnChain(t *testing.T) { runRotatingOwnedGroupOnChain(t, localnetXmss) }
func TestRotatingSlhdsaOwnedGroupOnChain(t *testing.T) {
	runRotatingOwnedGroupOnChain(t, localnetSlhdsa)
}

// runRotatingOwnedGroupOnChain groups a held hot account's payment with a
// rotating spend, the rotating spend second, and lands it; then signs an
// owned slot whose sender has no credential of its own, through the held
// key it is rekeyed to.
func runRotatingOwnedGroupOnChain(t *testing.T, kind localnetRotatingType) {
	h := newRotatingGroupHarness(t, kind)
	funderAddr, _ := types.DecodeAddress(h.funder.GetAddress())
	hot := h.holdAccount(1_000_000)

	hotPay := types.Transaction{Type: types.PaymentTx, Header: h.header(hot.Address, 100),
		PaymentTxnFields: types.PaymentTxnFields{Receiver: funderAddr, Amount: 2000}}
	spend := h.rotatingSpend(100, funderAddr, 1000)
	spend.Header = hotPay.Header
	spend.Sender = h.account
	sent := groupRequests(hotPay, spend)
	before := h.balance(hot.Address)
	prep := h.prepare(sent)
	if prep.Rotations[0].Index != 1 || len(prep.OwnedIndexes) != 1 {
		t.Fatalf("prepared rotations %+v owned %v", prep.Rotations, prep.OwnedIndexes)
	}
	signed := h.sign(prep, sent)
	if err := h.submit(signed); err != nil {
		t.Fatalf("submit owned group: %v", err)
	}
	if _, err := h.testnet.WaitForConfirmation(signed.TxID, 10); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	h.authorizerIs(1)
	if after := h.balance(hot.Address); before-after < 2000 {
		t.Fatalf("hot account balance moved %d, want at least the 2000 payment", before-after)
	}
	t.Logf("%s: group of %d landed; hot paid, account rotated to stage 1", kind.keyType, len(signed.Signed))

	// An account rekeyed on chain to the held hot key, with no credential
	// of its own, joins the group through its auth_address.
	rekeyed := sdkcrypto.GenerateAccount()
	if err := h.funder.FundMicroAlgosAndWait(rekeyed.Address.String(), 500_000); err != nil {
		t.Fatal(err)
	}
	rekeyTxn := types.Transaction{Type: types.PaymentTx, Header: h.header(rekeyed.Address, 100),
		PaymentTxnFields: types.PaymentTxnFields{Receiver: rekeyed.Address}}
	rekeyTxn.RekeyTo = hot.Address
	txid, raw, err := coresigning.SignTransactionWithKey(rekeyed.PrivateKey, rekeyTxn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.testnet.Client.SendRawTransaction(raw).Do(context.Background()); err != nil {
		t.Fatalf("rekey to the hot key: %v", err)
	}
	if _, err := h.testnet.WaitForConfirmation(txid, 10); err != nil {
		t.Fatal(err)
	}
	fromRekeyed := types.Transaction{Type: types.PaymentTx, Header: h.header(rekeyed.Address, 100),
		PaymentTxnFields: types.PaymentTxnFields{Receiver: funderAddr, Amount: 3000}}
	second := h.rotatingSpend(100, funderAddr, 1000)
	second.Header = fromRekeyed.Header
	second.Sender = h.account
	sent = groupRequests(fromRekeyed, second)
	sent[0].AuthAddress = hot.Address.String()
	signed = h.sign(h.prepare(sent), sent)
	if err := h.submit(signed); err != nil {
		t.Fatalf("submit group with a rekeyed owned sender: %v", err)
	}
	if _, err := h.testnet.WaitForConfirmation(signed.TxID, 10); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	h.authorizerIs(2)
}

// gatedApproval approves a no-argument call only while global "open" is 1;
// the creator sets "open" with one integer argument. It is the owned slot's
// outside state that can change between simulation and submission.
const gatedApproval = `#pragma version 10
txn ApplicationID
bz create
txn OnCompletion
int DeleteApplication
==
bnz delete
txn NumAppArgs
bnz set
byte "open"
app_global_get
return
set:
txn Sender
global CreatorAddress
==
assert
byte "open"
txna ApplicationArgs 0
btoi
app_global_put
int 1
return
create:
byte "open"
int 1
app_global_put
int 1
return
delete:
txn Sender
global CreatorAddress
==
return
`

const gatedClear = "#pragma version 10\nint 1\n"

func TestRotatingTripleOwnedGroupFailsAfterRelease(t *testing.T) {
	runRotatingOwnedGroupFailsAfterRelease(t, localnetTriple)
}

func TestRotatingSlhdsaOwnedGroupFailsAfterRelease(t *testing.T) {
	runRotatingOwnedGroupFailsAfterRelease(t, localnetSlhdsa)
}

// runRotatingOwnedGroupFailsAfterRelease is the residual risk the group
// form adds: the signer releases a valid, simulated group, then outside
// state changes so an owned slot fails. The held group is rejected whole,
// the rotating account stays on its stage with the release remembered, the
// expired release is reported, and a rotate-only spend from the same stage
// recovers. The state change is sequenced, not raced.
func runRotatingOwnedGroupFailsAfterRelease(t *testing.T, kind localnetRotatingType) {
	h := newRotatingGroupHarness(t, kind)
	hot := h.holdAccount(1_000_000)
	app, err := harness.DeployTEALApp(t, h.testnet.Client, h.funder, []byte(gatedApproval), []byte(gatedClear),
		types.StateSchema{NumUint: 1}, types.StateSchema{})
	if err != nil {
		t.Fatalf("deploy gated app: %v", err)
	}
	t.Cleanup(func() { _ = harness.DestroyApp(t, h.testnet.Client, app.AppID, h.funder) })

	// A short window, so the release expires within the test.
	const window = 12
	header := h.header(hot.Address, window)
	call, err := transaction.MakeApplicationNoOpTx(app.AppID, nil, nil, nil, nil,
		types.SuggestedParams{Fee: header.Fee, FirstRoundValid: header.FirstValid, LastRoundValid: header.LastValid,
			GenesisID: header.GenesisID, GenesisHash: header.GenesisHash[:], FlatFee: true},
		hot.Address, nil, types.Digest{}, [32]byte{}, types.Address{})
	if err != nil {
		t.Fatal(err)
	}
	spend := types.Transaction{Type: types.PaymentTx, Header: header,
		PaymentTxnFields: types.PaymentTxnFields{Receiver: h.account, Amount: 0}}
	spend.Sender = h.account
	sent := groupRequests(call, spend)
	prep := h.prepare(sent)

	// Simulate the exact unsigned group, as the client does before sign.
	unsigned := make([]types.Transaction, len(prep.Transactions))
	for i, txHex := range prep.Transactions {
		unsigned[i], err = txnutil.DecodePrefixedHex(txHex)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, simErr := coresigning.SimulateUnsignedTransactionsWithContext(context.Background(), unsigned, h.testnet.Client, &bytes.Buffer{}); simErr != nil {
		t.Fatalf("the prepared group must simulate before the state change: %v", simErr)
	}
	signed := h.sign(prep, sent)
	stageZero, _ := h.stageOps.StageAddress(h.secret, 0)

	// Close the gate and wait for that to confirm before submitting.
	if err := app.CallMethod([][]byte{harness.EncodeUint64(0)}, h.funder, nil); err != nil {
		t.Fatalf("close the gate: %v", err)
	}
	err = h.submit(signed)
	if err == nil {
		t.Fatal("the held group landed although its owned app call now rejects")
	}
	if msg := strings.ToLower(err.Error()); !strings.Contains(msg, "rejected") && !strings.Contains(msg, "logic eval") {
		t.Fatalf("held group refused for an unexpected reason: %v", err)
	}
	h.authorizerIs(0)
	rec, ok := h.releases.Get(h.address)
	if !ok || rec.Stage != 0 || rec.TxID != signed.TxID || rec.StageAddr != stageZero {
		t.Fatalf("release memory after the rejected group = %+v, %v; want the stage 0 release kept", rec, ok)
	}

	// Let the window pass, then the fill pass reports the expired release
	// whose keys still control the account.
	for round := currentRound(t, h.testnet.Client); round <= uint64(header.LastValid); round = currentRound(t, h.testnet.Client) {
		advanceOneRound(t, h)
	}
	reports := h.svc.FillStageTables(context.Background(), h.session, signersigning.StageFillOptions{Horizon: 2})
	warnings, _ := h.svc.RotatingStatus(reports)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "expired") || !strings.Contains(warnings[0], signed.TxID) {
		t.Fatalf("status warnings after the window = %v, want the expired release of %s", warnings, signed.TxID)
	}

	// Same-stage recovery: a rotate-only spend from stage 0 lands.
	recovery := h.rotatingSpend(100, h.account, 0)
	recoverySent := groupRequests(recovery)
	recovered := h.sign(h.prepare(recoverySent), recoverySent)
	if recovered.Stage != 0 {
		t.Fatalf("recovery released stage %d, want stage 0 again", recovered.Stage)
	}
	if err := h.submit(recovered); err != nil {
		t.Fatalf("submit the rotate-only recovery: %v", err)
	}
	if _, err := h.testnet.WaitForConfirmation(recovered.TxID, 10); err != nil {
		t.Fatalf("confirm the recovery: %v", err)
	}
	h.authorizerIs(1)
}

func currentRound(t *testing.T, client *algod.Client) uint64 {
	t.Helper()
	status, err := client.Status().Do(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return status.LastRound
}

// advanceOneRound confirms a zero payment from the funder to itself, which
// moves a LocalNet in dev mode forward and waits a round on any other.
func advanceOneRound(t *testing.T, h *rotatingGroupHarness) {
	t.Helper()
	sp, err := h.testnet.GetSuggestedParams()
	if err != nil {
		t.Fatal(err)
	}
	note := make([]byte, 8)
	if _, err := rand.Read(note); err != nil {
		t.Fatal(err)
	}
	addr := h.funder.GetAddress()
	txn, err := transaction.MakePaymentTxn(addr, addr, 0, note, "", sp)
	if err != nil {
		t.Fatal(err)
	}
	txid, raw, err := h.funder.PrepareAndSignTransaction(txn, sp.MinFee)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.testnet.Client.SendRawTransaction(raw).Do(context.Background()); err != nil {
		t.Fatal(fmt.Errorf("advance a round: %w", err))
	}
	if _, err := h.testnet.WaitForConfirmation(txid, 10); err != nil {
		t.Fatal(err)
	}
}
