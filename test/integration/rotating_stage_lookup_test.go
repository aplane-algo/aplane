// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

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
	"github.com/aplane-algo/aplane/internal/stagetable"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/txnutil"
	rotatingwotscsignerreg "github.com/aplane-algo/aplane/lsig/rotatingtriplewotsc/signerreg"
	"github.com/aplane-algo/aplane/pkg/signerapi"
	"github.com/aplane-algo/aplane/test/integration/harness"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// defaultLocalnetIndexerURL is AlgoKit LocalNet's Indexer, which shares the
// LocalNet token.
const defaultLocalnetIndexerURL = "http://localhost:8980"

// TestRotatingStageLookupOnChain resolves a rotating account's stage on a
// signer that has only the seed, through LocalNet's Indexer: the stage table
// worker reads the account's last confirmed rekey, tries the stage it names,
// and finds it after one derivation. Without an Indexer, or with one that
// cannot be reached, the same account resolves through the ordinary search,
// and a spend signed but never submitted does not move the candidate. One
// key type is enough, and WOTS+C derives fastest.
func TestRotatingStageLookupOnChain(t *testing.T) {
	if harness.IntegrationNetwork() != harness.IntegrationNetworkLocalnet {
		t.Skip("the stage lookup test needs LocalNet's Indexer")
	}
	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Fatalf("funding account: %v", err)
	}
	funderAddr, err := types.DecodeAddress(funder.GetAddress())
	if err != nil {
		t.Fatal(err)
	}
	keyType := rotatingkey.RotatingTripleWotscV1
	rotatingwotscsignerreg.Register()

	sp, err := testnet.GetSuggestedParams()
	if err != nil {
		t.Fatal(err)
	}
	var genesis [rotatinghybrid.GenesisHashSize]byte
	copy(genesis[:], sp.GenesisHash)
	var seed rotatinghybrid.Seed
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatal(err)
	}
	defer seed.Zero()
	payload, address, err := rotatingwotscsignerreg.NewKeyPayload(&seed, genesis)
	if err != nil {
		t.Fatal(err)
	}
	payload.ZeroSecrets()
	account, _ := types.DecodeAddress(address)
	if err := funder.FundMicroAlgosAndWait(address, 1_000_000); err != nil {
		t.Fatalf("fund rotating account: %v", err)
	}

	rk, _ := rotatingkey.Lookup(keyType)
	argumentBytes := uint64(rk.MaxArgumentBytes)
	profile, err := lsigresource.Materialize(uint64(rk.MaxProgramBytes), &argumentBytes, nil,
		lsigresource.DefaultOpcodeProfile(uint64(rk.MaxOpcodeCost)))
	if err != nil {
		t.Fatal(err)
	}
	stageOps, err := coresigning.GetRotatingStageOps(keyType)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := apconfig.NewGenesisHashNetworkResolver(map[string]string{
		base64.StdEncoding.EncodeToString(genesis[:]): "itestnet",
	})
	if err != nil {
		t.Fatalf("LocalNet genesis mapping: %v", err)
	}
	indexerURL := strings.TrimRight(strings.TrimSpace(os.Getenv("APLANE_LOCALNET_INDEXER_URL")), "/")
	if indexerURL == "" {
		indexerURL = defaultLocalnetIndexerURL
	}
	// readerWith reads algod as every signer does, and the Indexer at
	// indexer ("" for none).
	readerWith := func(indexer string) chainread.Reader {
		r := chainread.Reader{
			Resolver: func() apconfig.GenesisHashNetworkResolver { return resolver },
			AlgodConfig: func(string) (*apconfig.AlgodNetworkConfig, error) {
				return &apconfig.AlgodNetworkConfig{Server: testnet.AlgodURL, Token: testnet.AlgodToken}, nil
			},
			MakeClient: func(server, token string) (*algod.Client, error) { return algod.MakeClient(server, token) },
		}
		if indexer != "" {
			r.IndexerConfig = func(string) *apconfig.IndexerNetworkConfig {
				return &apconfig.IndexerNetworkConfig{Server: indexer, Token: testnet.AlgodToken}
			}
		}
		return r
	}
	// newSigner is a signer on this seed with an empty stage table: a
	// restore, or a new machine.
	newSigner := func(chain chainread.Reader) (*signersigning.Service, *keystore.KeySession) {
		session := keystore.NewKeySession(&rotatingSeedStore{keyType: keyType, seed: bytes.Clone(seed[:]), genesis: genesis[:]})
		session.InitializeSession()
		t.Cleanup(session.Destroy)
		approve := true
		return &signersigning.Service{
			Planner: &signersigning.Planner{GenesisHashResolver: resolver, Snapshot: func() signersigning.PlannerRuntimeSnapshot {
				return signersigning.PlannerRuntimeSnapshot{
					KeyFiles:    map[string]string{address: "keys/" + address + ".key"},
					KeyTypes:    map[string]string{address: keyType},
					KeyMetadata: map[string]signersigning.PlannerKeyMetadata{address: {Category: keys.CategoryRotatingLsig, LogicSigResources: &profile}},
				}
			}},
			Approval:                      &signersigning.ApprovalService{UserAutoApprove: &approve},
			GenerateTxnDescriptionFromTxn: func(types.Transaction) string { return "rotating spend" },
			IsUnlocked:                    func() bool { return true },
			PolicyFor:                     func(string) *policy.Config { return policy.DefaultConfig() },
			Rotating: &signersigning.RotatingDeps{
				Chain:    chain,
				Tables:   stagetable.NewStore(storepaths.NewPaths(t.TempDir())),
				Locks:    &signersigning.RotatingLocks{},
				Releases: &signersigning.ReleaseMemory{},
				Recovery: &signersigning.RotatingRecovery{MaxStages: 1024, Timeout: 5 * time.Minute},
				// Nothing locks these services; the daemon wires the runtime's KeyUseContext.
				KeyUse: func(ctx context.Context) (context.Context, func()) { return ctx, func() {} },
			},
		}, session
	}
	secret := &coresigning.RotatingKeyMaterial{Seed: bytes.Clone(seed[:]), GenesisHash: genesis[:]}
	defer secret.Zero()
	ctx := context.Background()
	stageAddress := func(t *testing.T, stage uint64) types.Address {
		t.Helper()
		a, err := stageOps.StageAddress(secret, stage)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	authorizerIs := func(t *testing.T, stage uint64) {
		t.Helper()
		info, err := testnet.Client.AccountInformation(address).Do(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if want := stageAddress(t, stage); info.AuthAddr != want.String() {
			t.Fatalf("authorizer %s, want stage %d %s", info.AuthAddr, stage, want)
		}
	}
	// spend prepares and signs one spend from svc and, if submit, sends it
	// and waits for it to confirm.
	spend := func(t *testing.T, svc *signersigning.Service, session *keystore.KeySession, wantStage uint64, submit bool) string {
		t.Helper()
		sp, err := testnet.GetSuggestedParams()
		if err != nil {
			t.Fatal(err)
		}
		txn := types.Transaction{
			Type: types.PaymentTx,
			Header: types.Header{
				Sender: account, Fee: types.MicroAlgos(sp.MinFee), FirstValid: sp.FirstRoundValid,
				LastValid: sp.FirstRoundValid + 100, GenesisID: sp.GenesisID, GenesisHash: genesis,
			},
			PaymentTxnFields: types.PaymentTxnFields{Receiver: funderAddr, Amount: 1000},
		}
		prep, svcErr := svc.PrepareRotatingWithContext(ctx, signerapi.RotatingPrepareRequest{
			Account: address, TxnBytesHex: txnutil.EncodeWithPrefixHex(txn),
		}, session)
		if svcErr != nil {
			t.Fatalf("prepare from stage %d: %v", wantStage, svcErr)
		}
		if prep.Stage != wantStage {
			t.Fatalf("prepare = stage %d, want %d", prep.Stage, wantStage)
		}
		signed, svcErr := svc.SignRotatingWithContext(ctx, signerapi.RotatingSignRequest{Account: address, Transactions: prep.Transactions}, session)
		if svcErr != nil {
			t.Fatalf("sign from stage %d: %v", wantStage, svcErr)
		}
		if !submit {
			return signed.TxID
		}
		var raw bytes.Buffer
		for _, h := range signed.Signed {
			b, err := hex.DecodeString(h)
			if err != nil {
				t.Fatal(err)
			}
			raw.Write(b)
		}
		if _, err := testnet.Client.SendRawTransaction(raw.Bytes()).Do(ctx); err != nil {
			t.Fatalf("submit from stage %d: %v", wantStage, err)
		}
		if _, err := testnet.WaitForConfirmation(signed.TxID, 10); err != nil {
			t.Fatalf("confirm %s: %v", signed.TxID, err)
		}
		authorizerIs(t, wantStage+1)
		return signed.TxID
	}
	// awaitIndexer waits, bounded, until the Indexer shows the spend that
	// handed the account to stage want, so the worker's one lookup is not
	// spent on an Indexer still behind algod.
	awaitIndexer := func(t *testing.T, want uint64) {
		t.Helper()
		reader := readerWith(indexerURL)
		deadline := time.Now().Add(60 * time.Second)
		for {
			got, err := reader.LookupLastRotation(ctx, genesis[:], account, stageAddress(t, want))
			if err != nil {
				t.Fatal(err)
			}
			if got.Outcome == chainread.LookupCandidate && got.Stage == want {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("the Indexer at %s never showed the rekey to stage %d: last %+v", indexerURL, want, got)
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
	// fillUntilResolved runs worker passes until the account resolves and
	// returns the passes' reports.
	fillUntilResolved := func(t *testing.T, svc *signersigning.Service, session *keystore.KeySession) []signersigning.StageTableReport {
		t.Helper()
		var reports []signersigning.StageTableReport
		for pass := 0; pass < 32; pass++ {
			got, cut := svc.FillStageTables(ctx, session, signersigning.StageFillOptions{Horizon: 2, MaxDerivations: 8, Parallel: 1})
			if cut || len(got) != 1 || got[0].Err != nil {
				t.Fatalf("pass %d: reports %+v, cut %v", pass, got, cut)
			}
			reports = append(reports, got[0])
			if got[0].Resolved {
				return reports
			}
		}
		t.Fatalf("the account never resolved: %+v", reports[len(reports)-1])
		return nil
	}

	// 1. A signer rotates the account four times: stage 4 now controls it.
	first, firstSession := newSigner(readerWith(""))
	var last string
	for stage := uint64(0); stage < 4; stage++ {
		last = spend(t, first, firstSession, stage, true)
	}
	awaitIndexer(t, 4)

	// 2. A signer on the same seed with an empty table and the Indexer: its
	// first pass resolves the account with one stage charged, from the last
	// spend.
	restored, restoredSession := newSigner(readerWith(indexerURL))
	reports := fillUntilResolved(t, restored, restoredSession)
	r := reports[0]
	if len(reports) != 1 || r.Stage != 4 {
		t.Fatalf("resolved after %d passes at stage %d, want the first pass at stage 4", len(reports), r.Stage)
	}
	if stop := r.Recovery.Last; stop == nil || stop.Reason != signersigning.StopFound || stop.Charged != 1 {
		t.Fatalf("recovery = %+v, want found with one stage charged", r.Recovery)
	}
	status := restored.RotatingAccountStatuses(reports)[0].Recovery
	if l := status.Lookup; l == nil || l.Outcome != signerapi.RotatingLookupCandidate || l.Stage == nil || *l.Stage != 4 ||
		l.Probe != signerapi.RotatingLookupProbeMatched || l.TxID != last || l.Round == 0 {
		t.Fatalf("status lookup = %+v, want stage 4 read from %s and matched", status.Lookup, last)
	}

	// 3. The next spend, from the restored signer, confirms.
	spend(t, restored, restoredSession, 4, true)
	awaitIndexer(t, 5)

	// 4. Without an Indexer, or with one that cannot be reached, the account
	// resolves through the ordinary search: stages 0 … 5.
	for name, indexer := range map[string]string{"unconfigured": "", "stopped": "http://127.0.0.1:1"} {
		t.Run("Indexer "+name, func(t *testing.T) {
			svc, session := newSigner(readerWith(indexer))
			reports := fillUntilResolved(t, svc, session)
			last := reports[len(reports)-1]
			if last.Stage != 5 || last.Recovery.Last == nil || last.Recovery.Last.Reason != signersigning.StopFound || last.Recovery.Last.Charged != 6 {
				t.Fatalf("resolved %+v, want stage 5 found after searching six stages", last)
			}
			lookup := svc.RotatingAccountStatuses(reports[len(reports)-1:])[0].Recovery.Lookup
			switch {
			case indexer == "" && lookup != nil:
				t.Fatalf("lookup without an Indexer: %+v", lookup)
			case indexer != "" && (lookup == nil || lookup.Outcome != signerapi.RotatingLookupUnavailable):
				t.Fatalf("lookup with a stopped Indexer: %+v, want unavailable", lookup)
			}
		})
	}

	// 5. A spend signed and never submitted does not move the candidate:
	// the chain still shows the spend that handed the account to stage 5.
	spend(t, restored, restoredSession, 5, false)
	authorizerIs(t, 5)
	fresh, freshSession := newSigner(readerWith(indexerURL))
	reports = fillUntilResolved(t, fresh, freshSession)
	if len(reports) != 1 || reports[0].Stage != 5 || reports[0].Lookup == nil || reports[0].Lookup.Stage != 5 || reports[0].Lookup.Probe != signersigning.ProbeMatched {
		t.Fatalf("after an unsubmitted spend: %+v, lookup %+v", reports, reports[0].Lookup)
	}
}
