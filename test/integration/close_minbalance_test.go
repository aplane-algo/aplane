// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/protocol"
	sdkconfig "github.com/algorand/go-algorand-sdk/v2/protocol/config"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

// TestCloseOutRequiresBaseMinBalance exercises the close-out rule that algod
// 5.0.4 adds (consensus v43) against a real node.
//
// An application update that changes the global schema makes the updating
// account the app's size sponsor: it then holds minimum balance for state
// of an app it neither created nor opted into. The legacy close checks
// (assets, created apps, local state, boxes) all pass for such an account,
// which is the gap v43 closes. The test makes that account, shows the node
// refuses to close it and that the client's preflight refuses before building
// the transaction, hands the sponsorship back to the creator, and then closes
// the same account successfully.
func TestCloseOutRequiresBaseMinBalance(t *testing.T) {
	if harness.IntegrationNetwork() != harness.IntegrationNetworkLocalnet {
		t.Skip("creates and closes throwaway accounts; LocalNet only")
	}
	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	ctx := context.Background()

	versions, err := testnet.Client.Versions().Do(ctx)
	if err != nil {
		t.Fatalf("algod versions: %v", err)
	}
	b := versions.Build
	if b.Major < 5 || (b.Major == 5 && b.Minor == 0 && b.BuildNumber < 4) {
		t.Skipf("algod %d.%d.%d does not enforce the close-out rule (needs 5.0.4)", b.Major, b.Minor, b.BuildNumber)
	}
	t.Logf("algod %d.%d.%d", b.Major, b.Minor, b.BuildNumber)

	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Fatalf("funding account: %v", err)
	}
	funderAddr := funder.GetAddress()

	creator := newEd25519Party(t)
	sponsor := newEd25519Party(t)
	if err := funder.FundMicroAlgosAndWait(creator.address.String(), 2_000_000); err != nil {
		t.Fatalf("fund creator: %v", err)
	}
	if err := funder.FundMicroAlgosAndWait(sponsor.address.String(), 1_000_000); err != nil {
		t.Fatalf("fund sponsor: %v", err)
	}

	// An app that approves everything, creation and updates included.
	program := compileTEAL(t, testnet.Client, "#pragma version 10\nint 1\n")
	createTxn, err := transaction.MakeApplicationCreateTx(false, program, program,
		types.StateSchema{}, types.StateSchema{}, nil, nil, nil, nil,
		mustSuggestedParams(t, testnet), creator.address, nil, types.Digest{}, [32]byte{}, types.Address{})
	if err != nil {
		t.Fatal(err)
	}
	createID := submitEd25519TxnExpectSuccess(t, testnet, creator.private, createTxn)
	pending, _, err := testnet.Client.PendingTransactionInformation(createID).Do(ctx)
	if err != nil || pending.ApplicationIndex == 0 {
		t.Fatalf("app creation %s: index %d, %v", createID, pending.ApplicationIndex, err)
	}
	appID := pending.ApplicationIndex

	// sizeUpdate updates the app with a one-integer global schema, which is
	// a size change: the sender becomes the size sponsor (the creator
	// taking it back clears the sponsor).
	sizeUpdate := func(from ed25519Party) {
		t.Helper()
		txn, err := transaction.MakeApplicationUpdateTx(appID, nil, nil, nil, nil, program, program,
			mustSuggestedParams(t, testnet), from.address, nil, types.Digest{}, [32]byte{}, types.Address{})
		if err != nil {
			t.Fatal(err)
		}
		txn.GlobalStateSchema = types.StateSchema{NumUint: 1}
		submitEd25519TxnExpectSuccess(t, testnet, from.private, txn)
	}

	// 1. The sponsor holds minimum balance for the app's global schema
	//    without holding anything the legacy close checks look at.
	sizeUpdate(sponsor)
	params := sdkconfig.Consensus[protocol.ConsensusV43]
	wantMBR := params.MinBalance + params.SchemaMinBalancePerEntry + params.SchemaUintMinBalance
	info, err := testnet.Client.AccountInformation(sponsor.address.String()).Do(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.CreatedApps) != 0 || len(info.AppsLocalState) != 0 || len(info.Assets) != 0 {
		t.Fatalf("sponsor holds created apps %d, local states %d, assets %d; want none",
			len(info.CreatedApps), len(info.AppsLocalState), len(info.Assets))
	}
	if info.MinBalance != wantMBR || info.AppsTotalSchema.NumUint != 1 {
		t.Fatalf("sponsor min balance %d (want %d), total schema uints %d (want 1)",
			info.MinBalance, wantMBR, info.AppsTotalSchema.NumUint)
	}
	t.Logf("sponsor min balance %d against base %d, with nothing the legacy checks count", info.MinBalance, params.MinBalance)

	// 2. The node refuses to close it.
	closeSponsor := func() error {
		t.Helper()
		txn, err := transaction.MakePaymentTxn(sponsor.address.String(), funderAddr, 0, nil, funderAddr, mustSuggestedParams(t, testnet))
		if err != nil {
			t.Fatal(err)
		}
		_, signed, err := signing.SignTransactionWithKey(sponsor.private, txn)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = testnet.Client.SendRawTransaction(signed).Do(ctx); err != nil {
			return err
		}
		return nil
	}
	err = closeSponsor()
	if err == nil {
		t.Fatal("node accepted the close-out of an account that requires more than the base minimum balance")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "cannot close") {
		t.Fatalf("close-out rejected for another reason than the minimum balance: %v", err)
	}
	t.Logf("node refused the close-out: %v", err)
	after, err := testnet.Client.AccountInformation(sponsor.address.String()).Do(ctx)
	if err != nil || after.Amount != info.Amount {
		t.Fatalf("sponsor balance %d after the refused close, want %d (err %v)", after.Amount, info.Amount, err)
	}

	// 3. The client refuses before building anything.
	eng, err := engine.NewEngine("localnet", engine.WithAlgodClient(testnet.Client))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := eng.PrepareClose(ctx, engine.CloseAccountParams{From: sponsor.address.String(), CloseTo: funderAddr}); err == nil ||
		!strings.Contains(err.Error(), "minimum balance requirement") {
		t.Fatalf("PrepareClose error = %v, want the minimum balance preflight", err)
	}
	// The payment-with-close-out path shares this preflight but first needs a
	// signing key for the sender, which this test deliberately does not have;
	// the engine's unit tests cover it with a key present.

	// 4. The creator takes the sponsorship back; the account is then
	//    ordinary again and closes through both the client and the node.
	sizeUpdate(creator)
	released, err := testnet.Client.AccountInformation(sponsor.address.String()).Do(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if released.MinBalance != params.MinBalance || released.AppsTotalSchema.NumUint != 0 {
		t.Fatalf("after release the sponsor requires %d with %d schema uints, want %d and 0",
			released.MinBalance, released.AppsTotalSchema.NumUint, params.MinBalance)
	}
	// Past the preflight, PrepareClose stops at the signing key this test
	// does not have; anything but that (above all the minimum balance
	// refusal) is a failure.
	if _, _, err := eng.PrepareClose(ctx, engine.CloseAccountParams{From: sponsor.address.String(), CloseTo: funderAddr}); err == nil ||
		strings.Contains(err.Error(), "minimum balance requirement") || !strings.Contains(err.Error(), "no signing key available") {
		t.Fatalf("PrepareClose after release = %v, want it past the minimum balance preflight", err)
	}
	if err := closeSponsor(); err != nil {
		t.Fatalf("node refused to close the released account: %v", err)
	}
	closed, err := testnet.Client.AccountInformation(sponsor.address.String()).Do(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; closed.Amount != 0 && i < 10; i++ {
		if _, werr := testnet.Client.StatusAfterBlock(closed.Round).Do(ctx); werr != nil {
			break
		}
		if closed, err = testnet.Client.AccountInformation(sponsor.address.String()).Do(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if closed.Amount != 0 {
		t.Fatalf("closed account still holds %d microAlgos", closed.Amount)
	}
}

// ed25519Party is a throwaway account with its key held in the test.
type ed25519Party struct {
	address types.Address
	private ed25519.PrivateKey
}

func newEd25519Party(t *testing.T) ed25519Party {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var address types.Address
	copy(address[:], public)
	return ed25519Party{address: address, private: private}
}

// compileTEAL compiles source with the node.
func compileTEAL(t *testing.T, client *algod.Client, source string) []byte {
	t.Helper()
	result, err := client.TealCompile([]byte(source)).Do(context.Background())
	if err != nil {
		t.Fatalf("compile TEAL: %v", err)
	}
	program, err := base64.StdEncoding.DecodeString(result.Result)
	if err != nil {
		t.Fatal(err)
	}
	return program
}
