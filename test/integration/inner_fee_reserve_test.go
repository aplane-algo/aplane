// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
	"github.com/aplane-algo/aplane/pkg/signerapi"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

// innerPaymentsApproval approves creation and creator deletion. Any other call
// issues two zero-amount inner payments from the app to itself with fee 0, so
// both draw on the group's fee credit: the caller's extra fee must survive
// planning for the call to succeed.
const innerPaymentsApproval = `#pragma version 10
txn ApplicationID
bz approve
txn OnCompletion
int DeleteApplication
==
bnz delete
itxn_begin
int pay
itxn_field TypeEnum
global CurrentApplicationAddress
itxn_field Receiver
int 0
itxn_field Fee
itxn_next
int pay
itxn_field TypeEnum
global CurrentApplicationAddress
itxn_field Receiver
int 0
itxn_field Fee
itxn_submit
approve:
int 1
return
delete:
txn Sender
global CreatorAddress
==
return
`

const innerPaymentsClear = `#pragma version 10
int 1
`

// TestNativeFalconAppCallKeepsInnerFeeReserve signs, from a native Falcon key,
// an app call whose extra fee pays for the app's inner transactions. The
// signer adds its native Falcon charge on top of that extra fee; spending the
// extra fee on the charge instead leaves the inner payments without fee
// credit, and algod rejects the group. A Mithras deposit failed that way.
func TestNativeFalconAppCallKeepsInnerFeeReserve(t *testing.T) {
	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{})
	network, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("validate network profile: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })
	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)

	funder, err := harness.NewFundTestAccount(network.Client)
	if err != nil {
		t.Fatalf("load funder: %v", err)
	}
	fundingAddress := funder.GetAddress()

	caller, err := apadmin.GenerateKeyWithType(nativefalcon.KeyType)
	if err != nil {
		t.Fatalf("generate native Falcon caller: %v", err)
	}
	if !waitForKey(t, signerd.GetURL(), caller, 10*time.Second) {
		t.Fatal("signer did not publish the generated native Falcon key")
	}
	if err := funder.FundMicroAlgosAndWait(caller, 300_000); err != nil {
		t.Fatalf("fund native Falcon caller: %v", err)
	}
	apshell := harness.NewApshellHarness(t)
	t.Cleanup(func() { closeAccountToFunding(t, apshell, network, caller, fundingAddress) })

	app, err := harness.DeployTEALApp(t, network.Client, funder,
		[]byte(innerPaymentsApproval), []byte(innerPaymentsClear), types.StateSchema{}, types.StateSchema{})
	if err != nil {
		t.Fatalf("deploy inner-payments app: %v", err)
	}
	t.Cleanup(func() {
		if err := app.DestroyTestApp(funder); err != nil {
			t.Logf("warning: destroy inner-payments app: %v", err)
		}
	})
	// The app account must exist to send its zero-amount inner payments.
	if err := app.FundApp(funder, 200_000); err != nil {
		t.Fatalf("fund app account: %v", err)
	}

	sp, err := network.GetSuggestedParams()
	if err != nil {
		t.Fatalf("get suggested params: %v", err)
	}
	// The caller pays its own base fee plus one minimum fee per inner payment.
	const innerReserve = 2 * 1_000
	clientFee := sp.MinFee + innerReserve
	sp.FlatFee = true
	sp.Fee = types.MicroAlgos(clientFee)
	sender, err := types.DecodeAddress(caller)
	if err != nil {
		t.Fatal(err)
	}
	call, err := transaction.MakeApplicationNoOpTx(app.AppID, nil, nil, nil, nil, sp, sender,
		[]byte("aplane-inner-fee-reserve"), types.Digest{}, [32]byte{}, types.Address{})
	if err != nil {
		t.Fatalf("build app call: %v", err)
	}

	response := signNativeFalconGroup(t, signerd.GetURL(), []signerapi.SignRequest{
		nativeFalconSignRequest(caller, call),
	})
	if len(response.Signed) != 1 {
		t.Fatalf("sign response contains %d transactions, want 1", len(response.Signed))
	}
	signed := assertNativeFalconSignedTxn(t, response.Signed[0], caller)
	// The native Falcon charge is two minimum fees on top of the client's fee.
	if want := clientFee + 2*sp.MinFee; uint64(signed.Txn.Fee) != want {
		t.Fatalf("signed fee = %d, want the client's %d plus the %d native Falcon charge", signed.Txn.Fee, clientFee, 2*sp.MinFee)
	}

	txids := submitSignedTxnGroup(t, network, response.Signed)
	if _, err := network.WaitForConfirmation(txids[0], 10); err != nil {
		t.Fatalf("app call with an inner fee reserve did not confirm: %v", err)
	}
	t.Logf("confirmed native Falcon app call %s with %d microAlgos reserved for inner payments", txids[0], innerReserve)
}
