// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/aplane-algo/aplane/internal/signerapi"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

func TestNativeFalconFNetProfile(t *testing.T) {
	if harness.IntegrationNetwork() != harness.IntegrationNetworkFNet {
		t.Skip("set APLANE_INTEGRATION_NETWORK=fnet to run native Falcon live acceptance")
	}

	network, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("validate FNet network profile: %v", err)
	}
	t.Logf("validated FNet genesis %s/%s at consensus %s",
		network.GenesisID, network.GenesisHash, network.ConsensusVersion)

	funding, err := harness.NewFundingAccount()
	if err != nil {
		t.Fatalf("load FNet native Falcon funding account: %v", err)
	}
	if err := funding.EnsureFunded(network.Client); err != nil {
		t.Fatalf("validate FNet native Falcon funding account: %v", err)
	}
	balance, err := network.GetAccountInfo(funding.Address)
	if err != nil {
		t.Fatalf("read funded native Falcon account: %v", err)
	}
	t.Logf("validated funded FNet native Falcon account %s with %d microAlgos", funding.Address, balance)
}

func TestNativeFalconFNetPayment(t *testing.T) {
	if harness.IntegrationNetwork() != harness.IntegrationNetworkFNet {
		t.Skip("set APLANE_INTEGRATION_NETWORK=fnet to run native Falcon live acceptance")
	}
	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{})
	network, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("validate FNet network profile: %v", err)
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
		t.Fatalf("load FNet native Falcon funder: %v", err)
	}
	fundingAddress := funder.GetAddress()

	childAddress, err := apadmin.GenerateKeyWithType(nativefalcon.KeyType)
	if err != nil {
		t.Fatalf("generate disposable native Falcon account: %v", err)
	}
	edAddress, err := apadmin.GenerateKeyWithType("ed25519")
	if err != nil {
		t.Fatalf("generate disposable Ed25519 account: %v", err)
	}
	token := readSignerToken(t, signerd)
	if !waitForKey(t, signerd.GetURL(), token, childAddress, 10*time.Second) ||
		!waitForKey(t, signerd.GetURL(), token, edAddress, 10*time.Second) {
		t.Fatal("signer did not publish generated test keys")
	}

	exportPassphrase := "public-fnet-native-falcon-backup-passphrase"
	backupResult, err := apadmin.CreateBackup(exportPassphrase)
	if err != nil {
		t.Fatalf("back up native Falcon key: %v", err)
	}
	if err := apadmin.DeleteKey(childAddress); err != nil {
		t.Fatalf("delete native Falcon key before restore: %v", err)
	}
	t.Setenv("APSIGNER_PASSPHRASE", mustReadPassphrase(t, signerd.GetWorkDir()))
	if output, restoreErr := apadmin.RunWithInput(exportPassphrase+"\n",
		"restore", "apply", filepath.Base(backupResult.ArchivePath), "--address", childAddress); restoreErr != nil {
		t.Fatalf("restore native Falcon key: %v\noutput:\n%s", restoreErr, output)
	}
	if !waitForKey(t, signerd.GetURL(), token, childAddress, 10*time.Second) {
		t.Fatalf("signer did not reload restored native Falcon key %s", childAddress)
	}

	if err := funder.FundMicroAlgosAndWait(childAddress, 300_000); err != nil {
		t.Fatalf("fund native Falcon child from native Falcon funder: %v", err)
	}
	if err := funder.FundMicroAlgosAndWait(edAddress, 300_000); err != nil {
		t.Fatalf("fund disposable Ed25519 child: %v", err)
	}

	sp, err := network.GetSuggestedParams()
	if err != nil {
		t.Fatalf("get FNet suggested params: %v", err)
	}
	firstNative, err := transaction.MakePaymentTxn(childAddress, fundingAddress, 0,
		[]byte("aplane-native-falcon-group-a"), "", sp)
	if err != nil {
		t.Fatalf("build first native Falcon group transaction: %v", err)
	}
	secondNative, err := transaction.MakePaymentTxn(childAddress, fundingAddress, 0,
		[]byte("aplane-native-falcon-group-b"), "", sp)
	if err != nil {
		t.Fatalf("build second native Falcon group transaction: %v", err)
	}
	response := signFNetGroup(t, signerd.GetURL(), token, []signerapi.SignRequest{
		nativeFNetSignRequest(childAddress, firstNative),
		nativeFNetSignRequest(childAddress, secondNative),
	})
	if len(response.Signed) != 2 {
		t.Fatalf("native Falcon group response contains %d transactions, want 2", len(response.Signed))
	}
	firstSigned := assertNativeFalconSignedTxn(t, response.Signed[0], childAddress)
	secondSigned := assertNativeFalconSignedTxn(t, response.Signed[1], childAddress)
	if firstSigned.Txn.Group == (types.Digest{}) || firstSigned.Txn.Group != secondSigned.Txn.Group {
		t.Fatal("native Falcon transactions were not returned as one atomic group")
	}
	if uint64(firstSigned.Txn.Fee)+uint64(secondSigned.Txn.Fee) < 6_000 {
		t.Fatalf("two-member native Falcon group fee = %d, want at least 6000",
			uint64(firstSigned.Txn.Fee)+uint64(secondSigned.Txn.Fee))
	}
	nativeGroupIDs := submitSignedTxnGroup(t, network, response.Signed)
	if _, err := network.WaitForConfirmation(nativeGroupIDs[0], 10); err != nil {
		t.Fatalf("native Falcon group did not confirm: %v", err)
	}

	sp, err = network.GetSuggestedParams()
	if err != nil {
		t.Fatalf("refresh FNet suggested params: %v", err)
	}
	nativeGrouped, err := transaction.MakePaymentTxn(childAddress, fundingAddress, 0,
		[]byte("aplane-native-falcon-mixed"), "", sp)
	if err != nil {
		t.Fatalf("build native member of mixed group: %v", err)
	}
	edGrouped, err := transaction.MakePaymentTxn(edAddress, fundingAddress, 0,
		[]byte("aplane-ed25519-mixed"), "", sp)
	if err != nil {
		t.Fatalf("build Ed25519 member of mixed group: %v", err)
	}
	mixedResponse := signFNetGroup(t, signerd.GetURL(), token, []signerapi.SignRequest{
		nativeFNetSignRequest(childAddress, nativeGrouped),
		nativeFNetSignRequest(edAddress, edGrouped),
	})
	if len(mixedResponse.Signed) != 2 {
		t.Fatalf("mixed group response contains %d transactions, want 2", len(mixedResponse.Signed))
	}
	nativeMember := assertNativeFalconSignedTxn(t, mixedResponse.Signed[0], childAddress)
	edMember := decodeSignedTxnHex(t, mixedResponse.Signed[1])
	if edMember.Sig == (types.Signature{}) || !edMember.PQsig.Blank() || len(edMember.Lsig.Logic) != 0 {
		t.Fatal("Ed25519 member of mixed group has the wrong authorization envelope")
	}
	if nativeMember.Txn.Group == (types.Digest{}) || nativeMember.Txn.Group != edMember.Txn.Group {
		t.Fatal("native Falcon and Ed25519 transactions were not returned as one atomic group")
	}
	if uint64(nativeMember.Txn.Fee)+uint64(edMember.Txn.Fee) < 4_000 {
		t.Fatalf("mixed native Falcon/Ed25519 group fee = %d, want at least 4000",
			uint64(nativeMember.Txn.Fee)+uint64(edMember.Txn.Fee))
	}
	mixedTxIDs := submitSignedTxnGroup(t, network, mixedResponse.Signed)
	if _, err := network.WaitForConfirmation(mixedTxIDs[0], 10); err != nil {
		t.Fatalf("mixed native Falcon/Ed25519 group did not confirm: %v", err)
	}

	apshell := harness.NewApshellHarness(t, signerd.GetURL())
	if err := apshell.CopyTokenFrom(signerd.GetWorkDir()); err != nil {
		t.Fatalf("copy signer token to apshell harness: %v", err)
	}
	t.Cleanup(func() {
		closeAccountToFunding(t, apshell, network, edAddress, fundingAddress)
		closeAccountToFunding(t, apshell, network, childAddress, fundingAddress)
	})

	rekeyID, err := apshell.RekeyAccount(edAddress, childAddress)
	if err != nil {
		t.Fatalf("rekey Ed25519 account to native Falcon: %v", err)
	}
	if _, err := network.WaitForConfirmation(rekeyID, 10); err != nil {
		t.Fatalf("Ed25519-to-native-Falcon rekey did not confirm: %v", err)
	}
	rekeyedSpendID, err := apshell.SendTransaction(edAddress, fundingAddress, 0.001)
	if err != nil {
		t.Fatalf("spend through rekeyed native Falcon authorizer: %v", err)
	}
	if _, err := network.WaitForConfirmation(rekeyedSpendID, 10); err != nil {
		t.Fatalf("rekeyed native Falcon payment did not confirm: %v", err)
	}
	unrekeyID, err := apshell.UnrekeyAccount(edAddress)
	if err != nil {
		t.Fatalf("unrekey Ed25519 account through native Falcon: %v", err)
	}
	if _, err := network.WaitForConfirmation(unrekeyID, 10); err != nil {
		t.Fatalf("native Falcon unrekey did not confirm: %v", err)
	}

	childSpendID, err := apshell.SendTransaction(childAddress, fundingAddress, 0.001)
	if err != nil {
		t.Fatalf("send through apshell from native Falcon child: %v", err)
	}
	if _, err := network.WaitForConfirmation(childSpendID, 10); err != nil {
		t.Fatalf("apshell native Falcon payment did not confirm: %v", err)
	}
	edCloseID, err := apshell.CloseAccount(edAddress, fundingAddress)
	if err != nil {
		t.Fatalf("close restored Ed25519 account through apshell: %v", err)
	}
	if _, err := network.WaitForConfirmation(edCloseID, 10); err != nil {
		t.Fatalf("Ed25519 close did not confirm: %v", err)
	}
	closeID, err := apshell.CloseAccount(childAddress, fundingAddress)
	if err != nil {
		t.Fatalf("close native Falcon child through apshell: %v", err)
	}
	if _, err := network.WaitForConfirmation(closeID, 10); err != nil {
		t.Fatalf("native Falcon close did not confirm: %v", err)
	}
	t.Logf("confirmed native Falcon backup/restore, mixed group, rekey, spend, and close on FNet: funding=%s mixed=%s rekey=%s spend=%s unrekey=%s close=%s",
		nativeGroupIDs[0], mixedTxIDs[0], rekeyID, rekeyedSpendID, unrekeyID, closeID)
}

func nativeFNetSignRequest(authorizer string, txn types.Transaction) signerapi.SignRequest {
	return signerapi.SignRequest{
		AuthAddress: authorizer,
		TxnBytesHex: hex.EncodeToString(append([]byte("TX"), msgpack.Encode(txn)...)),
	}
}

func signFNetGroup(t *testing.T, signerURL, token string, requests []signerapi.SignRequest) signerapi.GroupSignResponse {
	t.Helper()
	status, body := postSignRequest(t, signerURL, "aplane "+token, signerapi.GroupSignRequest{Requests: requests})
	if status != 200 {
		t.Fatalf("native Falcon /sign status = %d: %s", status, body)
	}
	var response signerapi.GroupSignResponse
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("decode native Falcon sign response: %v", err)
	}
	if response.Error != "" {
		t.Fatalf("native Falcon sign response = %#v", response)
	}
	return response
}

func assertNativeFalconSignedTxn(t *testing.T, encoded, authorizer string) types.SignedTxn {
	t.Helper()
	signed := decodeSignedTxnHex(t, encoded)
	if signed.PQsig.Blank() || signed.PQsig.Scheme != (types.PQScheme{'f', '1'}) {
		t.Fatalf("signed transaction has invalid native PQ envelope: %#v", signed.PQsig)
	}
	if len(signed.PQsig.PublicKey) != nativefalcon.PublicKeySize ||
		len(signed.PQsig.Signature) == 0 || len(signed.PQsig.Signature) > nativefalcon.MaxSignatureSize {
		t.Fatalf("native PQ key/signature sizes = %d/%d",
			len(signed.PQsig.PublicKey), len(signed.PQsig.Signature))
	}
	if signed.Sig != (types.Signature{}) || !signed.Msig.Blank() || len(signed.Lsig.Logic) != 0 {
		t.Fatal("native Falcon transaction contains another authorization shape")
	}
	derived, err := nativefalcon.Address(byte(signed.PQsig.Salt), signed.PQsig.PublicKey)
	if err != nil {
		t.Fatalf("derive native Falcon authorizer from PQ envelope: %v", err)
	}
	if derived.String() != authorizer {
		t.Fatalf("native Falcon envelope authorizer = %s, want %s", derived, authorizer)
	}
	return signed
}
