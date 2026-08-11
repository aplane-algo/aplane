// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/algorand/falcon"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	algomnemonic "github.com/algorand/go-algorand-sdk/v2/mnemonic"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
	securecrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/signerapi"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

const fnetFalconRootAddress = "HXK6I7UPOE7H2CPXV52QVN7OYURJ355YSRWZKJGA7I4LNGE3633LTESHZQ"

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

	address := fnetFalconAddressFromMnemonic(t, readFNetFalconMnemonic(t))
	if address != fnetFalconRootAddress {
		t.Fatalf("native Falcon test mnemonic derives %s, want %s", address, fnetFalconRootAddress)
	}

	balance, err := network.GetAccountInfo(address)
	if err != nil {
		t.Fatalf("read funded native Falcon account: %v", err)
	}
	if balance == 0 {
		t.Fatalf("native Falcon FNet root %s is not funded", address)
	}
	t.Logf("validated funded native Falcon root %s with %d microAlgos", address, balance)
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

	rootMnemonic := readFNetFalconMnemonic(t)
	rootAddress, err := apadmin.ImportKeyWithTypeAndParams(nativefalcon.KeyType, rootMnemonic, nil)
	if err != nil {
		t.Fatalf("import native Falcon FNet root through admin IPC: %v", err)
	}
	if rootAddress != fnetFalconRootAddress {
		t.Fatalf("imported native Falcon root = %s, want %s", rootAddress, fnetFalconRootAddress)
	}

	childAddress, err := apadmin.GenerateKeyWithType(nativefalcon.KeyType)
	if err != nil {
		t.Fatalf("generate disposable native Falcon account: %v", err)
	}
	edAddress, err := apadmin.GenerateKeyWithType("ed25519")
	if err != nil {
		t.Fatalf("generate disposable Ed25519 account: %v", err)
	}
	token := readSignerToken(t, signerd)
	if !waitForKey(t, signerd.GetURL(), token, rootAddress, 10*time.Second) ||
		!waitForKey(t, signerd.GetURL(), token, childAddress, 10*time.Second) ||
		!waitForKey(t, signerd.GetURL(), token, edAddress, 10*time.Second) {
		t.Fatal("signer did not publish imported and generated test keys")
	}

	exportPassphrase := "public-fnet-native-falcon-backup-passphrase"
	backupResult, err := apadmin.CreateBackup(exportPassphrase)
	if err != nil {
		t.Fatalf("back up native Falcon key: %v", err)
	}
	if err := apadmin.DeleteKey(childAddress); err != nil {
		t.Fatalf("delete native Falcon key before restore: %v", err)
	}
	apstore := harness.NewApStoreHarness(t, signerd.GetWorkDir())
	if output, restoreErr := apstore.RunWithInput(exportPassphrase+"\n",
		"restore", "apply", filepath.Base(backupResult.ArchivePath), "--address", childAddress); restoreErr != nil {
		t.Fatalf("restore native Falcon key: %v\noutput:\n%s", restoreErr, output)
	}
	if !waitForKey(t, signerd.GetURL(), token, childAddress, 10*time.Second) {
		t.Fatalf("signer did not reload restored native Falcon key %s", childAddress)
	}

	sp, err := network.GetSuggestedParams()
	if err != nil {
		t.Fatalf("get FNet suggested params: %v", err)
	}
	childFunding, err := transaction.MakePaymentTxn(rootAddress, childAddress, 300_000,
		[]byte("aplane-native-falcon-child"), "", sp)
	if err != nil {
		t.Fatalf("build native Falcon child funding transaction: %v", err)
	}
	edFunding, err := transaction.MakePaymentTxn(rootAddress, edAddress, 300_000,
		[]byte("aplane-native-falcon-ed25519"), "", sp)
	if err != nil {
		t.Fatalf("build Ed25519 child funding transaction: %v", err)
	}
	response := signFNetGroup(t, signerd.GetURL(), token, []signerapi.SignRequest{
		nativeFNetSignRequest(rootAddress, childFunding),
		nativeFNetSignRequest(rootAddress, edFunding),
	})
	if len(response.Signed) != 2 {
		t.Fatalf("native Falcon funding response contains %d transactions, want 2", len(response.Signed))
	}
	firstFunding := assertNativeFalconSignedTxn(t, response.Signed[0], rootAddress)
	secondFunding := assertNativeFalconSignedTxn(t, response.Signed[1], rootAddress)
	if firstFunding.Txn.Group == (types.Digest{}) || firstFunding.Txn.Group != secondFunding.Txn.Group {
		t.Fatal("native Falcon funding transactions were not returned as one atomic group")
	}
	if uint64(firstFunding.Txn.Fee)+uint64(secondFunding.Txn.Fee) < 6_000 {
		t.Fatalf("two-member native Falcon group fee = %d, want at least 6000",
			uint64(firstFunding.Txn.Fee)+uint64(secondFunding.Txn.Fee))
	}
	fundingTxIDs := submitSignedTxnGroup(t, network, response.Signed)
	if _, err := network.WaitForConfirmation(fundingTxIDs[0], 10); err != nil {
		t.Fatalf("native Falcon funding group did not confirm: %v", err)
	}

	sp, err = network.GetSuggestedParams()
	if err != nil {
		t.Fatalf("refresh FNet suggested params: %v", err)
	}
	nativeGrouped, err := transaction.MakePaymentTxn(childAddress, rootAddress, 0,
		[]byte("aplane-native-falcon-mixed"), "", sp)
	if err != nil {
		t.Fatalf("build native member of mixed group: %v", err)
	}
	edGrouped, err := transaction.MakePaymentTxn(edAddress, rootAddress, 0,
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
		closeAccountToFunding(t, apshell, network, edAddress, rootAddress)
		closeAccountToFunding(t, apshell, network, childAddress, rootAddress)
	})

	rekeyID, err := apshell.RekeyAccount(edAddress, childAddress)
	if err != nil {
		t.Fatalf("rekey Ed25519 account to native Falcon: %v", err)
	}
	if _, err := network.WaitForConfirmation(rekeyID, 10); err != nil {
		t.Fatalf("Ed25519-to-native-Falcon rekey did not confirm: %v", err)
	}
	rekeyedSpendID, err := apshell.SendTransaction(edAddress, rootAddress, 0.001)
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

	childSpendID, err := apshell.SendTransaction(childAddress, rootAddress, 0.001)
	if err != nil {
		t.Fatalf("send through apshell from native Falcon child: %v", err)
	}
	if _, err := network.WaitForConfirmation(childSpendID, 10); err != nil {
		t.Fatalf("apshell native Falcon payment did not confirm: %v", err)
	}
	edCloseID, err := apshell.CloseAccount(edAddress, rootAddress)
	if err != nil {
		t.Fatalf("close restored Ed25519 account through apshell: %v", err)
	}
	if _, err := network.WaitForConfirmation(edCloseID, 10); err != nil {
		t.Fatalf("Ed25519 close did not confirm: %v", err)
	}
	closeID, err := apshell.CloseAccount(childAddress, rootAddress)
	if err != nil {
		t.Fatalf("close native Falcon child through apshell: %v", err)
	}
	if _, err := network.WaitForConfirmation(closeID, 10); err != nil {
		t.Fatalf("native Falcon close did not confirm: %v", err)
	}
	t.Logf("confirmed native Falcon backup/restore, mixed group, rekey, spend, and close on FNet: funding=%s mixed=%s rekey=%s spend=%s unrekey=%s close=%s",
		fundingTxIDs[0], mixedTxIDs[0], rekeyID, rekeyedSpendID, unrekeyID, closeID)
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

func readFNetFalconMnemonic(t *testing.T) string {
	t.Helper()
	path := strings.TrimSpace(os.Getenv("APLANE_FNET_FALCON_MNEMONIC_FILE"))
	if path == "" {
		t.Skip("set APLANE_FNET_FALCON_MNEMONIC_FILE to the ignored 25-word test mnemonic")
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("inspect FNet mnemonic file: %v", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("FNet mnemonic file must be a private regular file (mode 0600 or stricter)")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read FNet mnemonic file: %v", err)
	}
	defer securecrypto.ZeroBytes(raw)
	words := strings.Fields(string(raw))
	if len(words) != nativefalcon.MnemonicWordCount {
		t.Fatalf("FNet native Falcon mnemonic has %d words, want %d", len(words), nativefalcon.MnemonicWordCount)
	}
	return strings.Join(words, " ")
}

func fnetFalconAddressFromMnemonic(t *testing.T, words string) string {
	t.Helper()
	entropy, err := algomnemonic.ToKey(words)
	if err != nil {
		t.Fatalf("decode FNet native Falcon mnemonic: %v", err)
	}
	defer securecrypto.ZeroBytes(entropy)
	seedInput := append([]byte("PQK"+nativefalcon.Scheme), entropy...)
	workingSeed := sha512.Sum512_256(seedInput)
	securecrypto.ZeroBytes(seedInput)
	defer securecrypto.ZeroBytes(workingSeed[:])
	publicKey, privateKey, err := falcon.GenerateKey(workingSeed[:])
	if err != nil {
		t.Fatalf("derive FNet native Falcon key: %v", err)
	}
	defer securecrypto.ZeroBytes(privateKey[:])
	_, address, err := nativefalcon.CanonicalAddress(publicKey[:])
	if err != nil {
		t.Fatalf("derive FNet native Falcon address: %v", err)
	}
	return address.String()
}
