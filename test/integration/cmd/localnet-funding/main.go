// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// localnet-funding uses an AlgoKit LocalNet KMD account to bootstrap a
// disposable protocol-native Falcon-1024 TEST_FUNDING_* account.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/client/kmd"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/mnemonic"
	"github.com/algorand/go-algorand-sdk/v2/protocol"
	sdkconfig "github.com/algorand/go-algorand-sdk/v2/protocol/config"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	securecrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

const (
	defaultAlgodURL = "http://localhost:4001"
	defaultKMDURL   = "http://localhost:4002"
	defaultToken    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	defaultWallet   = "unencrypted-default-wallet"

	mainnetGenesisID = "mainnet-v1.0"
	testnetGenesisID = "testnet-v1.0"
	betanetGenesisID = "betanet-v1.0"

	integrationBurnAddress = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	minBurnBalance         = uint64(100_000)
	nativeFundingBalance   = uint64(100_000_000)
)

type candidate struct {
	address    string
	balance    uint64
	minBalance uint64
	spendable  uint64
}

func main() {
	algodURL := envDefault("APLANE_LOCALNET_ALGOD_URL", envDefault("ALGOD_URL", defaultAlgodURL))
	kmdURL := envDefault("APLANE_LOCALNET_KMD_URL", defaultKMDURL)
	token := envDefault("APLANE_LOCALNET_TOKEN", envDefault("ALGOD_TOKEN", defaultToken))
	walletName := envDefault("APLANE_LOCALNET_WALLET", defaultWallet)
	walletPassword := os.Getenv("APLANE_LOCALNET_WALLET_PASSWORD")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	algodClient, err := algod.MakeClient(algodURL, token)
	if err != nil {
		fatalf("create algod client: %v", err)
	}
	version, err := algodClient.Versions().Do(ctx)
	if err != nil {
		fatalf("read algod versions from %s: %v", algodURL, err)
	}
	if err := validateLocalnetAlgod(algodURL, version.GenesisID); err != nil {
		fatalf("%v", err)
	}
	genesisHash := base64.StdEncoding.EncodeToString(version.GenesisHash)

	kmdClient, err := kmd.MakeClient(kmdURL, token)
	if err != nil {
		fatalf("create kmd client: %v", err)
	}
	walletID, err := findWalletID(kmdClient, walletName)
	if err != nil {
		fatalf("%v", err)
	}

	handle, err := kmdClient.InitWalletHandle(walletID, walletPassword)
	if err != nil {
		fatalf("open KMD wallet %q: %v", walletName, err)
	}
	defer func() { _, _ = kmdClient.ReleaseWalletHandle(handle.WalletHandleToken) }()

	keys, err := kmdClient.ListKeys(handle.WalletHandleToken)
	if err != nil {
		fatalf("list KMD wallet keys: %v", err)
	}
	if len(keys.Addresses) == 0 {
		fatalf("KMD wallet %q has no keys", walletName)
	}

	selected, err := selectFundingAccount(ctx, algodClient, keys.Addresses)
	if err != nil {
		fatalf("%v", err)
	}
	if err := ensureBurnAddressFunded(ctx, algodClient, kmdClient, handle.WalletHandleToken, walletPassword, selected.address); err != nil {
		fatalf("%v", err)
	}

	entropy := make([]byte, 32)
	if _, err := rand.Read(entropy); err != nil {
		fatalf("generate native Falcon funding entropy: %v", err)
	}
	defer securecrypto.ZeroBytes(entropy)
	mn, err := mnemonic.FromKey(entropy)
	if err != nil {
		fatalf("encode native Falcon funding mnemonic: %v", err)
	}
	nativeAddress, err := harness.NativeFundingAddressFromMnemonic(mn)
	if err != nil {
		fatalf("derive native Falcon funding address: %v", err)
	}
	if err := fundNativeAccount(ctx, algodClient, kmdClient, handle.WalletHandleToken, walletPassword, selected.address, nativeAddress); err != nil {
		fatalf("%v", err)
	}

	fmt.Printf("FUNDING_ADDRESS=%s\n", nativeAddress)
	fmt.Printf("TEST_FUNDING_MNEMONIC=%s\n", mn)
	fmt.Printf("LOCALNET_GENESIS_ID=%s\n", version.GenesisID)
	fmt.Printf("LOCALNET_GENESIS_HASH=%s\n", genesisHash)
}

func fundNativeAccount(
	ctx context.Context,
	client *algod.Client,
	kmdClient kmd.Client,
	walletHandle string,
	walletPassword string,
	bootstrapAddress string,
	nativeAddress string,
) error {
	sp, err := client.SuggestedParams().Do(ctx)
	if err != nil {
		return fmt.Errorf("read suggested params for native funding: %w", err)
	}
	params, ok := sdkconfig.Consensus[protocol.ConsensusVersion(sp.ConsensusVersion)]
	if !ok || !params.EnablePQSchemeFalcon1024 {
		return fmt.Errorf("localnet consensus %q does not support native Falcon-1024 authorization", sp.ConsensusVersion)
	}
	txn, err := transaction.MakePaymentTxn(
		bootstrapAddress,
		nativeAddress,
		nativeFundingBalance,
		[]byte("aplane localnet native Falcon test funder"),
		"",
		sp,
	)
	if err != nil {
		return fmt.Errorf("build native funding transaction: %w", err)
	}
	signed, err := kmdClient.SignTransaction(walletHandle, walletPassword, txn)
	if err != nil {
		return fmt.Errorf("sign native funding transaction with KMD: %w", err)
	}
	txid, err := client.SendRawTransaction(signed.SignedTransaction).Do(ctx)
	if err != nil {
		return fmt.Errorf("submit native funding transaction: %w", err)
	}
	if _, err := transaction.WaitForConfirmation(client, txid, 4, ctx); err != nil {
		return fmt.Errorf("wait for native funding transaction %s: %w", txid, err)
	}
	return nil
}

func findWalletID(client kmd.Client, walletName string) (string, error) {
	wallets, err := client.ListWallets()
	if err != nil {
		return "", fmt.Errorf("list KMD wallets: %w", err)
	}
	for _, wallet := range wallets.Wallets {
		if wallet.Name == walletName {
			return wallet.ID, nil
		}
	}

	names := make([]string, 0, len(wallets.Wallets))
	for _, wallet := range wallets.Wallets {
		names = append(names, wallet.Name)
	}
	sort.Strings(names)
	return "", fmt.Errorf("KMD wallet %q not found; available wallets: %s", walletName, strings.Join(names, ", "))
}

func selectFundingAccount(ctx context.Context, client *algod.Client, addresses []string) (candidate, error) {
	candidates := make([]candidate, 0, len(addresses))
	for _, addr := range addresses {
		info, err := client.AccountInformation(addr).Do(ctx)
		if err != nil {
			continue
		}
		spendable := uint64(0)
		if info.Amount > info.MinBalance {
			spendable = info.Amount - info.MinBalance
		}
		candidates = append(candidates, candidate{
			address:    addr,
			balance:    info.Amount,
			minBalance: info.MinBalance,
			spendable:  spendable,
		})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].spendable == candidates[j].spendable {
			return candidates[i].address < candidates[j].address
		}
		return candidates[i].spendable > candidates[j].spendable
	})
	if len(candidates) == 0 || candidates[0].spendable == 0 {
		return candidate{}, fmt.Errorf("no funded KMD wallet account found")
	}
	return candidates[0], nil
}

func ensureBurnAddressFunded(
	ctx context.Context,
	client *algod.Client,
	kmdClient kmd.Client,
	walletHandle string,
	walletPassword string,
	fundingAddress string,
) error {
	currentBalance := uint64(0)
	if info, err := client.AccountInformation(integrationBurnAddress).Do(ctx); err == nil {
		currentBalance = info.Amount
	}
	if currentBalance >= minBurnBalance {
		return nil
	}

	sp, err := client.SuggestedParams().Do(ctx)
	if err != nil {
		return fmt.Errorf("read suggested params for burn-address funding: %w", err)
	}
	amount := minBurnBalance - currentBalance
	txn, err := transaction.MakePaymentTxn(fundingAddress, integrationBurnAddress, amount, []byte("aplane localnet integration burn seed"), "", sp)
	if err != nil {
		return fmt.Errorf("build burn-address funding transaction: %w", err)
	}
	signed, err := kmdClient.SignTransaction(walletHandle, walletPassword, txn)
	if err != nil {
		return fmt.Errorf("sign burn-address funding transaction with KMD: %w", err)
	}
	txid, err := client.SendRawTransaction(signed.SignedTransaction).Do(ctx)
	if err != nil {
		return fmt.Errorf("submit burn-address funding transaction: %w", err)
	}
	if _, err := transaction.WaitForConfirmation(client, txid, 4, ctx); err != nil {
		return fmt.Errorf("wait for burn-address funding transaction %s: %w", txid, err)
	}
	return nil
}

func validateLocalnetAlgod(algodURL, genesisID string) error {
	if genesisID == "" {
		return fmt.Errorf("localnet algod %s returned an empty genesis ID", algodURL)
	}
	switch genesisID {
	case mainnetGenesisID, testnetGenesisID, betanetGenesisID:
		return fmt.Errorf("localnet setup refused canonical Algorand genesis %q from %s", genesisID, algodURL)
	}
	if !isLocalEndpoint(algodURL) {
		return fmt.Errorf("localnet algod URL must be localhost, private, or single-label Docker DNS; got %s", algodURL)
	}
	return nil
}

func isLocalEndpoint(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") ||
		strings.EqualFold(host, "host.docker.internal") ||
		strings.HasSuffix(strings.ToLower(host), ".local") ||
		!strings.Contains(host, ".") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate()
}

func envDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func fatalf(format string, args ...interface{}) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
