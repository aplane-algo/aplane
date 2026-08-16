// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package harness

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

const (
	IntegrationNetworkEnv = "APLANE_INTEGRATION_NETWORK"

	IntegrationNetworkTestnet  = "testnet"
	IntegrationNetworkLocalnet = "localnet"
	IntegrationNetworkFNet     = "fnet"

	TestnetGenesisID = "testnet-v1.0"
	MainnetGenesisID = "mainnet-v1.0"
	BetanetGenesisID = "betanet-v1.0"
	FNetGenesisID    = "fnet-v1"
	FNetGenesisHash  = "kUt08LxeVAAGHnh4JoAoAMM9ql/hBwSoiFtlnKNeOxA="
	FNetConsensus    = "fnet5"

	defaultTestnetAlgodURL  = "https://testnet-api.4160.nodely.dev"
	defaultFNetAlgodURL     = "https://fnet-api.4160.nodely.dev"
	defaultLocalnetAlgodURL = "http://localhost:4001"
	defaultLocalnetToken    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

// TestnetConfig holds integration network connection configuration.
//
// The name is kept for compatibility with existing integration tests. New
// callers should treat it as the explicitly selected TestNet, LocalNet, or
// FNet integration profile.
type TestnetConfig struct {
	Network          string
	AlgodURL         string
	AlgodToken       string
	GenesisID        string
	GenesisHash      string
	ConsensusVersion string
	Client           *algod.Client
}

// IntegrationNetwork returns the explicitly selected integration network.
func IntegrationNetwork() string {
	return strings.TrimSpace(os.Getenv(IntegrationNetworkEnv))
}

// NewTestnetConfig creates a new integration network configuration.
func NewTestnetConfig() (*TestnetConfig, error) {
	network := IntegrationNetwork()
	algodURL, algodToken, err := integrationAlgodEndpoint(network)
	if err != nil {
		return nil, err
	}

	// Create client
	client, err := algod.MakeClient(algodURL, algodToken)
	if err != nil {
		return nil, fmt.Errorf("failed to create algod client: %w", err)
	}

	// Test connection
	status, err := client.Status().Do(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to connect to algod: %w", err)
	}
	sp, err := client.SuggestedParams().Do(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to read suggested params from algod: %w", err)
	}
	version, err := client.Versions().Do(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to read versions from algod: %w", err)
	}
	genesisHash := base64.StdEncoding.EncodeToString(version.GenesisHash)
	if err := validateIntegrationNetwork(network, algodURL, sp.GenesisID, genesisHash, sp.ConsensusVersion, status.LastVersion); err != nil {
		return nil, err
	}

	return &TestnetConfig{
		Network:          network,
		AlgodURL:         algodURL,
		AlgodToken:       algodToken,
		GenesisID:        sp.GenesisID,
		GenesisHash:      genesisHash,
		ConsensusVersion: sp.ConsensusVersion,
		Client:           client,
	}, nil
}

func integrationAlgodEndpoint(network string) (string, string, error) {
	switch network {
	case IntegrationNetworkTestnet:
		algodURL := strings.TrimSpace(os.Getenv("ALGOD_URL"))
		if algodURL == "" {
			algodURL = defaultTestnetAlgodURL
		}
		return algodURL, os.Getenv("ALGOD_TOKEN"), nil
	case IntegrationNetworkLocalnet:
		algodURL := strings.TrimSpace(os.Getenv("ALGOD_URL"))
		if algodURL == "" {
			algodURL = strings.TrimSpace(os.Getenv("APLANE_LOCALNET_ALGOD_URL"))
		}
		if algodURL == "" {
			algodURL = defaultLocalnetAlgodURL
		}
		algodToken := strings.TrimSpace(os.Getenv("ALGOD_TOKEN"))
		if algodToken == "" {
			algodToken = strings.TrimSpace(os.Getenv("APLANE_LOCALNET_TOKEN"))
		}
		if algodToken == "" {
			algodToken = defaultLocalnetToken
		}
		return algodURL, algodToken, nil
	case IntegrationNetworkFNet:
		algodURL := strings.TrimSpace(os.Getenv("ALGOD_URL"))
		if algodURL == "" {
			algodURL = strings.TrimSpace(os.Getenv("APLANE_FNET_ALGOD_URL"))
		}
		if algodURL == "" {
			algodURL = defaultFNetAlgodURL
		}
		algodToken := strings.TrimSpace(os.Getenv("ALGOD_TOKEN"))
		if algodToken == "" {
			algodToken = strings.TrimSpace(os.Getenv("APLANE_FNET_ALGOD_TOKEN"))
		}
		return algodURL, algodToken, nil
	default:
		if network == "" {
			return "", "", fmt.Errorf("%s must be set to %q, %q, or %q", IntegrationNetworkEnv, IntegrationNetworkTestnet, IntegrationNetworkLocalnet, IntegrationNetworkFNet)
		}
		return "", "", fmt.Errorf("%s must be %q, %q, or %q, got %q", IntegrationNetworkEnv, IntegrationNetworkTestnet, IntegrationNetworkLocalnet, IntegrationNetworkFNet, network)
	}
}

func validateIntegrationNetwork(network, algodURL, genesisID, genesisHash, suggestedConsensus, statusConsensus string) error {
	switch network {
	case IntegrationNetworkTestnet:
		if genesisID != TestnetGenesisID {
			return fmt.Errorf("integration tests require %s, but ALGOD_URL %s reports genesis %q", TestnetGenesisID, algodURL, genesisID)
		}
	case IntegrationNetworkLocalnet:
		if genesisID == "" {
			return fmt.Errorf("localnet integration algod %s returned an empty genesis ID", algodURL)
		}
		switch genesisID {
		case MainnetGenesisID, TestnetGenesisID, BetanetGenesisID:
			return fmt.Errorf("localnet integration refused canonical Algorand genesis %q from %s", genesisID, algodURL)
		}
		if !isLocalIntegrationEndpoint(algodURL) {
			return fmt.Errorf("localnet integration algod URL must be localhost, private, or single-label Docker DNS; got %s", algodURL)
		}
	case IntegrationNetworkFNet:
		if genesisID != FNetGenesisID || genesisHash != FNetGenesisHash {
			return fmt.Errorf("FNet integration requires genesis %s/%s, but ALGOD_URL %s reports %s/%s", FNetGenesisID, FNetGenesisHash, algodURL, genesisID, genesisHash)
		}
		if suggestedConsensus != FNetConsensus || statusConsensus != FNetConsensus {
			return fmt.Errorf("FNet native Falcon integration requires consensus %s, but ALGOD_URL %s reports suggested=%q status=%q", FNetConsensus, algodURL, suggestedConsensus, statusConsensus)
		}
	}
	return nil
}

func isLocalIntegrationEndpoint(raw string) bool {
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
	if ip.IsLoopback() || ip.IsPrivate() {
		return true
	}
	return false
}

// GetSuggestedParams gets the current suggested parameters
func (tc *TestnetConfig) GetSuggestedParams() (types.SuggestedParams, error) {
	sp, err := tc.Client.SuggestedParams().Do(context.Background())
	if err != nil {
		return types.SuggestedParams{}, fmt.Errorf("failed to get suggested params: %w", err)
	}
	return sp, nil
}

// WaitForConfirmation waits for a transaction to be confirmed
func (tc *TestnetConfig) WaitForConfirmation(txid string, maxRounds uint64) (uint64, error) {
	ctx := context.Background()

	// Get initial status
	status, err := tc.Client.Status().Do(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to get status: %w", err)
	}

	startRound := status.LastRound
	currentRound := startRound

	for currentRound < startRound+maxRounds {
		// Check if transaction is confirmed
		txInfo, _, err := tc.Client.PendingTransactionInformation(txid).Do(ctx)
		if err != nil {
			return 0, fmt.Errorf("failed to get transaction info: %w", err)
		}

		if txInfo.ConfirmedRound > 0 {
			// Transaction confirmed
			return txInfo.ConfirmedRound, nil
		}

		// Wait for next round
		status, err = tc.Client.StatusAfterBlock(currentRound).Do(ctx)
		if err != nil {
			return 0, fmt.Errorf("failed to wait for round: %w", err)
		}
		currentRound = status.LastRound
	}

	return 0, fmt.Errorf("transaction not confirmed after %d rounds", maxRounds)
}

// SubmitTransaction submits a signed transaction to the network
func (tc *TestnetConfig) SubmitTransaction(stxn types.SignedTxn) (string, error) {
	rawTxn := msgpack.Encode(stxn)
	txid, err := tc.Client.SendRawTransaction(rawTxn).Do(context.Background())
	if err != nil {
		return "", fmt.Errorf("failed to submit transaction: %w", err)
	}
	return txid, nil
}

// GetAccountInfo gets information for an account
func (tc *TestnetConfig) GetAccountInfo(address string) (uint64, error) {
	acct, err := tc.Client.AccountInformation(address).Do(context.Background())
	if err != nil {
		return 0, fmt.Errorf("failed to get account info: %w", err)
	}
	return acct.Amount, nil
}
