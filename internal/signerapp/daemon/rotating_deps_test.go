// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/config"
)

// The chain reader takes the Indexer from the signer's configuration, per
// network, as it takes algod; a network without one has none.
func TestChainReaderTakesTheIndexerFromTheConfig(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	server.config.Indexer = map[string]*config.IndexerNetworkConfig{"testnet": {Server: "http://mock-indexer", Token: "t"}}
	reader := server.chainReader()
	if got := reader.IndexerConfig("testnet"); got == nil || got.Server != "http://mock-indexer" || got.Token != "t" {
		t.Fatalf("testnet Indexer = %+v", got)
	}
	if got := reader.IndexerConfig("mainnet"); got != nil {
		t.Fatalf("mainnet Indexer = %+v, want none", got)
	}
}
