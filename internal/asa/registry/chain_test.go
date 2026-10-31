// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package registry

import (
	"context"
	"errors"
	"net"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common"
)

// builtinCheckNodes are the public nodes the table is checked against.
var builtinCheckNodes = map[string]string{
	"mainnet": "https://mainnet-api.4160.nodely.dev",
	"testnet": "https://testnet-api.4160.nodely.dev",
}

// TestBuiltinMetadataMatchesChain checks every built-in entry against algod.
// Built-in entries win over cached metadata, so a wrong entry here converts
// display amounts by the wrong power of ten. It skips when a node cannot be
// reached or is throttling, under -short, or with APLANE_SKIP_LIVE_ASA=1. An
// asset whose on-chain name, unit name or decimals differ always fails.
func TestBuiltinMetadataMatchesChain(t *testing.T) {
	if testing.Short() || os.Getenv("APLANE_SKIP_LIVE_ASA") == "1" {
		t.Skip("live ASA check skipped")
	}
	for network, url := range builtinCheckNodes {
		client, err := algod.MakeClient(url, "")
		if err != nil {
			t.Fatal(err)
		}
		all := AllBuiltinMetadata(network)
		ids := make([]uint64, 0, len(all))
		for id := range all {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		for _, id := range ids {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			asset, err := client.GetAssetByID(id).Do(ctx)
			cancel()
			if err != nil {
				var netErr net.Error
				var other common.HTTPError
				var internal common.InternalError
				if errors.As(err, &netErr) || errors.As(err, &internal) ||
					(errors.As(err, &other) && (other.StatusCode == 429 || other.StatusCode >= 500)) {
					t.Skipf("%s node unavailable: %v", network, err)
				}
				t.Errorf("%s asset %d: %v", network, id, err)
				continue
			}
			want, p := all[id], asset.Params
			if p.Decimals != want.Decimals || p.UnitName != want.UnitName || p.Name != want.Name {
				t.Errorf("%s asset %d: built-in (%q, %q, %d decimals), chain (%q, %q, %d decimals)",
					network, id, want.Name, want.UnitName, want.Decimals, p.Name, p.UnitName, p.Decimals)
			}
		}
	}
}
