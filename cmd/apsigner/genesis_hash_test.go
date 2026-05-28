// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"encoding/base64"
	"testing"

	apconfig "github.com/aplane-algo/aplane/internal/config"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func testnetGenesisHashBytes(t *testing.T) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(apconfig.AlgorandTestnetGenesisHash)
	if err != nil {
		t.Fatalf("decode testnet genesis hash: %v", err)
	}
	return decoded
}

func testnetGenesisHashDigest(t *testing.T) types.Digest {
	t.Helper()
	var out types.Digest
	copy(out[:], testnetGenesisHashBytes(t))
	return out
}
