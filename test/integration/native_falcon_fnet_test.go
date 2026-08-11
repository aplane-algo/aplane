// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"crypto/sha512"
	"os"
	"strings"
	"testing"

	"github.com/algorand/falcon"
	algomnemonic "github.com/algorand/go-algorand-sdk/v2/mnemonic"
	securecrypto "github.com/aplane-algo/aplane/internal/crypto"
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

	address := fnetFalconAddressFromMnemonicFile(t)
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

func fnetFalconAddressFromMnemonicFile(t *testing.T) string {
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
	entropy, err := algomnemonic.ToKey(strings.Join(words, " "))
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
