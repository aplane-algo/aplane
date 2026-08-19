// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"os"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

func TestApstoreInitializeBootstrapsUninitializedStore(t *testing.T) {
	env := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{})
	paths := storepaths.NewPaths(env.SignerDataDir)
	identityDir := paths.ProductDir()
	if err := os.RemoveAll(identityDir); err != nil {
		t.Fatalf("failed to remove cloned identity dir: %v", err)
	}
	if err := os.Remove(paths.NodeRolePath()); err != nil && !os.IsNotExist(err) {
		t.Fatalf("failed to remove cloned node role: %v", err)
	}

	const passphrase = "initialize-passphrase-for-integration"
	apstore := harness.NewApStoreHarness(t, env.SignerDataDir)
	output, err := apstore.RunWithInput(passphrase+"\n"+passphrase+"\n", "initialize")
	if err != nil {
		t.Fatalf("apstore initialize failed: %v\noutput:\n%s", err, output)
	}
	if !strings.Contains(output, "start apsigner to unlock and use this keystore") {
		t.Fatalf("initialize output did not report offline bootstrap completion:\n%s", output)
	}

	if !crypto.KeyringExistsIn(paths.KeystoreMetadataDir()) {
		t.Fatal("keystore metadata missing after apstore initialize")
	}
	// New stores are generational: the keys namespace lives in the first
	// generation behind CURRENT.
	active, err := genstore.ResolveActive(paths)
	if err != nil {
		t.Fatalf("ResolveActive() error = %v", err)
	}
	if _, err := os.Stat(active.KeysDir()); err != nil {
		t.Fatalf("keys dir missing after apstore initialize: %v", err)
	}

	t.Setenv("TEST_PASSPHRASE", passphrase)
	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer after initialize: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	token := readSignerToken(t, signerd)
	client := signerclient.NewSignerClientWithToken(signerd.GetURL(), token)
	keys, err := client.GetKeys()
	if err != nil {
		t.Fatalf("failed to fetch keys after initialize: %v", err)
	}
	if keys.Locked {
		t.Fatal("signer is locked after apstore initialize")
	}
}
