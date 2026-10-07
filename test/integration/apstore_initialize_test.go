// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"os"
	"path/filepath"
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

	if !crypto.StoreRootExistsIn(paths.KeystoreMetadataDir()) {
		t.Fatal("keystore metadata missing after apstore initialize")
	}
	// New stores are generational: the keys namespace lives in the first
	// generation selected by store-root.enc.
	active, kr, err := genstore.ResolveStoreRoot(paths, []byte(passphrase))
	if err != nil {
		t.Fatalf("ResolveStoreRoot() error = %v", err)
	}
	kr.Zero()
	if _, err := os.Stat(active.KeysDir()); err != nil {
		t.Fatalf("keys dir missing after apstore initialize: %v", err)
	}

	// A fresh store enrolls no client; enroll the test client's key the way
	// an operator approval would, so the harness tunnel is accepted.
	clientKey, err := os.ReadFile(filepath.Join(env.ClientDataDir, ".ssh", "id_ed25519.pub"))
	if err != nil {
		t.Fatalf("read client public key: %v", err)
	}
	registryDir := filepath.Join(paths.ProductDir(), ".ssh")
	if err := os.MkdirAll(registryDir, 0o700); err != nil {
		t.Fatalf("create registry dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(registryDir, "authorized_keys"), clientKey, 0o600); err != nil {
		t.Fatalf("write enrolled client registry: %v", err)
	}

	t.Setenv("TEST_PASSPHRASE", passphrase)
	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer after initialize: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	client := signerclient.NewSignerClient(signerd.GetURL())
	keys, err := client.GetKeys()
	if err != nil {
		t.Fatalf("failed to fetch keys after initialize: %v", err)
	}
	if keys.Locked {
		t.Fatal("signer is locked after apstore initialize")
	}
}
