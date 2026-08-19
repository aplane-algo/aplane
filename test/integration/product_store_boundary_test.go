// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/test/integration/harness"
)

func TestExtraProductStoreEntryPreventsSignerStartup(t *testing.T) {
	env := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{})
	aliceDir := filepath.Join(env.SignerDataDir, "identities", "alice")
	if err := os.MkdirAll(filepath.Join(aliceDir, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	// Seed selector-bearing artifacts to prove layout validation runs before a
	// second token or SSH enrollment can become an authentication route.
	if err := os.WriteFile(filepath.Join(aliceDir, "aplane.token"), []byte("not-a-product-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(aliceDir, ".ssh", "authorized_keys"), []byte("not-an-ssh-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err == nil {
		_ = signerd.Stop()
		t.Fatal("apsigner started with an extra identity entry")
	}
	logs, err := signerd.GetLogs()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs, `unsupported entry "alice" under identities`) ||
		!strings.Contains(logs, `supports only the "default" product store`) {
		t.Fatalf("startup logs did not report the product-store integrity boundary:\n%s", logs)
	}

	client := &http.Client{Timeout: 250 * time.Millisecond}
	if resp, err := client.Get(signerd.GetURL() + "/health"); err == nil {
		_ = resp.Body.Close()
		t.Fatalf("HTTP route became reachable after rejected startup: status %d", resp.StatusCode)
	}

	sshCfg := mustLoadClientSSHConfig(t)
	sshAddr := net.JoinHostPort(sshCfg.Host, strconv.Itoa(sshCfg.Port))
	if conn, err := net.DialTimeout("tcp", sshAddr, 250*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatalf("SSH route %s became reachable after rejected startup", sshAddr)
	}
}
