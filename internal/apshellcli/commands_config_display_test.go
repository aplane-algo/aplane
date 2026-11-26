// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/config"
)

// config prints through the shell's writer, which is what apconsole shows:
// the process's stdout goes nowhere there. The networks come in order.
func TestConfigPrintsThroughTheShell(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), []byte(`
network: testnet
networks:
  testnet:
    algod:
      server: http://localhost:4001
  mainnet:
    algod:
      server: http://localhost:4002
  betanet:
    algod:
      server: http://localhost:4003
`), 0o600); err != nil {
		t.Fatal(err)
	}
	session, err := NewSession("testnet", config.DefaultConfig(), dataDir, nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	t.Cleanup(session.Shutdown)
	for range 5 {
		output, _, err := session.ExecuteLineCaptured("config")
		if err != nil {
			t.Fatalf("config error = %v", err)
		}
		at := func(s string) int {
			t.Helper()
			i := strings.Index(output, s)
			if i < 0 {
				t.Fatalf("config output has no %q:\n%s", s, output)
			}
			return i
		}
		at("Data dir:    " + dataDir)
		if b, m, n := at("algod.betanet:"), at("algod.mainnet:"), at("algod.testnet:"); b > m || m > n {
			t.Fatalf("networks out of order:\n%s", output)
		}
	}
}
