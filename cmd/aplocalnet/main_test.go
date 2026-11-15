// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/aplocalnet"
)

func TestModelViewShowsConfiguredKMDURL(t *testing.T) {
	m := newModel(aplocalnet.Options{
		SignerDataDir: t.TempDir(),
		AlgodURL:      "http://localhost:4001",
		KMDURL:        "http://localhost:4012",
		IndexerURL:    "http://localhost:8980",
	})
	m.busy = false

	view := m.View()
	if !strings.Contains(view, "http://localhost:4012") {
		t.Fatalf("view missing KMD URL:\n%s", view)
	}
	if !strings.Contains(view, "localhost:8980") {
		t.Fatalf("view missing Indexer URL:\n%s", view)
	}
	if strings.Contains(view, "u algod URL") {
		t.Fatalf("view still advertises interactive algod URL edit:\n%s", view)
	}
	if !strings.Contains(view, "apply") || strings.Contains(view, "enter setup") {
		t.Fatalf("view should label the primary action as apply:\n%s", view)
	}
}

func TestApplyTargetSpecifiedUsesFlagsOrEnv(t *testing.T) {
	t.Setenv("APCLIENT_DATA", "")
	t.Setenv("APSIGNER_DATA", "")
	if clientTargetSpecified("") {
		t.Fatal("client target unexpectedly specified")
	}
	if signerTargetSpecified("") {
		t.Fatal("signer target unexpectedly specified")
	}
	if !clientTargetSpecified("/tmp/client") {
		t.Fatal("client flag should specify a client target")
	}
	if !signerTargetSpecified("/tmp/signer") {
		t.Fatal("signer flag should specify a signer target")
	}

	t.Setenv("APCLIENT_DATA", "/tmp/client-env")
	t.Setenv("APSIGNER_DATA", "/tmp/signer-env")
	if !clientTargetSpecified("") {
		t.Fatal("APCLIENT_DATA should specify a client target")
	}
	if !signerTargetSpecified("") {
		t.Fatal("APSIGNER_DATA should specify a signer target")
	}
}

func TestModelViewShowsTheIndexerTheSignerWillName(t *testing.T) {
	t.Setenv("APLANE_LOCALNET_INDEXER_URL", "")
	withEntry := t.TempDir()
	if err := os.WriteFile(filepath.Join(withEntry, "config.yaml"), []byte("networks:\n  localnet:\n    indexer:\n      server: http://indexer.example:8990\n      token: secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, dir, algod, want string
	}{
		{"default algod, no entry", t.TempDir(), aplocalnet.DefaultAlgodURL, "localhost:8980"},
		{"another algod, no entry", t.TempDir(), "http://localhost:4011", "none: pass --indexer-url"},
		{"another algod, an entry", withEntry, "http://localhost:4011", "indexer.example:8990, already in the signer config, left as it is"},
		{"default algod, an entry", withEntry, aplocalnet.DefaultAlgodURL, "indexer.example:8990, already in the signer config, left as it is"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newModel(aplocalnet.Options{SignerDataDir: tc.dir, AlgodURL: tc.algod})
			m.busy = false
			view := m.View()
			if !strings.Contains(view, tc.want) || strings.Contains(view, "secret") {
				t.Fatalf("view does not show %q (or shows the token):\n%s", tc.want, view)
			}
		})
	}
}
