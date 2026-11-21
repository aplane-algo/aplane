// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseServiceFileReadsSignerDaemonUnit(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "apsigner.service")
	unit := `[Unit]
Description=APlane Signer daemon (apsigner)

[Service]
ExecStart=/usr/local/bin/apsigner
User=aplane
Group=aplane
LoadCredentialEncrypted=aplane-passphrase:/var/lib/apsigner/identities/default/passphrase.cred
`
	if err := os.WriteFile(path, []byte(unit), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	info, err := parseServiceFile(path)
	if err != nil {
		t.Fatalf("parseServiceFile() error = %v", err)
	}
	if info.BinDir != "/usr/local/bin" {
		t.Fatalf("BinDir = %q, want /usr/local/bin", info.BinDir)
	}
	if info.User != "aplane" {
		t.Fatalf("User = %q, want aplane", info.User)
	}
	if info.Group != "aplane" {
		t.Fatalf("Group = %q, want aplane", info.Group)
	}
	if !info.HasLoadCred {
		t.Fatal("HasLoadCred = false, want true")
	}
}
