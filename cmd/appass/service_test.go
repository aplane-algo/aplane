// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDefaultServiceFileUsesSignerDaemonUnit(t *testing.T) {
	t.Parallel()

	if got, want := defaultServiceFile, "/etc/systemd/system/apsigner.service"; got != want {
		t.Fatalf("defaultServiceFile = %q, want %q", got, want)
	}
}

func TestCandidateServiceFilesIncludeCommonSystemdUnitLocations(t *testing.T) {
	t.Parallel()

	want := []string{
		"/etc/systemd/system/apsigner.service",
		"/lib/systemd/system/apsigner.service",
		"/usr/lib/systemd/system/apsigner.service",
	}
	if !reflect.DeepEqual(serviceFileCandidates, want) {
		t.Fatalf("serviceFileCandidates = %#v, want %#v", serviceFileCandidates, want)
	}
}

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

func TestCandidateServiceFilesHonorsTestOverride(t *testing.T) {
	original := currentServiceFile()
	setServiceFile(filepath.Join(t.TempDir(), "apsigner.service"))
	t.Cleanup(func() { setServiceFile(original) })

	if got, want := candidateServiceFiles(), []string{currentServiceFile()}; !reflect.DeepEqual(got, want) {
		t.Fatalf("candidateServiceFiles() = %#v, want %#v", got, want)
	}
}
