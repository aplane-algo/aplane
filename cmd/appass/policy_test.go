// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"strings"
	"testing"
)

func TestValidateManagedFileOwner_LocalMode(t *testing.T) {
	t.Parallel()

	path := "/tmp/config.yaml"
	current := currentUsername()

	if err := validateManagedFileOwner(path, current, true, nil); err != nil {
		t.Fatalf("validateManagedFileOwner() error = %v", err)
	}
	if err := validateManagedFileOwner(path, "root", true, nil); err == nil {
		t.Fatal("validateManagedFileOwner() error = nil, want mixed-mode rejection")
	}
}

func TestValidateManagedFileOwner_LocalModeProductionOwnerHint(t *testing.T) {
	t.Parallel()

	err := validateManagedFileOwner("/var/lib/apsigner/config.yaml", "aplane", true, nil)
	if err == nil {
		t.Fatal("validateManagedFileOwner() error = nil, want production hint")
	}
	for _, want := range []string{
		"this looks like a systemd-managed signer data directory",
		"1. sudo systemctl stop apsigner",
		"2. sudo appass -d /var/lib/apsigner",
		"3. sudo systemctl start apsigner",
		"sudo appass -d /var/lib/apsigner",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want substring %q", err.Error(), want)
		}
	}
}

func TestValidateManagedFileOwner_ProductionMode(t *testing.T) {
	t.Parallel()

	path := "/tmp/config.yaml"
	svc := &serviceInfo{User: "apadmin"}

	for _, owner := range []string{"root", "apadmin"} {
		if err := validateManagedFileOwner(path, owner, false, svc); err != nil {
			t.Fatalf("validateManagedFileOwner(%q) error = %v", owner, err)
		}
	}
	if err := validateManagedFileOwner(path, currentUsername(), false, svc); err == nil {
		t.Fatal("validateManagedFileOwner() error = nil, want production-mode rejection")
	}
}
