// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestManagedModePolicyPathsAreIdentityScoped(t *testing.T) {
	dataDir := filepath.Join("store", "root")
	identityDir := filepath.Join(dataDir, "identities", "secondary")
	want := []string{
		filepath.Join(dataDir, "config.yaml"),
		filepath.Join(identityDir, "unlock.yaml"),
		filepath.Join(identityDir, "passphrase"),
		filepath.Join(identityDir, "passphrase.cred"),
	}
	if got := managedModePolicyPaths(dataDir, "secondary"); !reflect.DeepEqual(got, want) {
		t.Fatalf("managedModePolicyPaths() = %#v, want %#v", got, want)
	}
}

func TestValidateManagedFileOwner_LocalMode(t *testing.T) {
	t.Parallel()

	path := "/tmp/config.yaml"
	current := currentUsername()
	dataDir := "/tmp"

	if err := validateManagedFileOwner(dataDir, path, current, true, nil); err != nil {
		t.Fatalf("validateManagedFileOwner() error = %v", err)
	}
	if err := validateManagedFileOwner(dataDir, path, "root", true, nil); err == nil {
		t.Fatal("validateManagedFileOwner() error = nil, want mixed-mode rejection")
	}
}

func TestValidateManagedFileOwner_LocalModeProductionOwnerHint(t *testing.T) {
	t.Parallel()

	dataDir := "/srv/custom-signer"
	path := filepath.Join(dataDir, "identities", "secondary", "unlock.yaml")
	err := validateManagedFileOwner(dataDir, path, "aplane", true, nil)
	if err == nil {
		t.Fatal("validateManagedFileOwner() error = nil, want production hint")
	}
	for _, want := range []string{
		"this looks like a systemd-managed signer data directory",
		"1. sudo systemctl stop apsigner",
		"2. sudo appass -d /srv/custom-signer",
		"3. sudo systemctl start apsigner",
		"sudo appass -d /srv/custom-signer",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want substring %q", err.Error(), want)
		}
	}
}

func TestValidateManagedFileOwner_ProductionMode(t *testing.T) {
	t.Parallel()

	path := "/tmp/config.yaml"
	svc := &serviceInfo{User: "apadmin", StoreUID: 123, StoreGID: 456}

	for _, owner := range []string{"root", "apadmin"} {
		if err := validateManagedFileOwner("/tmp", path, owner, false, svc); err != nil {
			t.Fatalf("validateManagedFileOwner(%q) error = %v", owner, err)
		}
	}
	if err := validateManagedFileOwner("/tmp", path, currentUsername(), false, svc); err == nil {
		t.Fatal("validateManagedFileOwner() error = nil, want production-mode rejection")
	}
}

func TestBindManagedServicePrincipalIDsRejectsUnitDrift(t *testing.T) {
	t.Parallel()

	svc := &serviceInfo{User: "aplane", Group: "aplane"}
	err := bindManagedServicePrincipalIDs(svc, 1001, 1002, 1001, 1003)
	if err == nil {
		t.Fatal("bindManagedServicePrincipalIDs() error = nil, want principal mismatch")
	}
	if !strings.Contains(err.Error(), "systemd unit resolves to 1001:1003") ||
		!strings.Contains(err.Error(), "service-principal.json records 1001:1002") {
		t.Fatalf("error = %q, want both ownership authorities", err)
	}
}

func TestBindManagedServicePrincipalIDsPinsMetadataOwner(t *testing.T) {
	t.Parallel()

	svc := &serviceInfo{User: "aplane", Group: "aplane"}
	if err := bindManagedServicePrincipalIDs(svc, 1001, 1002, 1001, 1002); err != nil {
		t.Fatalf("bindManagedServicePrincipalIDs() error = %v", err)
	}
	if svc.StoreUID != 1001 || svc.StoreGID != 1002 {
		t.Fatalf("store owner = %d:%d, want 1001:1002", svc.StoreUID, svc.StoreGID)
	}
}
