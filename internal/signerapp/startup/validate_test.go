// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package startup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/serverconfig"
	utilkeys "github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/storeperm"
)

func TestValidateRequiresSSHDefaults(t *testing.T) {
	t.Parallel()

	cfg := serverconfig.DefaultServerConfig()
	runtime := &RuntimeState{}

	if _, err := Validate(&cfg, runtime, utilkeys.NewPaths(t.TempDir()), "default"); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
}

func TestValidateRejectsInvalidSSHConfig(t *testing.T) {
	t.Parallel()

	cfg := serverconfig.DefaultServerConfig()
	cfg.Endpoint.SSH.HostKeyPath = ""
	runtime := &RuntimeState{}

	if _, err := Validate(&cfg, runtime, utilkeys.NewPaths(t.TempDir()), "default"); err == nil {
		t.Fatal("Validate() error = nil, want invalid ssh configuration error")
	}
}

func TestBlockManualProdStart(t *testing.T) {
	t.Run("allows local instance without marker", func(t *testing.T) {
		dataDir := t.TempDir()
		setNoSystemdEnv(t)
		if err := BlockManualProdStart(dataDir); err != nil {
			t.Fatalf("BlockManualProdStart() error = %v, want nil", err)
		}
	})

	t.Run("blocks managed marker outside systemd", func(t *testing.T) {
		dataDir := t.TempDir()
		setNoSystemdEnv(t)
		writeProdMarker(t, dataDir)

		err := BlockManualProdStart(dataDir)
		if err == nil {
			t.Fatal("BlockManualProdStart() error = nil, want refusal")
		}
		if !strings.Contains(err.Error(), "systemctl start apsigner") {
			t.Fatalf("BlockManualProdStart() error = %q, want systemctl hint", err.Error())
		}
	})

	t.Run("allows managed marker under systemd", func(t *testing.T) {
		dataDir := t.TempDir()
		writeProdMarker(t, dataDir)
		t.Setenv(systemdManagedInstanceEnv, "1")

		if err := BlockManualProdStart(dataDir); err != nil {
			t.Fatalf("BlockManualProdStart() error = %v, want nil", err)
		}
	})
}

func TestValidateProductionStorePermissionsUsesManagedServicePrincipal(t *testing.T) {
	dataDir := t.TempDir()
	writeProdMarker(t, dataDir)
	originalAudit := auditPrivateStore
	originalOwner := managedServiceOwner
	t.Cleanup(func() {
		auditPrivateStore = originalAudit
		managedServiceOwner = originalOwner
	})
	managedServiceOwner = func(string) (int, int, error) {
		return os.Geteuid(), os.Getegid(), nil
	}
	var got storeperm.AuditOptions
	auditPrivateStore = func(opts storeperm.AuditOptions) ([]storeperm.Finding, error) {
		got = opts
		return nil, nil
	}
	if err := ValidateProductionStorePermissions(dataDir); err != nil {
		t.Fatalf("ValidateProductionStorePermissions() error = %v", err)
	}
	want := storeperm.ProductionAuditOptions(dataDir, os.Geteuid(), os.Getegid())
	if got != want {
		t.Fatal("production validation did not use the strict production audit policy")
	}
}

func TestValidateProductionStorePermissionsRejectsServicePrincipalMismatch(t *testing.T) {
	dataDir := t.TempDir()
	writeProdMarker(t, dataDir)
	originalAudit := auditPrivateStore
	originalOwner := managedServiceOwner
	t.Cleanup(func() {
		auditPrivateStore = originalAudit
		managedServiceOwner = originalOwner
	})
	managedServiceOwner = func(string) (int, int, error) {
		return os.Geteuid() + 1, os.Getegid(), nil
	}
	auditPrivateStore = func(storeperm.AuditOptions) ([]storeperm.Finding, error) {
		t.Fatal("store audit ran despite service principal mismatch")
		return nil, nil
	}

	err := ValidateProductionStorePermissions(dataDir)
	if err == nil || !strings.Contains(err.Error(), "service principal mismatch") ||
		!strings.Contains(err.Error(), "systemd-setup") {
		t.Fatalf("ValidateProductionStorePermissions() error = %v, want setup-specific principal mismatch", err)
	}
}

func TestValidateProductionStorePermissionsReturnsMigrationHint(t *testing.T) {
	dataDir := t.TempDir()
	writeProdMarker(t, dataDir)
	originalAudit := auditPrivateStore
	originalOwner := managedServiceOwner
	t.Cleanup(func() {
		auditPrivateStore = originalAudit
		managedServiceOwner = originalOwner
	})
	managedServiceOwner = func(string) (int, int, error) {
		return os.Geteuid(), os.Getegid(), nil
	}
	auditPrivateStore = func(storeperm.AuditOptions) ([]storeperm.Finding, error) {
		return []storeperm.Finding{{Path: dataDir, Code: "mode", Detail: "mode is 0770"}}, nil
	}
	err := ValidateProductionStorePermissions(dataDir)
	if err == nil || !strings.Contains(err.Error(), "permissions migrate") {
		t.Fatalf("ValidateProductionStorePermissions() error = %v, want migration hint", err)
	}
}

func TestValidateProductionStorePermissionsReturnsManualAncestorRepairHint(t *testing.T) {
	dataDir := t.TempDir()
	writeProdMarker(t, dataDir)
	originalAudit := auditPrivateStore
	originalOwner := managedServiceOwner
	t.Cleanup(func() {
		auditPrivateStore = originalAudit
		managedServiceOwner = originalOwner
	})
	managedServiceOwner = func(string) (int, int, error) {
		return os.Geteuid(), os.Getegid(), nil
	}
	unsafeAncestor := filepath.Dir(dataDir)
	for _, code := range []string{"ancestor-write", "ancestor-owner", "ancestor-type"} {
		t.Run(code, func(t *testing.T) {
			auditPrivateStore = func(storeperm.AuditOptions) ([]storeperm.Finding, error) {
				return []storeperm.Finding{{
					Path: unsafeAncestor, Code: code, Detail: "unsafe store ancestor",
				}}, nil
			}
			err := ValidateProductionStorePermissions(dataDir)
			if err == nil || !strings.Contains(err.Error(), unsafeAncestor) ||
				!strings.Contains(err.Error(), "permissions migrate cannot repair") ||
				!strings.Contains(err.Error(), "permissions audit") {
				t.Fatalf("ValidateProductionStorePermissions() error = %v, want manual ancestor repair guidance", err)
			}
		})
	}
}

func writeProdMarker(t *testing.T, dataDir string) {
	t.Helper()
	path := filepath.Join(dataDir, prodMarkerFile)
	if err := os.WriteFile(path, []byte("systemd-managed\n"), 0o640); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}

func setNoSystemdEnv(t *testing.T) {
	t.Helper()
	t.Setenv(systemdManagedInstanceEnv, "")
}
