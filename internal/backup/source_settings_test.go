// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/backup/sourcecontext"
	"github.com/aplane-algo/aplane/internal/noderole"
)

func TestWriteAndInspectSourceSettings(t *testing.T) {
	root := t.TempDir()
	autoApprove := false
	rawHash := strings.Repeat("42", 32)
	if err := writeSourceSettings(root, noderole.RoleSigner, SourceSettingsSnapshot{
		UserAutoApprove: &autoApprove,
		GenesisHashMappings: map[string]string{
			rawHash: "voi-mainnet",
		},
	}); err != nil {
		t.Fatalf("writeSourceSettings() error = %v", err)
	}

	inspection := inspectSourceSettings(root, string(noderole.RoleSigner))
	if inspection.Status != sourcecontext.StatusUnverified ||
		inspection.SHA256 == "" ||
		inspection.Warning != "" {
		t.Fatalf("inspectSourceSettings() = %+v, want unverified valid metadata", inspection)
	}
	if inspection.Projection.UserAutoApprove == nil ||
		*inspection.Projection.UserAutoApprove {
		t.Fatalf("UserAutoApprove = %v, want false", inspection.Projection.UserAutoApprove)
	}
	if len(inspection.Projection.GenesisHashMappings) != 1 ||
		inspection.Projection.GenesisHashMappings[0].GenesisHash == rawHash ||
		inspection.Projection.GenesisHashMappings[0].Network != "voi-mainnet" {
		t.Fatalf("GenesisHashMappings = %+v, want canonical mapping", inspection.Projection.GenesisHashMappings)
	}
	data, err := os.ReadFile(filepath.Join(root, SourceSettingsFileName))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"algod", "token", "server", "endpoint"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("source settings unexpectedly contain %q: %s", forbidden, data)
		}
	}
}

func TestSourceSettingsSentryOmitsApprovalDefault(t *testing.T) {
	root := t.TempDir()
	if err := writeSourceSettings(root, noderole.RoleSentry, SourceSettingsSnapshot{}); err != nil {
		t.Fatalf("writeSourceSettings() error = %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, SourceSettingsFileName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "user_auto_approve") {
		t.Fatalf("sentry source settings carry user_auto_approve: %s", data)
	}
	inspection := inspectSourceSettings(root, string(noderole.RoleSentry))
	if inspection.Status != sourcecontext.StatusUnverified ||
		inspection.Projection.UserAutoApprove != nil {
		t.Fatalf("inspectSourceSettings() = %+v, want sentry unverified without approval default", inspection)
	}
}

func TestWriteSourceSettingsRequiresRoleAppropriateApprovalDefault(t *testing.T) {
	if err := writeSourceSettings(
		t.TempDir(),
		noderole.RoleSigner,
		SourceSettingsSnapshot{},
	); err == nil || !strings.Contains(err.Error(), "require user_auto_approve") {
		t.Fatalf("writeSourceSettings(signer) error = %v, want missing approval rejection", err)
	}
	autoApprove := true
	if err := writeSourceSettings(
		t.TempDir(),
		noderole.RoleSentry,
		SourceSettingsSnapshot{UserAutoApprove: &autoApprove},
	); err == nil || !strings.Contains(err.Error(), "must not carry") {
		t.Fatalf("writeSourceSettings(sentry) error = %v, want approval rejection", err)
	}
}

func TestInspectSourceSettingsClassifiesMissingAndInvalid(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		inspection := inspectSourceSettings(t.TempDir(), string(noderole.RoleSigner))
		if inspection.Status != sourcecontext.StatusMissing || inspection.Warning != "" {
			t.Fatalf("inspectSourceSettings() = %+v, want missing", inspection)
		}
	})

	tests := []struct {
		name string
		data []byte
		role string
	}{
		{name: "malformed", data: []byte(`{`), role: string(noderole.RoleSigner)},
		{
			name: "unknown field",
			data: []byte(`{
				"schema":"aplane.backup.source-settings.v1",
				"schema_version":1,
				"user_auto_approve":false,
				"future":true
			}`),
			role: string(noderole.RoleSigner),
		},
		{
			name: "unknown role",
			data: []byte(`{
				"schema":"aplane.backup.source-settings.v1",
				"schema_version":1,
				"user_auto_approve":false
			}`),
			role: "unknown",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, SourceSettingsFileName), tt.data, 0o600); err != nil {
				t.Fatal(err)
			}
			inspection := inspectSourceSettings(root, tt.role)
			if inspection.Status != sourcecontext.StatusInvalid ||
				inspection.Warning == "" ||
				inspection.SHA256 != "" ||
				inspection.Projection.UserAutoApprove != nil {
				t.Fatalf("inspectSourceSettings() = %+v, want invalid without values", inspection)
			}
		})
	}
}

func TestInspectSourceSettingsRejectsOversizedAndSymlinkFiles(t *testing.T) {
	t.Run("oversized", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(
			filepath.Join(root, SourceSettingsFileName),
			make([]byte, maxSourceSettingsBytes+1),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		inspection := inspectSourceSettings(root, string(noderole.RoleSigner))
		if inspection.Status != sourcecontext.StatusInvalid ||
			!strings.Contains(inspection.Warning, "size limit") {
			t.Fatalf("inspectSourceSettings() = %+v, want oversized invalid", inspection)
		}
	})

	t.Run("symlink", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "target.json")
		if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(root, SourceSettingsFileName)); err != nil {
			t.Fatal(err)
		}
		inspection := inspectSourceSettings(root, string(noderole.RoleSigner))
		if inspection.Status != sourcecontext.StatusInvalid {
			t.Fatalf("inspectSourceSettings() = %+v, want symlink invalid", inspection)
		}
	})
}
