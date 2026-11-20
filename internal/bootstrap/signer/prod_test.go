// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signer

import (
	"path/filepath"
	"testing"
)

// The refusals name the exact command to run instead, quoted for a shell.
func TestEnforceExecutionModeRefusalText(t *testing.T) {
	local := filepath.Join(t.TempDir(), "it's local")
	quotedLocal := "'" + filepath.Dir(local) + "/it'\"'\"'s local'"
	managed := "/var/lib/apsigner"
	tests := []struct {
		binary      string
		dataDir     string
		prodManaged bool
		euid        int
		args        []string
		want        string
	}{
		{"appass", local, false, 0, nil, "local signer data directory " + local + " must not be managed as root; rerun without sudo:\n" +
			"  appass -d " + quotedLocal},
		{"appass", managed, true, 1000, nil, "systemd-managed data directory /var/lib/apsigner requires root for appass; run:\n" +
			"  sudo appass -d /var/lib/apsigner"},
		{"apstore", managed, true, 1000, []string{"rebuild", "/mnt/a b.tar.gz", "--address", ""},
			"systemd-managed data directory /var/lib/apsigner requires root for apstore; run:\n" +
				"  sudo apstore -d /var/lib/apsigner rebuild '/mnt/a b.tar.gz' --address ''"},
		{"appass", managed, true, 0, nil, ""},
		{"appass", local, false, 1000, nil, ""},
	}
	for _, tt := range tests {
		err := EnforceExecutionMode(tt.binary, tt.dataDir, tt.prodManaged, tt.euid, tt.args)
		got := ""
		if err != nil {
			got = err.Error()
		}
		if got != tt.want {
			t.Fatalf("%s mode(%s, managed=%v, euid=%d):\n got %q\nwant %q", tt.binary, tt.dataDir, tt.prodManaged, tt.euid, got, tt.want)
		}
	}
}
