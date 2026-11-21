// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package serverconfig

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Without a config.yaml the signer runs on the defaults, and they are
// resolved the way a file's values are: the SSH host key lives under the data
// directory, not under whatever directory the process was started in. A file
// that sets nothing gives exactly the same configuration as no file.
func TestMissingConfigResolvesLikeAnEmptyFile(t *testing.T) {
	t.Chdir(t.TempDir())
	dataDir := t.TempDir()

	missing, err := LoadServerConfig(dataDir)
	if err != nil {
		t.Fatalf("LoadServerConfig(no file): %v", err)
	}
	if want := filepath.Join(dataDir, ".ssh", "ssh_host_key"); missing.Endpoint.SSH.HostKeyPath != want {
		t.Fatalf("host key path without a config file = %q, want %q", missing.Endpoint.SSH.HostKeyPath, want)
	}

	if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	empty, err := LoadServerConfig(dataDir)
	if err != nil {
		t.Fatalf("LoadServerConfig(empty file): %v", err)
	}
	if !reflect.DeepEqual(missing, empty) {
		t.Fatalf("no config file and an empty one differ:\n no file: %+v\n empty:   %+v", missing, empty)
	}
}

// A signer config.yaml with no YAML document is refused, never read as the
// defaults: a file truncated to nothing would otherwise start without the
// settings it held.
func TestEmptyConfigFileIsRefused(t *testing.T) {
	for _, body := range []string{"", "\n", "  \n\n", "# only a comment\n"} {
		dataDir := t.TempDir()
		path := filepath.Join(dataDir, "config.yaml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		want := "config file " + path + " is empty"
		if _, err := LoadServerConfig(dataDir); err == nil || err.Error() != want {
			t.Errorf("%q: LoadServerConfig error = %v, want %q", body, err, want)
		}
		if _, err := LoadServerConfigStrict(dataDir); err == nil || err.Error() != want {
			t.Errorf("%q: LoadServerConfigStrict error = %v, want %q", body, err, want)
		}
	}
}
