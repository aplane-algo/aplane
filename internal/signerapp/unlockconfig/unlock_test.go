// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package unlockconfig

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestMethod(t *testing.T) {
	tests := []struct {
		name string
		cfg  *UnlockConfig
		want string
	}{
		{name: "nil config", cfg: nil, want: "none"},
		{name: "empty argv", cfg: &UnlockConfig{}, want: "none"},
		{name: "appass-file bare", cfg: &UnlockConfig{PassphraseCommandArgv: []string{"appass-file", "/tmp/secret"}}, want: "passfile"},
		{name: "appass-file absolute", cfg: &UnlockConfig{PassphraseCommandArgv: []string{"/usr/local/bin/appass-file", "/tmp/secret"}}, want: "passfile"},
		{name: "appass-systemd-creds bare", cfg: &UnlockConfig{PassphraseCommandArgv: []string{"appass-systemd-creds"}}, want: "systemd-creds"},
		{name: "appass-systemd-creds absolute", cfg: &UnlockConfig{PassphraseCommandArgv: []string{"/usr/bin/appass-systemd-creds"}}, want: "systemd-creds"},
		{name: "custom command", cfg: &UnlockConfig{PassphraseCommandArgv: []string{"/usr/bin/my-unlock-helper"}}, want: "custom"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.Method(); got != tt.want {
				t.Errorf("Method() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoadUnlockConfigMarksAParseFailureMalformed(t *testing.T) {
	root := t.TempDir()
	path := UnlockConfigPath(root)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("passphrase_command_argv: [unterminated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadUnlockConfig(root); !errors.Is(err, ErrMalformed) {
		t.Fatalf("LoadUnlockConfig() error = %v, want ErrMalformed", err)
	}
}

func TestLoadPassphraseHelperReadsProductStore(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	want := &UnlockConfig{
		PassphraseCommandArgv: []string{"identity-pass", "/tmp/identity"},
		PassphraseCommandEnv:  map[string]string{"IDENTITY": "1"},
	}
	if err := SaveUnlockConfig(root, want); err != nil {
		t.Fatalf("SaveUnlockConfig() error = %v", err)
	}

	got, err := LoadPassphraseHelper(root)
	if err != nil {
		t.Fatalf("LoadPassphraseHelper() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("LoadPassphraseHelper() = %+v, want %+v", got, want)
	}
}

func TestLoadPassphraseHelperWithoutHelperIsNil(t *testing.T) {
	t.Parallel()

	got, err := LoadPassphraseHelper(t.TempDir())
	if err != nil || got != nil {
		t.Fatalf("LoadPassphraseHelper() = %+v, %v; want nil, nil", got, err)
	}
}
