// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sandbox

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestGenerateSeatbeltProfileStateDir(t *testing.T) {
	with := generateSeatbeltProfile(Config{PluginDir: "/tmp/plugin", StateDir: "/tmp/data/plugin-state/foo"})
	if !strings.Contains(with, `(allow file-read* file-write* (subpath "/tmp/data/plugin-state/foo"))`) {
		t.Errorf("state dir should be granted read-write, got:\n%s", with)
	}

	without := generateSeatbeltProfile(Config{PluginDir: "/tmp/plugin"})
	if strings.Contains(without, "plugin-state") {
		t.Error("profile should not reference a state dir when unset")
	}
}

func TestBuildCommandLinuxStateDir(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only test")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bubblewrap not installed")
	}

	withCmd, err := BuildCommand(Config{
		PluginDir:    "/tmp/test-plugin",
		StateDir:     "/tmp/test-data/plugin-state/foo",
		ExecPath:     "/tmp/test-plugin/run.sh",
		AllowNetwork: true,
	})
	if err != nil {
		t.Fatalf("BuildCommand() error: %v", err)
	}
	args := strings.Join(withCmd.Args, " ")
	if !strings.Contains(args, "--bind /tmp/test-data/plugin-state/foo /tmp/test-data/plugin-state/foo") {
		t.Errorf("state dir should be bound read-write, got: %s", args)
	}
	if !strings.Contains(args, "--ro-bind /tmp/test-plugin /tmp/test-plugin") {
		t.Error("plugin dir must remain read-only")
	}

	withoutCmd, err := BuildCommand(Config{
		PluginDir:    "/tmp/test-plugin",
		ExecPath:     "/tmp/test-plugin/run.sh",
		AllowNetwork: true,
	})
	if err != nil {
		t.Fatalf("BuildCommand() error: %v", err)
	}
	if strings.Contains(strings.Join(withoutCmd.Args, " "), "--bind ") {
		t.Error("no writable --bind expected when StateDir is unset")
	}
}
