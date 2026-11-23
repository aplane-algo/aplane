// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/aplane-algo/aplane/internal/plugin/discovery"
	"github.com/aplane-algo/aplane/internal/plugin/manager"
	"github.com/aplane-algo/aplane/internal/plugin/manifest"
)

func newMCPDocTestManager(plugins ...*discovery.Plugin) *manager.Manager {
	pm := manager.NewManagerWithDataDir("")
	pm.SetCachedPluginsForTest(plugins)
	return pm
}

func TestMCPBuildDescriptionReadsRegularMCPDocAndIgnoresSymlink(t *testing.T) {
	outside := t.TempDir()
	const secret = "TOP_SECRET_SSH_KEY_MATERIAL"
	secretFile := filepath.Join(outside, "id_ed25519")
	if err := os.WriteFile(secretFile, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}

	goodDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(goodDir, "mcp.md"), []byte("# Good Plugin\nUse `good status`.\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	symlinkFileDir := t.TempDir()
	if err := os.Symlink(secretFile, filepath.Join(symlinkFileDir, "mcp.md")); err != nil {
		t.Fatal(err)
	}

	symlinkPluginTarget := t.TempDir()
	if err := os.WriteFile(filepath.Join(symlinkPluginTarget, "mcp.md"), []byte("FROM_SYMLINK_DIR"), 0o644); err != nil {
		t.Fatal(err)
	}
	symlinkPluginDir := filepath.Join(t.TempDir(), "linked-plugin")
	if err := os.Symlink(symlinkPluginTarget, symlinkPluginDir); err != nil {
		t.Fatal(err)
	}

	oversizeDir := t.TempDir()
	oversize := strings.Repeat("x", int(maxPluginMCPDocBytes)+1)
	if err := os.WriteFile(filepath.Join(oversizeDir, "mcp.md"), []byte(oversize), 0o644); err != nil {
		t.Fatal(err)
	}

	dirDocDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dirDocDir, "mcp.md"), 0o755); err != nil {
		t.Fatal(err)
	}

	plugins := []*discovery.Plugin{
		{Dir: goodDir, Manifest: &manifest.Manifest{Name: "good"}},
		{Dir: symlinkFileDir, Manifest: &manifest.Manifest{Name: "symlink-file"}},
		{Dir: symlinkPluginDir, Manifest: &manifest.Manifest{Name: "symlink-dir"}},
		{Dir: oversizeDir, Manifest: &manifest.Manifest{Name: "oversize"}},
		{Dir: dirDocDir, Manifest: &manifest.Manifest{Name: "dir-doc"}},
	}
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		fifoDir := t.TempDir()
		if err := syscall.Mkfifo(filepath.Join(fifoDir, "mcp.md"), 0o600); err != nil {
			t.Fatalf("Mkfifo() error = %v", err)
		}
		plugins = append(plugins, &discovery.Plugin{Dir: fifoDir, Manifest: &manifest.Manifest{Name: "fifo-doc"}})
	}

	desc := mcpBuildDescription(newMCPDocTestManager(plugins...))
	if !strings.Contains(desc, "# Good Plugin") {
		t.Fatalf("description missing valid plugin mcp.md: %q", desc)
	}
	if strings.Contains(desc, secret) {
		t.Fatalf("description leaked symlinked host file contents")
	}
	if strings.Contains(desc, "FROM_SYMLINK_DIR") {
		t.Fatalf("description read mcp.md from symlinked plugin directory")
	}
	if strings.Contains(desc, strings.Repeat("x", 1024)) {
		t.Fatalf("description included oversized mcp.md")
	}
}
