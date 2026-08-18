// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShellResultBoundaryRetiredArtifactsStayDeleted(t *testing.T) {
	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, "internal", "apshellcli", "render_mcp.go")); !os.IsNotExist(err) {
		t.Fatalf("render_mcp.go returned; MCP projections belong to the shared command result path")
	}

	checks := map[string][]string{
		"internal/apshellcli": {
			"mcpStructured", "mcpFallbackResult", "mcpBlockedCommands", "mcpCaptureHelp",
			"resultFromCommandResult", "type CommandResult interface", "type JSONResult struct",
			"type KeysResult struct", "type ToggleResult struct",
		},
		"internal/plugin": {
			"type Function struct", "type FunctionParam struct", "Functions []Function",
		},
	}
	for rel, forbidden := range checks {
		err := filepath.WalkDir(filepath.Join(root, rel), func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, token := range forbidden {
				if strings.Contains(string(data), token) {
					t.Errorf("%s contains retired shell/plugin artifact %q", path, token)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	mcpData, err := os.ReadFile(filepath.Join(root, "internal", "apshellcli", "mcp.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"mcpFallbackResult", "state.SetOutput(&"} {
		if strings.Contains(string(mcpData), forbidden) {
			t.Errorf("mcp.go contains %q; MCP execute must marshal the shared result, not capture terminal output", forbidden)
		}
	}
}

func TestInTreePluginManifestsStayCommandOnlyV2(t *testing.T) {
	paths := []string{
		"plugins/algokit-localnet/manifest.json",
		"examples/external_plugins/echo-plugin/manifest.json",
		"examples/external_plugins/reti/manifest.json",
	}
	for _, rel := range paths {
		data, err := os.ReadFile(filepath.Join("..", "..", rel))
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		if !strings.Contains(text, `"manifest_format": "2.0"`) {
			t.Errorf("%s does not declare manifest format 2.0", rel)
		}
		if strings.Contains(text, `"functions"`) {
			t.Errorf("%s contains retired typed functions metadata", rel)
		}
	}
}
