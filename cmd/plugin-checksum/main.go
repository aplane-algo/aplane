// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// plugin-checksum generates checksums.sha256 for apshell external plugins.
//
// Usage:
//
//	plugin-checksum <plugin-directory> [additional-files...]
//
// This tool reads the plugin's manifest.json to find the executable,
// then generates a checksums.sha256 file containing SHA256 hashes for:
//   - manifest.json
//   - the plugin executable
//   - any additional files specified on the command line
//
// The generated file uses the standard sha256sum format and is compatible
// with `sha256sum -c checksums.sha256` for manual verification.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/aplane-algo/aplane/internal/plugin/integrity"
	"github.com/aplane-algo/aplane/internal/plugin/manifest"
	"github.com/aplane-algo/aplane/internal/util"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: plugin-checksum <plugin-directory> [additional-files...]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Generates checksums.sha256 for an apshell external plugin.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "The tool automatically includes manifest.json and the executable")
		fmt.Fprintln(os.Stderr, "specified in the manifest. Additional files can be listed as extra arguments.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  plugin-checksum ./my-plugin")
		fmt.Fprintln(os.Stderr, "  plugin-checksum ./my-plugin lib/helper.js config.yaml")
		os.Exit(2)
	}

	pluginDir := os.Args[1]

	// Verify directory exists
	info, err := os.Stat(pluginDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot access plugin directory: %v\n", err)
		os.Exit(1)
	}
	if !info.IsDir() {
		fmt.Fprintf(os.Stderr, "Error: not a directory: %s\n", pluginDir)
		os.Exit(1)
	}

	// Load manifest to get executable name
	m, err := manifest.LoadFromDir(pluginDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to load manifest.json: %v\n", err)
		os.Exit(1)
	}

	// Determine which files to checksum
	files := []string{"manifest.json"}

	// Add executable (normalize path - remove leading ./)
	execPath := m.Executable
	if len(execPath) > 2 && execPath[:2] == "./" {
		execPath = execPath[2:]
	}

	// Check if executable is a local file or a system command (node, python, etc.)
	localExecPath := filepath.Join(pluginDir, execPath)
	if _, err := os.Stat(localExecPath); os.IsNotExist(err) {
		// Executable is likely a system command - use first arg as the script to checksum
		if len(m.Args) > 0 {
			execPath = m.Args[0]
			if len(execPath) > 2 && execPath[:2] == "./" {
				execPath = execPath[2:]
			}
		}
	}
	files = append(files, execPath)

	// Add any additional files specified by user
	if len(os.Args) > 2 {
		files = append(files, os.Args[2:]...)
	}

	// Verify all files exist before generating
	for _, file := range files {
		filePath := filepath.Join(pluginDir, file)
		if _, err := os.Stat(filePath); err != nil {
			fmt.Fprintf(os.Stderr, "Error: file not found: %s\n", file)
			os.Exit(1)
		}
	}

	// Generate checksums content
	content, err := integrity.GenerateChecksums(pluginDir, files)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to generate checksums: %v\n", err)
		os.Exit(1)
	}

	// Write to checksums.sha256 file
	checksumPath := filepath.Join(pluginDir, "checksums.sha256")
	if err := os.WriteFile(checksumPath, []byte(content), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to write checksums file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generated %s\n", checksumPath)
	fmt.Printf("Files included (%d):\n", len(files))
	for _, file := range files {
		hash, _ := util.ComputeSHA256(filepath.Join(pluginDir, file))
		fmt.Printf("  %s  %s\n", hash[:16]+"...", file)
	}
}
