// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aplane-algo/aplane/internal/docassets"

	"github.com/mark3labs/mcp-go/mcp"
)

// docDir is the on-disk location, relative to the client data directory, where
// an installation may ship or update bundled reference docs. Files here take
// precedence over the copies embedded in the binary, so docs can be refreshed
// without a rebuild.
const docDir = "docs"

// docEntry is one row in the bundled reference-doc index.
type docEntry struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// resolveDocName validates and normalizes a requested doc name: it strips a
// trailing ".md", rejects empty names and anything containing a path separator
// or "..", and returns the bare name plus its file form.
func resolveDocName(name string) (bare, file string, err error) {
	bare = strings.TrimSpace(name)
	bare = strings.TrimSuffix(bare, ".md")
	if bare == "" {
		return "", "", fmt.Errorf("doc name is required")
	}
	if strings.ContainsAny(bare, `/\`) || strings.Contains(bare, "..") {
		return "", "", fmt.Errorf("invalid doc name %q", name)
	}
	return bare, bare + ".md", nil
}

// readDoc returns the content of a bundled reference doc by name, preferring an
// on-disk copy under <dataDir>/docs and falling back to the embedded curated
// copy.
func readDoc(dataDir, name string) (string, error) {
	bare, file, err := resolveDocName(name)
	if err != nil {
		return "", err
	}
	if dataDir != "" {
		if data, err := os.ReadFile(filepath.Join(dataDir, docDir, file)); err == nil {
			return string(data), nil
		}
	}
	if curated := docassets.CuratedDocs(); curated != nil {
		if data, err := fs.ReadFile(curated, file); err == nil {
			return string(data), nil
		}
	}
	return "", fmt.Errorf("doc %q not found; call doc with no name to list available docs", bare)
}

// listDocs returns the available reference docs — the embedded curated set plus
// any extra .md files shipped under <dataDir>/docs — each with a one-line
// description taken from the document's first level-1 heading. Disk copies
// override embedded ones of the same name.
func listDocs(dataDir string) []docEntry {
	desc := map[string]string{}

	if curated := docassets.CuratedDocs(); curated != nil {
		_ = fs.WalkDir(curated, ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".md") {
				return nil
			}
			data, _ := fs.ReadFile(curated, p)
			desc[strings.TrimSuffix(path.Base(p), ".md")] = firstHeading(string(data))
			return nil
		})
	}
	if dataDir != "" {
		dir := filepath.Join(dataDir, docDir)
		if entries, err := os.ReadDir(dir); err == nil {
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
					continue
				}
				data, _ := os.ReadFile(filepath.Join(dir, e.Name()))
				desc[strings.TrimSuffix(e.Name(), ".md")] = firstHeading(string(data))
			}
		}
	}

	names := make([]string, 0, len(desc))
	for n := range desc {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]docEntry, 0, len(names))
	for _, n := range names {
		out = append(out, docEntry{Name: n, Description: desc[n]})
	}
	return out
}

// firstHeading returns the text of the first Markdown level-1 heading, or "".
func firstHeading(content string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "# ") {
			return strings.TrimSpace(line[2:])
		}
	}
	return ""
}

// mcpDocResult builds the MCP result for the "doc" tool: a JSON index of
// available docs when name is empty, or the requested document's Markdown.
func mcpDocResult(dataDir, name string) *mcp.CallToolResult {
	if strings.TrimSpace(name) == "" {
		data, err := json.Marshal(listDocs(dataDir))
		if err != nil {
			return mcp.NewToolResultError(err.Error())
		}
		return mcp.NewToolResultText(string(data))
	}
	content, err := readDoc(dataDir, name)
	if err != nil {
		return mcp.NewToolResultError(err.Error())
	}
	return mcp.NewToolResultText(content)
}
