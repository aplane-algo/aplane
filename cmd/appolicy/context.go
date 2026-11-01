// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"strings"

	"github.com/aplane-algo/aplane/internal/policyexport"
	"github.com/aplane-algo/aplane/internal/signerapp/policyauthor"
)

// nodeContextFor selects the node the files are for: the context named by
// override, or the export the files sit in. It is nil for files not from an
// export, which are checked against the built-in networks and assets only.
func nodeContextFor(files []string, override string) (*policyauthor.NodeContext, error) {
	selected, err := policyexport.Discover(files, override)
	if err != nil || selected == nil {
		return nil, err
	}
	return nodeContextOf(selected), nil
}

// nodeContextForDir is nodeContextFor for the files in dir.
func nodeContextForDir(dir, override string) (*policyauthor.NodeContext, error) {
	selected, err := policyexport.ForDir(dir, override)
	if err != nil || selected == nil {
		return nil, err
	}
	return nodeContextOf(selected), nil
}

func nodeContextOf(s *policyexport.Selected) *policyauthor.NodeContext {
	return &policyauthor.NodeContext{Context: s.Export.Context, ExportedAt: s.Export.ExportedAt, Path: s.Path}
}

// workspacePaths are the paths a workspace was opened with and the files it
// holds, for selecting its context: a directory named explicitly is
// inspected even when it holds no policy file yet, so an export that stopped
// before its first document, or a fresh one, keeps its context.
func workspacePaths(w *policyauthor.Workspace) []string {
	paths := append([]string(nil), w.Paths...)
	for _, f := range w.Files {
		paths = append(paths, f.Path)
	}
	return paths
}

// removedFlag explains a flag appolicy no longer has, which it refuses
// rather than ignores: a check that quietly stopped reading the signer's
// networks would pass documents the node refuses.
func removedFlag(args []string) string {
	for _, arg := range args {
		if arg == "--" {
			break
		}
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		name, _, _ := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		if name == "signer-data" {
			return "--signer-data is removed: appolicy no longer reads a signer's data directory. " +
				"Export the node's policy with apadmin policy export --all DIR, then open, check or try the files in DIR; " +
				"appolicy reads the node's networks and ASA set from DIR/.appolicy/node.json, or from --node-context FILE"
		}
	}
	return ""
}
