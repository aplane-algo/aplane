// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/aplane-algo/aplane/internal/signerapp/policyauthor"
)

// runTest runs a workspace's saved cases: exit 0 when every case gets the
// answer it expects, 1 when one does not, 2 when the cases file is bad or a
// case cannot run.
func runTest(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("test", stderr)
	contextFile := fs.String("node-context", "", "use this export context instead of the workspace's own")
	dirs, err := parseInterleaved(fs, args)
	if err != nil {
		return exitUsage
	}
	if len(dirs) > 1 {
		writeln(stderr, "appolicy test: name at most one workspace directory")
		return exitUsage
	}
	dir := "."
	if len(dirs) == 1 {
		dir = dirs[0]
	}
	cf, err := policyauthor.LoadCases(dir)
	if errors.Is(err, os.ErrNotExist) {
		writef(stderr, "appolicy test: no saved cases: %s does not exist\n", policyauthor.CasesPath(dir))
		return exitUsage
	}
	if err != nil {
		writef(stderr, "appolicy test: %v\n", err)
		return exitUsage
	}
	node, err := nodeContextForDir(dir, *contextFile)
	if err != nil {
		writef(stderr, "appolicy test: %v\n", err)
		return exitUsage
	}
	networks, err := node.Networks(time.Now())
	if err != nil {
		writef(stderr, "appolicy test: %v\n", err)
		return exitUsage
	}
	failed, broken := 0, 0
	for _, r := range policyauthor.RunCases(cf.Cases, policyauthor.DiskDocuments(dir), networks) {
		switch {
		case r.Err != nil:
			broken++
			writef(stdout, "ERROR %s: %v\n", r.Case.Name, r.Err)
		case r.Passed:
			writef(stdout, "ok    %s\n", r.Case.Name)
		default:
			failed++
			writef(stdout, "FAIL  %s: got %s, want %s\n", r.Case.Name, describeExpect(policyauthor.ExpectOf(r.Got)), describeExpect(r.Case.Expect))
		}
	}
	writef(stdout, "%d case(s), %d failed, %d could not run (%s)\n", len(cf.Cases), failed, broken, networks.Source)
	switch {
	case broken > 0:
		return exitUsage
	case failed > 0:
		return exitProblems
	}
	return exitOK
}

func describeExpect(e policyauthor.CaseExpect) string {
	if e.RuleID == "" {
		return e.Outcome
	}
	return fmt.Sprintf("%s (rule %s)", e.Outcome, e.RuleID)
}
