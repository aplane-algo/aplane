// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Command appolicy checks, formats, explains and tries policy files without a
// node. It reads and writes only the files it is given, plus, read-only, the
// signer's ASA metadata cache and network mapping. Installing policy stays with apadmin policy
// check and apply.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/aplane-algo/aplane/internal/asa"
	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/signerapp/asametadata"
	"github.com/aplane-algo/aplane/internal/signerapp/policyauthor"
	"github.com/aplane-algo/aplane/internal/signerapp/policyauthor/authortui"
	"github.com/aplane-algo/aplane/internal/version"
	tea "github.com/charmbracelet/bubbletea"
)

const (
	exitOK       = 0
	exitProblems = 1
	exitUsage    = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "-h", "--help", "help":
		usage(stdout)
		return exitOK
	case "--version", "version":
		writef(stdout, "appolicy %s\n", version.String())
		return exitOK
	case "check":
		return runCheck(args[1:], stdout, stderr)
	case "fmt":
		return runFmt(args[1:], stdout, stderr)
	case "explain":
		return runExplain(args[1:], stdout, stderr)
	case "try":
		return runTry(args[1:], stdout, stderr)
	case "test":
		return runTest(args[1:], stdout, stderr)
	case "open":
		return runOpen(args[1:], stderr)
	}
	if retired := retiredForm(args); retired != "" {
		writef(stderr, "appolicy: %s\n", retired)
		return exitUsage
	}
	// A path in place of a command opens it: appolicy policy/ is appolicy open
	// policy/.
	if _, err := os.Stat(args[0]); err == nil {
		return runOpen(args, stderr)
	}
	writef(stderr, "appolicy: %q is not a command or a file\n", args[0])
	usage(stderr)
	return exitUsage
}

// writef, writeln and writes write to an output stream. There is nothing
// useful to do when the terminal or a pipe refuses output, so the error is
// dropped.
func writef(w io.Writer, format string, args ...any) { _, _ = fmt.Fprintf(w, format, args...) }

func writeln(w io.Writer, s string) { _, _ = fmt.Fprintln(w, s) }

func writes(w io.Writer, s string) { _, _ = fmt.Fprint(w, s) }

func usage(w io.Writer) {
	writes(w, `Usage:
  appolicy [open] [--signer-data DIR] PATH...
  appolicy check [--json] PATH...
  appolicy fmt [--check] [--strip-comments] PATH...
  appolicy explain [--signer-data DIR] FILE
  appolicy try FILE --from ADDR --to ADDR|self [--amount N] [--asset ID]
               [--network NAME] [--fee N] [--close-to ADDR]
               [--clawback-from ADDR] [--rekey-to ADDR [--rekey-held]]
               [--signer-data DIR] [--json]
  appolicy test [--signer-data DIR] [DIR]

PATH is a policy file, or a directory whose *.json files are policy files.
Each document is identified by its "key" field, not its file name.

  open     browse and edit the files in a terminal UI: each document's
           outline, its fields and their problems; edits are saved only after
           a review. A path in place of a command opens it.
  check    report each file's errors and warnings, by JSON Pointer.
           Exit 0 when no file has an error, 1 when one does.
  fmt      rewrite files in canonical form. A file that is not JSON is left
           untouched; a file with comments is refused unless --strip-comments.
           --check only reports which files would change.
  explain  describe a valid document in plain language. ASA amounts use the
           built-in asset table and, read-only, the signer's ASA cache in
           --signer-data (default $APSIGNER_DATA).
  try      ask what one valid document decides for one transaction, through
           the signer's own policy evaluator: rejects, requires review,
           approves, or leaves it to the operator default. A cosigner
           document permits or rejects. It answers for the document only and
           lists what it assumed; the network mapping comes from
           --signer-data's config.yaml, else the built-in networks. Exit 0
           whatever the verdict, 2 for bad input.
  test     run the saved cases in DIR/.appolicy/cases.json (DIR defaults to
           the current directory): each is a try with the answer expected.
           Exit 0 when every case passes, 1 when one fails, 2 when the cases
           file is bad or a case cannot run.

appolicy never contacts a node. Install policy with apadmin policy check and
apadmin policy apply.
`)
}

// retiredForm explains an invocation of the retired appolicy binary, which
// took flags rather than commands.
func retiredForm(args []string) string {
	first := strings.TrimLeft(args[0], "-")
	switch first {
	case "online", "check", "yaml", "sha256", "save", "to-sentry", "d":
		if strings.HasPrefix(args[0], "-") {
			return fmt.Sprintf("%s is a flag of the retired appolicy, which is not supported; manage a node's policy with apadmin policy (see docs/USER_POLICY.md)", args[0])
		}
	}
	return ""
}

func newFlags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("appolicy "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// openWorkspace opens every path as one workspace, so the rules across
// files hold whether files are named one by one or through a directory.
func openWorkspace(paths []string, stderr io.Writer) (*policyauthor.Workspace, bool) {
	w, err := policyauthor.Open(paths...)
	if err != nil {
		writef(stderr, "appolicy: %v\n", err)
		return nil, false
	}
	return w, true
}

type checkFile struct {
	Path        string `json:"path"`
	State       string `json:"state"`
	Key         string `json:"key,omitempty"`
	Role        string `json:"role,omitempty"`
	HadComments bool   `json:"had_comments,omitempty"`
}

type checkReport struct {
	Files    []checkFile            `json:"files"`
	Problems []policyauthor.Problem `json:"problems"`
	Errors   int                    `json:"errors"`
	Warnings int                    `json:"warnings"`
}

func runCheck(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("check", stderr)
	asJSON := fs.Bool("json", false, "print the report as JSON")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() == 0 {
		writeln(stderr, "appolicy check: name at least one file or directory")
		return exitUsage
	}
	w, ok := openWorkspace(fs.Args(), stderr)
	if !ok {
		return exitUsage
	}
	report := checkReport{Files: []checkFile{}, Problems: []policyauthor.Problem{}}
	for _, f := range w.Files {
		report.Files = append(report.Files, checkFile{Path: f.Path, State: f.State.String(), Key: f.Key, Role: string(f.Role), HadComments: f.HadComments})
	}
	for _, p := range w.AllProblems() {
		report.Problems = append(report.Problems, p)
		if p.Severity == policyauthor.SeverityError {
			report.Errors++
		} else {
			report.Warnings++
		}
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			writef(stderr, "appolicy check: %v\n", err)
			return exitUsage
		}
	} else {
		for _, p := range report.Problems {
			where := p.Path
			if p.Pointer != "" {
				where += " " + p.Pointer
			}
			writef(stdout, "%s: %s: %s\n", where, p.Severity, p.Message)
		}
		writef(stdout, "%d file(s), %d error(s), %d warning(s)\n", len(report.Files), report.Errors, report.Warnings)
	}
	if report.Errors > 0 {
		return exitProblems
	}
	return exitOK
}

func runFmt(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("fmt", stderr)
	checkOnly := fs.Bool("check", false, "report files that are not canonical, and change nothing")
	stripComments := fs.Bool("strip-comments", false, "allow formatting a file with comments, which are dropped")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() == 0 {
		writeln(stderr, "appolicy fmt: name at least one file or directory")
		return exitUsage
	}
	w, ok := openWorkspace(fs.Args(), stderr)
	if !ok {
		return exitUsage
	}
	status := exitOK
	fail := func(path, format string, a ...any) {
		writef(stderr, "%s: %s\n", path, fmt.Sprintf(format, a...))
		status = exitProblems
	}
	for _, f := range w.Files {
		if f.Draft == nil {
			msg := f.State.String()
			if len(f.Problems) > 0 {
				msg += ": " + f.Problems[0].Message
			}
			fail(f.Path, "not formatted, left untouched (%s)", msg)
			continue
		}
		if f.HadComments && !*stripComments {
			fail(f.Path, "not formatted: it has comments, which fmt would drop; move notes into description fields, or rerun with --strip-comments")
			continue
		}
		canonical, err := f.Canonical()
		if err != nil {
			fail(f.Path, "not formatted: %v", err)
			continue
		}
		if string(canonical) == string(f.Loaded) {
			continue
		}
		if *checkOnly {
			writef(stdout, "%s: not canonical\n", f.Path)
			status = exitProblems
			continue
		}
		if err := f.Write(canonical, false); err != nil {
			fail(f.Path, "not formatted: %v", err)
			continue
		}
		writef(stdout, "%s: formatted\n", f.Path)
	}
	return status
}

func runExplain(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("explain", stderr)
	signerData := fs.String("signer-data", os.Getenv("APSIGNER_DATA"), "signer data directory whose ASA cache is read, read-only")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 1 {
		writeln(stderr, "appolicy explain: name one policy file")
		return exitUsage
	}
	f := policyauthor.LoadFile(fs.Arg(0))
	if f.Document == nil {
		writef(stderr, "%s is %s; run appolicy check %s\n", f.Path, f.State, f.Path)
		return exitProblems
	}
	writes(stdout, policyauthor.Explain(f.Document, assetLookup(*signerData, func(msg string) { writef(stderr, "appolicy: %s\n", msg) })))
	return exitOK
}

// assetLookup returns the lookup explain and the TUI use: the built-in table,
// and the signer's cache read-only when a signer data directory is named. A
// cache that cannot be read or verified is reported once, through report; the
// built-in entries still answer.
func assetLookup(signerData string, report func(string)) policyauthor.AssetLookup {
	if signerData == "" {
		return asa.BuiltinMetadata
	}
	store, err := asametadata.NewReadOnlyStore(signerData)
	if err != nil {
		report(fmt.Sprintf("%v; using built-in asset metadata only", err))
		return asa.BuiltinMetadata
	}
	var reported sync.Once
	return func(network string, assetID uint64) (asa.Metadata, bool) {
		meta, ok, err := store.MetadataByID(network, assetID)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			reported.Do(func() {
				report(fmt.Sprintf("warning: the signer's ASA cache is unusable (%v); amounts use built-in metadata only", err))
			})
		}
		return meta, ok
	}
}

// runProgram runs the TUI; tests replace it.
var runProgram = func(m tea.Model) error {
	_, err := tea.NewProgram(m, tea.WithAltScreen()).Run()
	return err
}

func runOpen(args []string, stderr io.Writer) int {
	fs := newFlags("open", stderr)
	signerData := fs.String("signer-data", os.Getenv("APSIGNER_DATA"), "signer data directory whose ASA cache and network mapping are read, read-only")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() == 0 {
		writeln(stderr, "appolicy open: name at least one file or directory")
		return exitUsage
	}
	w, ok := openWorkspace(fs.Args(), stderr)
	if !ok {
		return exitUsage
	}
	// The cache package logs to stdout, which the TUI owns.
	cache.SetLoggerOutput(io.Discard)
	var diagnostics []string
	lookup := assetLookup(*signerData, func(msg string) { diagnostics = append(diagnostics, msg) })
	networks, err := signerNetworks(*signerData)
	if err != nil {
		writef(stderr, "appolicy: %v\n", err)
		return exitUsage
	}
	if err := runProgram(authortui.New(w, lookup, &diagnostics).WithNetworks(networks)); err != nil {
		writef(stderr, "appolicy: %v\n", err)
		return exitUsage
	}
	return exitOK
}
