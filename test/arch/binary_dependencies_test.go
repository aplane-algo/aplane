// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
)

// signerStorePackages hold the signer's product store: its generations, keys,
// key types, templates, ASA set and stage tables, their lock, and their
// mutation.
var signerStorePackages = []string{
	modulePrefix + "/internal/genstore",
	modulePrefix + "/internal/keys",
	modulePrefix + "/internal/keystore",
	modulePrefix + "/internal/keytypestate",
	modulePrefix + "/internal/templatestore",
	modulePrefix + "/internal/templatelibrary",
	modulePrefix + "/internal/storeinit",
	modulePrefix + "/internal/storepass",
	modulePrefix + "/internal/storelock",
	modulePrefix + "/internal/asasetstore",
	modulePrefix + "/internal/stagetable",
}

// binariesExempt link the signer on purpose, each for its reason.
var binariesExempt = map[string]string{
	"apsigner":  "it is the signer",
	"apadmin":   "its offline policy rescue validates templates against the store",
	"apconsole": "it hosts the signer's own pane",
}

// releasePlatforms are the systems binaries are built for: a file built for
// one only can add an edge the others don't have.
var releasePlatforms = []string{"linux", "darwin", "windows"}

var (
	platformImportsMu sync.Mutex
	platformImports   = map[string]map[string][]string{}
)

// moduleImportsFor is moduleImports for one GOOS. Build tags other than the
// platform's are not walked: no released binary is built with one.
func moduleImportsFor(t *testing.T, goos string) map[string][]string {
	t.Helper()
	platformImportsMu.Lock()
	defer platformImportsMu.Unlock()
	if imports, ok := platformImports[goos]; ok {
		return imports
	}
	cmd := exec.Command("go", "list", "-f", `{{.ImportPath}} {{join .Imports " "}}`, "./...")
	cmd.Dir = filepath.Join("..", "..")
	cmd.Env = append(os.Environ(), "GOOS="+goos)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			t.Fatalf("GOOS=%s go list: %v\n%s", goos, err, exitErr.Stderr)
		}
		t.Fatalf("GOOS=%s go list: %v", goos, err)
	}
	imports := make(map[string][]string)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if fields := strings.Fields(line); len(fields) > 0 {
			imports[fields[0]] = fields[1:]
		}
	}
	platformImports[goos] = imports
	return imports
}

// packagesUnder is every module package at or below dir.
func packagesUnder(imports map[string][]string, dir string) []string {
	var out []string
	for pkg := range imports {
		if pkg == dir || strings.HasPrefix(pkg, dir+"/") {
			out = append(out, pkg)
		}
	}
	sort.Strings(out)
	return out
}

// reachable is every module package root reaches by a chain of imports.
func reachable(imports map[string][]string, root string) map[string]bool {
	seen := map[string]bool{root: true}
	queue := []string{root}
	for len(queue) > 0 {
		pkg := queue[0]
		queue = queue[1:]
		for _, imported := range imports[pkg] {
			if strings.HasPrefix(imported, modulePrefix+"/") && !seen[imported] {
				seen[imported] = true
				queue = append(queue, imported)
			}
		}
	}
	return seen
}

// binaryRule is what one binary may link of the signer. forbidden it must
// never reach. When allowed is set, the signerapp packages it reaches are
// exactly those: a new one fails, and so does one it no longer reaches, so
// the list stays current.
type binaryRule struct {
	binary    string
	forbidden []string
	allowed   []string
}

func binaryRules(signerapp []string) []binaryRule {
	signerappPackage := func(name string) string { return modulePrefix + "/internal/signerapp/" + name }
	client := append(slices.Clone(signerapp), signerStorePackages...)
	unlockConfig := signerappPackage("unlockconfig")
	return []binaryRule{
		{binary: "apshell", forbidden: client},
		{binary: "apapprover", forbidden: client},
		{binary: "aplocalnet", forbidden: client},
		{binary: "approbe", forbidden: client},
		{binary: "appass-file", forbidden: client},
		{binary: "appass-systemd-creds", forbidden: client},
		{binary: "applugin-checksum", forbidden: client},
		{binary: "configdoc", forbidden: client},
		// The passphrase helper reads unlock.yaml, which unlockconfig owns.
		{binary: "appass", forbidden: slices.DeleteFunc(slices.Clone(client), func(pkg string) bool { return pkg == unlockConfig })},
		// The policy editor works on files: it evaluates policy, and never
		// meets the store or the live signer.
		{binary: "appolicy", forbidden: signerStorePackages, allowed: []string{
			signerappPackage("externalcheck"), signerappPackage("policyauthor"), signerappPackage("policyauthor/authortui"),
			signerappPackage("policyeval"), signerappPackage("policytext"),
		}},
		// apstore works on a stopped store: it reaches the store and its
		// validation, never the daemon's live runtime.
		{binary: "apstore", allowed: []string{
			signerappPackage("policyapply"), signerappPackage("policyruntime"), signerappPackage("storevalidate"),
			signerappPackage("templaterepair"), signerappPackage("templates"), unlockConfig,
		}},
	}
}

// TestBinariesStayOffTheSigner pins what each binary that is a client of the
// signer, or a tool that works on files or a stopped store, may link of the
// signer, on every platform a release is built for. A new edge fails with
// the chain that made it. Every binary is either ruled here or exempt.
//
// Linking is not running, but a client that links the signer's store or its
// live runtime can call into them, and the one place that would show it is
// here. internal/crypto is left out on purpose: clients link it to zero
// buffers.
func TestBinariesStayOffTheSigner(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("..", "..", "cmd"))
	if err != nil {
		t.Fatal(err)
	}
	for _, goos := range releasePlatforms {
		t.Run(goos, func(t *testing.T) {
			imports := moduleImportsFor(t, goos)
			signerapp := packagesUnder(imports, modulePrefix+"/internal/signerapp")
			if len(signerapp) == 0 {
				t.Fatal("no internal/signerapp packages found")
			}
			rules := binaryRules(signerapp)
			ruled := map[string]bool{}
			for _, rule := range rules {
				ruled[rule.binary] = true
			}
			for _, entry := range entries {
				if entry.IsDir() && !ruled[entry.Name()] && binariesExempt[entry.Name()] == "" {
					t.Errorf("cmd/%s is neither ruled here nor exempt: say what it may link of the signer", entry.Name())
				}
			}
			for _, rule := range rules {
				checkBinaryRule(t, imports, rule)
			}
		})
	}
}

func checkBinaryRule(t *testing.T, imports map[string][]string, rule binaryRule) {
	t.Helper()
	root := modulePrefix + "/cmd/" + rule.binary
	if _, ok := imports[root]; !ok {
		t.Errorf("no package %s", root)
		return
	}
	// A name that is no package would guard nothing.
	for _, pkg := range append(slices.Clone(rule.forbidden), rule.allowed...) {
		if _, ok := imports[pkg]; !ok {
			t.Errorf("%s: %s is not a package", rule.binary, pkg)
		}
	}
	if path := dependencyPath(imports, root, rule.forbidden...); path != nil {
		t.Errorf("%s reaches %s", rule.binary, strings.Join(path, " -> "))
	}
	if rule.allowed == nil {
		return
	}
	linked := reachable(imports, root)
	for _, pkg := range packagesUnder(imports, modulePrefix+"/internal/signerapp") {
		switch allowed := slices.Contains(rule.allowed, pkg); {
		case linked[pkg] && !allowed:
			t.Errorf("%s reaches %s, which is not on its list", rule.binary, strings.Join(dependencyPath(imports, root, pkg), " -> "))
		case !linked[pkg] && allowed:
			t.Errorf("%s no longer reaches %s: take it off its list", rule.binary, pkg)
		}
	}
}
