// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestAppolicyShipsWithTheSignerBinaries pins where appolicy is built,
// packaged, installed and removed. It is a signer-side tool: built for every
// platform the signer ships on, installed into the signer bindir by the
// install copy loop (no exclusion), and removed with the signer binaries on
// uninstall.
func TestAppolicyShipsWithTheSignerBinaries(t *testing.T) {
	root := filepath.Join("..", "..")
	read := func(name string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}

	installer := read("install.sh")
	if strings.Contains(installer, `[ "$name" = "appolicy" ]`) {
		t.Error("install.sh still skips appolicy in a binary copy loop")
	}
	if strings.Contains(installer, `"$SIGNER_BINDIR/appolicy"`) {
		t.Error("install.sh removes appolicy from the signer bindir")
	}

	removal := regexp.MustCompile(`(?m)^\s*for binary in [^\n]*\bappolicy\b[^\n]*; do\s*$`)
	if got := len(removal.FindAllString(read("uninstall.sh"), -1)); got != 2 {
		t.Errorf("uninstall.sh includes appolicy in %d signer-binary removal lists, want 2", got)
	}

	makefile := read("Makefile")
	for _, want := range []string{
		"-o bin/appolicy ./cmd/appolicy",
		"-o appolicy-arm64 ./cmd/appolicy",
		"@mv appolicy-arm64 bin/arm64/appolicy",
		"-o bin/amd64/appolicy ./cmd/appolicy",
		"-o bin/darwin-arm64/appolicy ./cmd/appolicy",
		"-o bin/darwin-amd64/appolicy ./cmd/appolicy",
		"bin/$${arch}/appolicy",
		"$${darwindir}appolicy",
	} {
		if !strings.Contains(makefile, want) {
			t.Errorf("Makefile lacks %q", want)
		}
	}
	release := read(filepath.Join(".github", "workflows", "release.yml"))
	for _, want := range []string{"bin/${arch}/appolicy", "bin/darwin-${arch}/appolicy"} {
		if !strings.Contains(release, want) {
			t.Errorf("release.yml does not package %q", want)
		}
	}
	if !regexp.MustCompile(`(?m)^\s+appolicy$`).MatchString(read(filepath.Join("scripts", "package-bootstrap-release.sh"))) {
		t.Error("package-bootstrap-release.sh does not require appolicy")
	}
}

// TestInstallerInstallsTheReleaseBinaries pins install.sh's binary list to the
// binaries every release archive carries: the bootstrap package, and the
// Linux and macOS archives release.yml and make release-local build (macOS has
// no appass-systemd-creds). So an install from a checkout installs what a
// release ships and nothing else that happens to sit in bin/, and a binary
// added to one archive alone fails here. uninstall.sh must remove
// each of them: systemd mode from one bindir, local mode from the signer and
// client bindirs, and client-only mode the same client binaries.
func TestInstallerInstallsTheReleaseBinaries(t *testing.T) {
	root := filepath.Join("..", "..")
	list := func(name, opener string) []string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		_, rest, found := strings.Cut(string(data), opener+"\n")
		body, _, closed := strings.Cut(rest, ")")
		if !found || !closed {
			t.Fatalf("%s has no %q list", name, opener)
		}
		return strings.Fields(body)
	}
	installed := list("install.sh", "RELEASE_BINARIES=(")
	packaged := list(filepath.Join("scripts", "package-bootstrap-release.sh"), "local binaries=(")
	if !slices.Equal(installed, packaged) {
		t.Errorf("install.sh installs %v, but a release packages %v", installed, packaged)
	}
	want := slices.Sorted(slices.Values(installed))
	wantDarwin := slices.DeleteFunc(slices.Clone(want), func(name string) bool { return name == "appass-systemd-creds" })
	for _, name := range []string{filepath.Join(".github", "workflows", "release.yml"), "Makefile"} {
		linux, darwin := archiveBinaryLists(t, filepath.Join(root, name))
		if !slices.Equal(linux, want) {
			t.Errorf("%s packages %v in a Linux archive, want %v", name, linux, want)
		}
		if !slices.Equal(darwin, wantDarwin) {
			t.Errorf("%s packages %v in a macOS archive, want %v", name, darwin, wantDarwin)
		}
	}

	uninstaller, err := os.ReadFile(filepath.Join(root, "uninstall.sh"))
	if err != nil {
		t.Fatal(err)
	}
	var systemd, localSigner []string
	var clients [][]string
	removal := regexp.MustCompile(`(?m)^\s*for binary in ([^;\n]+); do$`)
	for _, match := range removal.FindAllStringSubmatch(string(uninstaller), -1) {
		names := strings.Fields(match[1])
		switch {
		case slices.Contains(names, "apsigner") && slices.Contains(names, "apshell"):
			systemd = names
		case slices.Contains(names, "apsigner"):
			localSigner = names
		default:
			clients = append(clients, names)
		}
	}
	if got := slices.Sorted(slices.Values(systemd)); !slices.Equal(got, want) {
		t.Errorf("systemd uninstall removes %v, want %v", got, want)
	}
	if len(clients) != 2 {
		t.Fatalf("uninstall.sh has %d client binary removal lists, want 2 (client-only and local)", len(clients))
	}
	for _, client := range clients {
		if got := slices.Sorted(slices.Values(slices.Concat(localSigner, client))); !slices.Equal(got, want) {
			t.Errorf("signer bindir plus client bindir removal lists cover %v, want %v", got, want)
		}
	}
}

// archiveBinaryLists returns, sorted, the binaries a build file copies into
// the Linux and the macOS archive's dist/staging/aplane/bin/.
func archiveBinaryLists(t *testing.T, path string) (linux, darwin []string) {
	t.Helper()
	name := regexp.MustCompile(`[A-Za-z0-9-]+$`)
	var linuxCopies, darwinCopies int
	for _, command := range shellCommands(readTextFile(t, path)) {
		fields := strings.Fields(command)
		if len(fields) < 3 || fields[0] != "cp" || fields[len(fields)-1] != "dist/staging/aplane/bin/" {
			continue
		}
		var names []string
		for _, source := range fields[1 : len(fields)-1] {
			names = append(names, name.FindString(source))
		}
		slices.Sort(names)
		if strings.Contains(command, "darwin") {
			darwin = names
			darwinCopies++
		} else {
			linux = names
			linuxCopies++
		}
	}
	if linuxCopies != 1 || darwinCopies != 1 {
		t.Fatalf("%s has %d Linux and %d macOS archive binary copies, want one of each", path, linuxCopies, darwinCopies)
	}
	return linux, darwin
}

// shellCommands splits a build file into its shell commands, continuation
// lines joined, at newlines and semicolons.
func shellCommands(text string) []string {
	joined := strings.ReplaceAll(text, "\\\n", " ")
	var commands []string
	for _, command := range strings.FieldsFunc(joined, func(r rune) bool { return r == '\n' || r == ';' }) {
		if command = strings.Join(strings.Fields(command), " "); command != "" {
			commands = append(commands, command)
		}
	}
	return commands
}

// TestReleaseArchivesShipTheInstallReadme pins that every archive copy of
// install.sh is followed by a copy of the repository root's
// install_readme.txt to the same place, when there is one, so a note made for
// a release reaches every operator: the bootstrap package, and the Linux and
// macOS archives release.yml and make release-local build.
func TestReleaseArchivesShipTheInstallReadme(t *testing.T) {
	root := filepath.Join("..", "..")
	for name, want := range map[string]int{
		filepath.Join("scripts", "package-bootstrap-release.sh"): 1,
		filepath.Join(".github", "workflows", "release.yml"):     2,
		"Makefile": 2,
	} {
		commands := shellCommands(readTextFile(t, filepath.Join(root, name)))
		copies := 0
		for i, command := range commands {
			fields := strings.Fields(command)
			if len(fields) < 3 || fields[0] != "cp" {
				continue
			}
			sources := fields[1 : len(fields)-1]
			at := slices.IndexFunc(sources, func(source string) bool {
				return filepath.Base(strings.Trim(source, `"`)) == "install.sh"
			})
			if at < 0 {
				continue
			}
			copies++
			note := strings.Replace(sources[at], "install.sh", "install_readme.txt", 1)
			wantNext := []string{"if [ -f " + note + " ]", "then cp " + note + " " + fields[len(fields)-1], "fi"}
			if next := commands[i+1 : min(i+4, len(commands))]; !slices.Equal(next, wantNext) {
				t.Errorf("%s: %q is followed by %q, want %q", name, command, next, wantNext)
			}
		}
		if copies != want {
			t.Errorf("%s copies install.sh into %d archives, want %d", name, copies, want)
		}
	}
}

// TestInstallerShowsTheInstallReadmeFirst runs install.sh from a scratch
// archive root. The install_readme.txt beside it is the first thing it
// prints, verbatim, before the usage and before an argument error; an empty
// or absent note prints nothing, and one in the working directory is not
// the archive's.
func TestInstallerShowsTheInstallReadmeFirst(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not available")
	}
	installer := readTextFile(t, filepath.Join(repositoryRoot(t), "install.sh"))
	note := "This release is new-install only: run the old uninstall.sh first.\n" +
		"100% of %s keys move by recovery phrase; C:\\new\\table \\n \\e[31m \x1b[1mbold\x1b[0m\n" +
		"$(touch pwned) ${HOME} `touch pwned`\n\n"
	shown := "==> Release notes for this installer (install_readme.txt)\n" +
		strings.TrimRight(note, "\n") + "\n" + strings.Repeat("=", 80) + "\n\n"
	cases := []struct {
		name    string
		written bool
		note    string
		arg     string
		code    int
		want    string
	}{
		{name: "before the usage", written: true, note: note, arg: "--help", want: shown + "Usage:\n"},
		{name: "before an argument error", written: true, note: note, arg: "--bogus", code: 2,
			want: shown + "Error: unknown option: --bogus\n"},
		{name: "empty", written: true, note: " \n\t\n", arg: "--help", want: "Usage:\n"},
		{name: "absent", arg: "--help", want: "Usage:\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			archive, work := t.TempDir(), t.TempDir()
			if err := os.WriteFile(filepath.Join(archive, "install.sh"), []byte(installer), 0o755); err != nil {
				t.Fatal(err)
			}
			if tc.written {
				if err := os.WriteFile(filepath.Join(archive, "install_readme.txt"), []byte(tc.note), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(work, "install_readme.txt"), []byte("not the archive's note\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(bash, filepath.Join(archive, "install.sh"), tc.arg)
			cmd.Dir = work
			cmd.Env = []string{"HOME=" + work, "PATH=/usr/bin:/bin"}
			out, err := cmd.CombinedOutput()
			if cmd.ProcessState == nil {
				t.Fatalf("run install.sh: %v", err)
			}
			if code := cmd.ProcessState.ExitCode(); code != tc.code {
				t.Fatalf("install.sh %s exited %d (%v), want %d:\n%s", tc.arg, code, err, tc.code, out)
			}
			if !strings.HasPrefix(string(out), tc.want) {
				t.Errorf("install.sh %s output does not start with\n%q\ngot\n%q", tc.arg, tc.want, out)
			}
			if got := strings.Count(string(out), "==> Release notes"); got > 1 || strings.Contains(string(out), "not the archive's") {
				t.Errorf("install.sh %s printed a note %d times or the working directory's note:\n%s", tc.arg, got, out)
			}
			if _, err := os.Stat(filepath.Join(work, "pwned")); !os.IsNotExist(err) {
				t.Errorf("install.sh ran the note's text as shell (pwned: %v)", err)
			}
		})
	}
}

func TestRescuePolicyOutputCannotBypassVerifiedStoreRead(t *testing.T) {
	path := filepath.Join("..", "..", "internal", "signerapp", "policycmd", "rescue.go")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "os.ReadFile(") {
		t.Error("rescue policy workflow reads output bytes outside OfflineStore verification")
	}
}

func TestPolicyWorkflowImportsStayInOwningBoundaries(t *testing.T) {
	root := filepath.Join("..", "..")
	rules := map[string]map[string]bool{
		"github.com/aplane-algo/aplane/internal/signerapp/policycmd": {
			filepath.Join("cmd", "apadmin"): true,
		},
		// policyreview owns what the operator reviews before an apply; the
		// batch commands and the TUI's load-policy-file flow are its only users.
		"github.com/aplane-algo/aplane/internal/signerapp/policyreview": {
			filepath.Join("internal", "signerapp", "policycmd"): true,
			filepath.Join("internal", "signerapp", "signertui"): true,
		},
		// policytext holds the text-level helpers for policy documents
		// (comments, templates, presets). It has no store or admin
		// dependencies, so policy authoring can use it without policyreview.
		"github.com/aplane-algo/aplane/internal/signerapp/policytext": {
			filepath.Join("internal", "signerapp", "policyauthor"): true,
			filepath.Join("internal", "signerapp", "policyreview"): true,
			filepath.Join("internal", "signerapp", "policycmd"):    true,
			filepath.Join("internal", "signerapp", "signertui"):    true,
		},
		// policyapply owns the rules for committing policy; the daemon admin
		// service, the rescue workflow, and apstore's checks are its only users.
		"github.com/aplane-algo/aplane/internal/signerapp/policyapply": {
			filepath.Join("cmd", "apstore"):                     true,
			filepath.Join("internal", "signerapp", "admin"):     true,
			filepath.Join("internal", "signerapp", "policycmd"): true,
		},
	}
	for _, sourceRoot := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, sourceRoot), func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			dir := filepath.Dir(relative)
			for _, spec := range parsed.Imports {
				importPath, err := strconv.Unquote(spec.Path.Value)
				if err != nil {
					return err
				}
				allowed, cosigned := rules[importPath]
				if cosigned && !allowed[dir] {
					t.Errorf("%s imports %s outside the policy workflow ownership allowlist", relative, importPath)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
