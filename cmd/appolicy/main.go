// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"

	signerbootstrap "github.com/aplane-algo/aplane/internal/bootstrap/signer"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policyeditor"
	"github.com/aplane-algo/aplane/internal/policytui"
	"github.com/aplane-algo/aplane/internal/version"
	"golang.org/x/term"
)

type options struct {
	dataDir         string
	identityID      string
	check           bool
	yaml            bool
	sha256          bool
	save            bool
	savePolicy      bool
	saveAttestation bool
	toAttestation   bool
	online          bool
	version         bool
}

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	var opts options
	fs := flag.NewFlagSet("appolicy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opts.dataDir, "d", "", "signer data directory (or APSIGNER_DATA)")
	fs.StringVar(&opts.identityID, "identity", policyeditor.DefaultIdentityID, "identity ID")
	fs.BoolVar(&opts.check, "check", false, "verify and validate policy.yaml or a policy file, then exit")
	fs.BoolVar(&opts.yaml, "yaml", false, "verify policy.yaml or a policy file and print it to stdout")
	fs.BoolVar(&opts.sha256, "sha256", false, "verify policy.yaml or a policy file and print its SHA-256 digest")
	fs.BoolVar(&opts.save, "save", false, "deprecated alias for --save-policy")
	fs.BoolVar(&opts.savePolicy, "save-policy", false, "read policy.yaml from stdin, validate, save, and sign it")
	fs.BoolVar(&opts.saveAttestation, "save-attestation", false, "read attestation.yaml from stdin, validate, save, and sign it")
	fs.BoolVar(&opts.toAttestation, "to-attestation", false, "convert policy.yaml or a policy file to direct attestation.yaml and print it to stdout")
	fs.BoolVar(&opts.online, "online", false, "disabled placeholder for future apsigner-connected policy editing")
	fs.BoolVar(&opts.version, "version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if opts.version {
		writef(stdout, "appolicy %s\n", version.String())
		return 0
	}
	if opts.online {
		writeLine(stderr, "appolicy online mode is not implemented yet")
		return 2
	}
	savePolicy := opts.save || opts.savePolicy
	saveAttestation := opts.saveAttestation
	if modeCount(opts.check, opts.yaml, opts.sha256, savePolicy, saveAttestation, opts.toAttestation) > 1 {
		writeLine(stderr, "appolicy: choose only one of -check, -yaml, -sha256, -save-policy, -save-attestation, or -to-attestation")
		return 2
	}
	policyFile := ""
	switch args := fs.Args(); len(args) {
	case 0:
	case 1:
		policyFile = args[0]
	default:
		writeLine(stderr, "appolicy: specify at most one policy YAML file")
		return 2
	}
	if (savePolicy || saveAttestation) && policyFile != "" {
		writef(stderr, "appolicy: %s reads YAML from stdin and does not accept a file argument\n", saveFlagName(savePolicy, saveAttestation))
		return 2
	}

	dataDir := ""
	if policyFile == "" || savePolicy || saveAttestation || opts.dataDir != "" || os.Getenv("APSIGNER_DATA") != "" {
		var err error
		dataDir, err = signerbootstrap.ResolveDataDir(opts.dataDir)
		if err != nil {
			writef(stderr, "appolicy: %v\n", err)
			return 2
		}
	}
	identityID := opts.identityID
	if identityID == "" {
		identityID = policyeditor.DefaultIdentityID
	}
	var saveInput []byte
	if savePolicy || saveAttestation {
		var err error
		saveInput, err = io.ReadAll(stdin)
		if err != nil {
			writef(stderr, "appolicy: failed to read YAML from stdin: %v\n", err)
			return 1
		}
		if strings.TrimSpace(string(saveInput)) == "" {
			writef(stderr, "appolicy: %s YAML on stdin is empty\n", saveDocumentName(savePolicy, saveAttestation))
			return 1
		}
	}

	passphrases := &passphraseCache{
		stdin:              stdin,
		stderr:             stderr,
		allowStdinFallback: !savePolicy && !saveAttestation,
	}
	defer passphrases.Clear()

	store := &policyeditor.OfflineStore{
		DataDir:    dataDir,
		IdentityID: identityID,
	}
	defer store.ClearPassphrase()
	if policyFile == "" || savePolicy || saveAttestation {
		store.PassphraseProvider = passphrases.Get
	}
	if policyFile != "" {
		return runPolicyFile(ctx, policyFile, opts, store, dataDir, identityID, stdout, stderr)
	}
	if savePolicy {
		if err := store.SaveYAML(ctx, saveInput); err != nil {
			writef(stderr, "appolicy: %v\n", err)
			return 1
		}
		writef(stdout, "policy saved: %s\n", policy.PolicyPath(dataDir, identityID))
		return 0
	}
	if saveAttestation {
		if err := store.SaveAttestationYAML(ctx, saveInput); err != nil {
			writef(stderr, "appolicy: %v\n", err)
			return 1
		}
		writef(stdout, "attestation policy saved: %s\n", policy.AttestationPath(dataDir, identityID))
		return 0
	}

	stored, err := store.Load(ctx)
	if err != nil {
		writef(stderr, "appolicy: %v\n", err)
		return 1
	}
	if passphrase := passphrases.Cached(); len(passphrase) > 0 {
		store.SetPassphrase(passphrase)
		crypto.ZeroBytes(passphrase)
	}

	if opts.yaml {
		data, err := os.ReadFile(policy.PolicyPath(dataDir, identityID))
		if err != nil {
			writef(stderr, "appolicy: failed to read policy YAML: %v\n", err)
			return 1
		}
		_, _ = stdout.Write(data)
		return 0
	}
	if opts.sha256 {
		data, err := os.ReadFile(policy.PolicyPath(dataDir, identityID))
		if err != nil {
			writef(stderr, "appolicy: failed to read policy YAML: %v\n", err)
			return 1
		}
		writef(stdout, "%s\n", policy.PolicySHA256(data))
		return 0
	}
	if opts.toAttestation {
		data, err := os.ReadFile(policy.PolicyPath(dataDir, identityID))
		if err != nil {
			writef(stderr, "appolicy: failed to read policy YAML: %v\n", err)
			return 1
		}
		out, err := policy.ConvertSigningPolicyToAttestationYAML(data)
		if err != nil {
			writef(stderr, "appolicy: failed to convert policy to attestation.yaml: %v\n", err)
			return 1
		}
		_, _ = stdout.Write(out)
		return 0
	}

	writef(stdout, "policy OK: %s\n", policy.PolicyPath(dataDir, identityID))
	if opts.check {
		return 0
	}
	program := tea.NewProgram(
		policytui.New(store, stored, dataDir, identityID),
		tea.WithAltScreen(),
	)
	if _, err := program.Run(); err != nil {
		writef(stderr, "appolicy: TUI failed: %v\n", err)
		return 1
	}
	return 0
}

func runPolicyFile(ctx context.Context, path string, opts options, store *policyeditor.OfflineStore, dataDir, identityID string, stdout, stderr io.Writer) int {
	data, err := os.ReadFile(path)
	if err != nil {
		writef(stderr, "appolicy: failed to read policy YAML: %v\n", err)
		return 1
	}
	if strings.TrimSpace(string(data)) == "" {
		writeLine(stderr, "appolicy: policy YAML file is empty")
		return 1
	}
	stored, err := policy.ParseStoredConfig(data)
	if err != nil {
		writef(stderr, "appolicy: failed to parse policy YAML: %v\n", err)
		return 1
	}
	if err := store.Validate(ctx, stored); err != nil {
		writef(stderr, "appolicy: %v\n", err)
		return 1
	}
	if opts.yaml {
		_, _ = stdout.Write(data)
		return 0
	}
	if opts.sha256 {
		writef(stdout, "%s\n", policy.PolicySHA256(data))
		return 0
	}
	if opts.toAttestation {
		out, err := policy.ConvertSigningPolicyToAttestation(stored)
		if err != nil {
			writef(stderr, "appolicy: failed to convert policy to attestation.yaml: %v\n", err)
			return 1
		}
		data, err := policy.MarshalStoredAttestationConfig(out)
		if err != nil {
			writef(stderr, "appolicy: failed to marshal attestation.yaml: %v\n", err)
			return 1
		}
		_, _ = stdout.Write(data)
		return 0
	}

	writef(stdout, "policy OK: %s\n", path)
	if opts.check {
		return 0
	}
	if passphrase := passphraseFromEnv(); len(passphrase) > 0 {
		store.SetPassphrase(passphrase)
		crypto.ZeroBytes(passphrase)
	}
	program := tea.NewProgram(
		policytui.New(store, stored, dataDir, identityID),
		tea.WithAltScreen(),
	)
	if _, err := program.Run(); err != nil {
		writef(stderr, "appolicy: TUI failed: %v\n", err)
		return 1
	}
	return 0
}

func modeCount(values ...bool) int {
	count := 0
	for _, value := range values {
		if value {
			count++
		}
	}
	return count
}

func saveFlagName(savePolicy, saveAttestation bool) string {
	if saveAttestation {
		return "--save-attestation"
	}
	if savePolicy {
		return "--save-policy"
	}
	return "--save-policy"
}

func saveDocumentName(savePolicy, saveAttestation bool) string {
	if saveAttestation {
		return "attestation"
	}
	if savePolicy {
		return "policy"
	}
	return "policy"
}

type passphraseCache struct {
	stdin              io.Reader
	stderr             io.Writer
	allowStdinFallback bool
	passphrase         []byte
}

func (p *passphraseCache) Get(context.Context) ([]byte, error) {
	if len(p.passphrase) == 0 {
		passphrase, err := readPassphrase(p.stdin, p.stderr, p.allowStdinFallback)
		if err != nil {
			return nil, err
		}
		p.passphrase = append([]byte(nil), passphrase...)
		crypto.ZeroBytes(passphrase)
	}
	return append([]byte(nil), p.passphrase...), nil
}

func (p *passphraseCache) Clear() {
	crypto.ZeroBytes(p.passphrase)
	p.passphrase = nil
}

func (p *passphraseCache) Cached() []byte {
	return append([]byte(nil), p.passphrase...)
}

func passphraseFromEnv() []byte {
	for _, env := range []string{"APPOLICY_PASSPHRASE", "APSIGNER_PASSPHRASE"} {
		if p := os.Getenv(env); p != "" {
			return []byte(p)
		}
	}
	return nil
}

func readPassphrase(stdin io.Reader, stderr io.Writer, allowStdinFallback bool) ([]byte, error) {
	if passphrase := passphraseFromEnv(); len(passphrase) > 0 {
		return passphrase, nil
	}

	if f, ok := stdin.(*os.File); ok {
		fd := int(f.Fd()) // #nosec G115 - file descriptors are small integers.
		if term.IsTerminal(fd) {
			writef(stderr, "Enter store passphrase: ")
			passphrase, err := term.ReadPassword(fd)
			writeLine(stderr, "")
			if err != nil {
				return nil, fmt.Errorf("failed to read passphrase: %w", err)
			}
			return passphrase, nil
		}
	}
	if stdin == os.Stdin && term.IsTerminal(int(syscall.Stdin)) {
		writef(stderr, "Enter store passphrase: ")
		passphrase, err := term.ReadPassword(int(syscall.Stdin))
		writeLine(stderr, "")
		if err != nil {
			return nil, fmt.Errorf("failed to read passphrase: %w", err)
		}
		return passphrase, nil
	}
	if !allowStdinFallback {
		if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
			defer func() { _ = tty.Close() }()
			writef(tty, "Enter store passphrase: ")
			passphrase, err := term.ReadPassword(int(tty.Fd()))
			writeLine(tty, "")
			if err != nil {
				return nil, fmt.Errorf("failed to read passphrase: %w", err)
			}
			return passphrase, nil
		}
		return nil, fmt.Errorf("passphrase must come from APPOLICY_PASSPHRASE, APSIGNER_PASSPHRASE, or an interactive terminal when policy YAML is read from stdin")
	}

	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read passphrase: %w", err)
	}
	passphrase := []byte(strings.TrimSpace(line))
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("passphrase cannot be empty")
	}
	return passphrase, nil
}

func writef(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

func writeLine(w io.Writer, s string) {
	_, _ = fmt.Fprintln(w, s)
}
