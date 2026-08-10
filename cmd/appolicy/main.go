// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/adminipc"
	signerbootstrap "github.com/aplane-algo/aplane/internal/bootstrap/signer"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/policyeditor"
	"github.com/aplane-algo/aplane/internal/signerapp/policytui"
	"github.com/aplane-algo/aplane/internal/storeperm"
	"github.com/aplane-algo/aplane/internal/transport"
	"github.com/aplane-algo/aplane/internal/version"
	"golang.org/x/term"
)

type options struct {
	dataDir    string
	identityID string
	target     string
	check      bool
	yaml       bool
	sha256     bool
	save       bool
	toSentry   bool
	online     bool
	ipcPath    string
	version    bool
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
	fs.StringVar(&opts.target, "target", "auto", "policy target: auto, signer, or sentry")
	fs.BoolVar(&opts.check, "check", false, "verify and validate the selected policy document or a policy file, then exit")
	fs.BoolVar(&opts.yaml, "yaml", false, "verify the selected policy document or a policy file and print it to stdout")
	fs.BoolVar(&opts.sha256, "sha256", false, "verify the selected policy document or a policy file and print its SHA-256 digest")
	fs.BoolVar(&opts.save, "save", false, "read selected policy YAML from stdin, validate, save, and sign it")
	fs.BoolVar(&opts.toSentry, "to-sentry", false, "convert signer policy YAML to direct sentry policy YAML and print it to stdout")
	fs.BoolVar(&opts.online, "online", false, "edit policy through authenticated apsigner IPC")
	fs.StringVar(&opts.ipcPath, "ipc-path", "", "admin IPC socket path (or APSIGNER_IPC_PATH)")
	fs.BoolVar(&opts.version, "version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if opts.version {
		writef(stdout, "appolicy %s\n", version.String())
		return 0
	}
	requestedTarget, err := policyeditor.ParseTarget(opts.target)
	if err != nil {
		writef(stderr, "appolicy: %v\n", err)
		return 2
	}
	if modeCount(opts.check, opts.yaml, opts.sha256, opts.save, opts.toSentry) > 1 {
		writeLine(stderr, "appolicy: choose only one of -check, -yaml, -sha256, -save, or -to-sentry")
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
	if opts.save && policyFile != "" {
		writeLine(stderr, "appolicy: --save reads YAML from stdin and does not accept a file argument")
		return 2
	}
	if opts.online {
		return runOnlinePolicy(ctx, opts, requestedTarget, policyFile, stdin, stdout, stderr)
	}

	dataDir := ""
	if policyFile == "" || opts.save || opts.dataDir != "" || os.Getenv("APSIGNER_DATA") != "" {
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
	target, err := resolveRunTarget(dataDir, policyFile, requestedTarget, opts.toSentry)
	if err != nil {
		writef(stderr, "appolicy: %v\n", err)
		return 2
	}
	var saveInput []byte
	if opts.save {
		var err error
		saveInput, err = io.ReadAll(stdin)
		if err != nil {
			writef(stderr, "appolicy: failed to read YAML from stdin: %v\n", err)
			return 1
		}
		if strings.TrimSpace(string(saveInput)) == "" {
			writef(stderr, "appolicy: %s YAML on stdin is empty\n", target.StatusNoun())
			return 1
		}
	}

	passphrases := &passphraseCache{
		stdin:              stdin,
		stderr:             stderr,
		allowStdinFallback: !opts.save,
	}
	defer passphrases.Clear()

	store := &policyeditor.OfflineStore{
		DataDir:    dataDir,
		IdentityID: identityID,
		Target:     target,
	}
	defer store.ClearPassphrase()
	if policyFile == "" || opts.save {
		store.PassphraseProvider = passphrases.Get
	}
	if policyFile != "" {
		return runPolicyFile(ctx, policyFile, opts, store, dataDir, identityID, target, stdout, stderr)
	}
	if opts.save {
		if err := store.SaveYAML(ctx, saveInput); err != nil {
			writef(stderr, "appolicy: %v\n", err)
			return 1
		}
		if err := normalizeOfflinePolicyStore(dataDir); err != nil {
			writef(stderr, "appolicy: policy saved, but managed store ownership normalization failed: %v\n", err)
			return 1
		}
		writef(stdout, "%s saved: %s\n", target.StatusNoun(), target.Path(dataDir, identityID))
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
		data, err := os.ReadFile(target.Path(dataDir, identityID))
		if err != nil {
			writef(stderr, "appolicy: failed to read %s: %v\n", target.DocumentName(), err)
			return 1
		}
		_, _ = stdout.Write(data)
		return 0
	}
	if opts.sha256 {
		data, err := os.ReadFile(target.Path(dataDir, identityID))
		if err != nil {
			writef(stderr, "appolicy: failed to read %s: %v\n", target.DocumentName(), err)
			return 1
		}
		writef(stdout, "%s\n", policy.PolicySHA256(data))
		return 0
	}
	if opts.toSentry {
		data, err := os.ReadFile(policy.PolicyPath(dataDir, identityID))
		if err != nil {
			writef(stderr, "appolicy: failed to read policy YAML: %v\n", err)
			return 1
		}
		out, err := policy.ConvertSigningPolicyToSentryYAML(data)
		if err != nil {
			writef(stderr, "appolicy: failed to convert policy to sentry policy: %v\n", err)
			return 1
		}
		_, _ = stdout.Write(out)
		return 0
	}

	writef(stdout, "%s OK: %s\n", target.StatusNoun(), target.Path(dataDir, identityID))
	if opts.check {
		return 0
	}
	program := tea.NewProgram(
		policytui.NewWithTarget(store, stored, dataDir, identityID, target),
		tea.WithAltScreen(),
	)
	if _, err := program.Run(); err != nil {
		writef(stderr, "appolicy: TUI failed: %v\n", err)
		return 1
	}
	if err := normalizeOfflinePolicyStore(dataDir); err != nil {
		writef(stderr, "appolicy: managed store ownership normalization failed: %v\n", err)
		return 1
	}
	return 0
}

const onlinePolicyTimeout = 10 * time.Second

func runOnlinePolicy(ctx context.Context, opts options, requestedTarget policyeditor.Target, policyFile string, stdin io.Reader, stdout, stderr io.Writer) int {
	if opts.identityID != "" && opts.identityID != policyeditor.DefaultIdentityID {
		writeLine(stderr, "appolicy: local online mode is bound to the product identity")
		return 2
	}
	dataDir := serverconfig.GetSignerDataDir(opts.dataDir)
	ipcPath, err := adminipc.ResolveClientPath(adminipc.ClientPathRequest{
		DataDir: dataDir, IPCPath: opts.ipcPath, DataDirExplicit: opts.dataDir != "",
	})
	if err != nil {
		writef(stderr, "appolicy: %v\n", err)
		return 1
	}
	conn := transport.NewIPC(ipcPath)
	if err := conn.Dial(); err != nil {
		writef(stderr, "appolicy: %v\n", err)
		return 1
	}
	defer conn.Close()

	passphrase, err := readPassphrase(stdin, stderr, !opts.save)
	if err != nil {
		writef(stderr, "appolicy: %v\n", err)
		return 1
	}
	defer crypto.ZeroBytes(passphrase)
	if err := authenticateAndUnlockOnlinePolicy(conn, passphrase); err != nil {
		writef(stderr, "appolicy: %v\n", err)
		return 1
	}

	target := requestedTarget
	if opts.toSentry {
		target = policyeditor.TargetSigner
	} else if target == "" || target == policyeditor.TargetAuto {
		target, err = onlinePolicyTarget(conn)
		if err != nil {
			writef(stderr, "appolicy: %v\n", err)
			return 1
		}
	}
	client := policyeditor.NewProtocolClient(conn, onlinePolicyTimeout)
	store := &policyeditor.AdminStore{Client: client, Target: target}

	if policyFile != "" {
		data, err := readPolicyYAMLFile(policyFile)
		if err != nil {
			writef(stderr, "appolicy: %v\n", err)
			return 1
		}
		parseTarget := target
		if opts.toSentry {
			parseTarget = policyeditor.TargetSigner
		}
		stored, err := parseTarget.Parse(data)
		if err != nil {
			writef(stderr, "appolicy: failed to parse %s: %v\n", parseTarget.DocumentName(), err)
			return 1
		}
		validateStore := &policyeditor.AdminStore{Client: client, Target: parseTarget}
		if err := validateStore.Validate(ctx, stored); err != nil {
			writef(stderr, "appolicy: %v\n", err)
			return 1
		}
		if opts.toSentry {
			converted, err := policy.ConvertSigningPolicyToSentryYAML(data)
			if err != nil {
				writef(stderr, "appolicy: failed to convert policy: %v\n", err)
				return 1
			}
			_, _ = stdout.Write(converted)
			return 0
		}
		if opts.yaml {
			_, _ = stdout.Write(data)
			return 0
		}
		if opts.sha256 {
			writef(stdout, "%s\n", policy.PolicySHA256(data))
			return 0
		}
		if opts.check {
			writef(stdout, "%s OK: %s\n", target.StatusNoun(), policyFile)
			return 0
		}
		if err := editOnlinePolicyFile(ctx, store, stored, target, policyFile, stdout); err != nil {
			writef(stderr, "appolicy: %v\n", err)
			return 1
		}
		return 0
	}

	stored, err := store.Load(ctx)
	if err != nil {
		writef(stderr, "appolicy: %v\n", err)
		return 1
	}
	if opts.save {
		data, err := readOnlinePolicyYAML(stdin)
		if err != nil {
			writef(stderr, "appolicy: %v\n", err)
			return 1
		}
		if err := store.SaveYAML(ctx, data); err != nil {
			writef(stderr, "appolicy: %v\n", err)
			return 1
		}
		writef(stdout, "%s saved online\n", target.StatusNoun())
		return 0
	}
	if opts.yaml {
		_, _ = io.WriteString(stdout, store.PolicyYAML())
		return 0
	}
	if opts.sha256 {
		writef(stdout, "%s\n", store.LastSHA256())
		return 0
	}
	if opts.toSentry {
		out, err := policy.ConvertSigningPolicyToSentryYAML([]byte(store.PolicyYAML()))
		if err != nil {
			writef(stderr, "appolicy: failed to convert policy: %v\n", err)
			return 1
		}
		_, _ = stdout.Write(out)
		return 0
	}
	writef(stdout, "%s OK online\n", target.StatusNoun())
	if opts.check {
		return 0
	}
	if err := launchPolicyEditor(store, stored, "", policyeditor.DefaultIdentityID, target); err != nil {
		writef(stderr, "appolicy: TUI failed: %v\n", err)
		return 1
	}
	return 0
}

type onlinePolicyAuthenticator interface {
	Authenticate(string, time.Duration) error
	WaitForStatus(time.Duration) (*protocol.StatusMessage, error)
	Unlock(string, time.Duration) (*protocol.UnlockResultMessage, error)
}

func authenticateAndUnlockOnlinePolicy(conn onlinePolicyAuthenticator, passphrase []byte) error {
	passphraseText := string(passphrase)
	if err := conn.Authenticate(passphraseText, onlinePolicyTimeout); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}
	status, err := conn.WaitForStatus(onlinePolicyTimeout)
	if err != nil {
		return fmt.Errorf("read signer status: %w", err)
	}
	if status.State != "locked" {
		return nil
	}
	result, err := conn.Unlock(passphraseText, onlinePolicyTimeout)
	if err != nil {
		return fmt.Errorf("unlock signer: %w", err)
	}
	if !result.Success {
		if result.Error != "" {
			return fmt.Errorf("unlock signer: %s", result.Error)
		}
		return fmt.Errorf("unlock signer failed")
	}
	return nil
}

func readOnlinePolicyYAML(stdin io.Reader) ([]byte, error) {
	data, err := io.ReadAll(stdin)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy YAML from stdin: %w", err)
	}
	if strings.TrimSpace(string(data)) == "" {
		return nil, fmt.Errorf("policy YAML on stdin is empty")
	}
	return data, nil
}

func onlinePolicyTarget(conn *transport.IPCClient) (policyeditor.Target, error) {
	id := fmt.Sprintf("appolicy-settings-%d", time.Now().UnixNano())
	raw, err := conn.SendAndReceive(protocol.GetAdminSettingsMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeGetAdminSettings, ID: id},
	}, onlinePolicyTimeout)
	if err != nil {
		return "", err
	}
	var settings protocol.AdminSettingsMessage
	if err := json.Unmarshal(raw, &settings); err != nil {
		return "", err
	}
	if strings.EqualFold(strings.TrimSpace(settings.NodeRole), "sentry") {
		return policyeditor.TargetSentry, nil
	}
	return policyeditor.TargetSigner, nil
}

func runPolicyFile(ctx context.Context, path string, opts options, store *policyeditor.OfflineStore, dataDir, identityID string, target policyeditor.Target, stdout, stderr io.Writer) int {
	data, err := readPolicyYAMLFile(path)
	if err != nil {
		writef(stderr, "appolicy: %v\n", err)
		return 1
	}
	parseTarget := target
	if opts.toSentry {
		parseTarget = policyeditor.TargetSigner
	}
	stored, err := parseTarget.Parse(data)
	if err != nil {
		writef(stderr, "appolicy: failed to parse %s: %v\n", parseTarget.DocumentName(), err)
		return 1
	}
	validateStore := *store
	if opts.toSentry {
		validateStore.Target = policyeditor.TargetSigner
	}
	if err := validateStore.Validate(ctx, stored); err != nil {
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
	if opts.toSentry {
		out, err := policy.ConvertSigningPolicyToSentry(stored)
		if err != nil {
			writef(stderr, "appolicy: failed to convert policy to sentry policy: %v\n", err)
			return 1
		}
		data, err := policy.MarshalStoredSentryConfig(out)
		if err != nil {
			writef(stderr, "appolicy: failed to marshal sentry policy: %v\n", err)
			return 1
		}
		_, _ = stdout.Write(data)
		return 0
	}

	writef(stdout, "%s OK: %s\n", target.StatusNoun(), path)
	if opts.check {
		return 0
	}
	if passphrase := passphraseFromEnv(); len(passphrase) > 0 {
		store.SetPassphrase(passphrase)
		crypto.ZeroBytes(passphrase)
	}
	if err := launchPolicyEditor(store, stored, dataDir, identityID, target); err != nil {
		writef(stderr, "appolicy: TUI failed: %v\n", err)
		return 1
	}
	if err := normalizeOfflinePolicyStore(dataDir); err != nil {
		writef(stderr, "appolicy: managed store ownership normalization failed: %v\n", err)
		return 1
	}
	return 0
}

var migrateOfflinePolicyStore = func(dataDir string, uid, gid int, socketPath string) error {
	_, err := storeperm.MigratePrivate(storeperm.LegacyMigrationOptions(dataDir, uid, gid, socketPath))
	return err
}

var (
	appolicyEUID         = os.Geteuid
	isManagedPolicyStore = signerbootstrap.IsProductionManagedDataDir
	managedPolicyOwner   = storeperm.ManagedServiceOwner
	loadPolicyConfig     = serverconfig.LoadServerConfig
	resolvePolicySocket  = adminipc.ResolveLegacyStoreSocketPath
)

// normalizeOfflinePolicyStore restores service ownership after a root-run
// offline rescue edit. Local same-UID stores already write with the correct
// owner and must never be migrated by a root invocation.
func normalizeOfflinePolicyStore(dataDir string) error {
	if appolicyEUID() != 0 || dataDir == "" {
		return nil
	}
	managed, err := isManagedPolicyStore(dataDir)
	if err != nil || !managed {
		return err
	}
	uid, gid, err := managedPolicyOwner(dataDir)
	if err != nil {
		return fmt.Errorf("resolve managed signer service principal: %w", err)
	}
	cfg, err := loadPolicyConfig(dataDir)
	if err != nil {
		return fmt.Errorf("load signer config: %w", err)
	}
	socketPath, err := resolvePolicySocket(dataDir, cfg.IPCPath)
	if err != nil {
		return fmt.Errorf("resolve legacy signer socket: %w", err)
	}
	return migrateOfflinePolicyStore(dataDir, uid, gid, socketPath)
}

func readPolicyYAMLFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy YAML file: %w", err)
	}
	if strings.TrimSpace(string(data)) == "" {
		return nil, fmt.Errorf("policy YAML file is empty")
	}
	return data, nil
}

func editOnlinePolicyFile(ctx context.Context, store *policyeditor.AdminStore, stored *policy.StoredConfig, target policyeditor.Target, policyFile string, stdout io.Writer) error {
	if _, err := store.Load(ctx); err != nil {
		return fmt.Errorf("failed to load active %s before editing draft: %w", target.StatusNoun(), err)
	}
	writef(stdout, "%s OK: %s\n", target.StatusNoun(), policyFile)
	if err := launchPolicyEditor(store, stored, "", policyeditor.DefaultIdentityID, target); err != nil {
		return fmt.Errorf("TUI failed: %w", err)
	}
	return nil
}

var launchPolicyEditor = func(store policyeditor.Store, stored *policy.StoredConfig, dataDir, identityID string, target policyeditor.Target) error {
	program := tea.NewProgram(
		policytui.NewWithTarget(store, stored, dataDir, identityID, target),
		tea.WithAltScreen(),
	)
	_, err := program.Run()
	return err
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

func resolveRunTarget(dataDir, policyFile string, requested policyeditor.Target, toSentry bool) (policyeditor.Target, error) {
	if toSentry {
		return policyeditor.TargetSigner, nil
	}
	if requested == "" || requested == policyeditor.TargetAuto {
		if policyFile != "" && dataDir == "" {
			return policyeditor.TargetSigner, nil
		}
		return policyeditor.ResolveTarget(dataDir, requested)
	}
	return policyeditor.ResolveTarget(dataDir, requested)
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
		return nil, fmt.Errorf("passphrase must come from APPOLICY_PASSPHRASE, APSIGNER_PASSPHRASE, or an interactive terminal when selected policy YAML is read from stdin")
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
