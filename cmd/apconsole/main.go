// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/addressdisplay"
	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/apshellcli"
	bootstrap "github.com/aplane-algo/aplane/internal/bootstrap/signer"
	"github.com/aplane-algo/aplane/internal/clientlog"
	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/manifest"
	"github.com/aplane-algo/aplane/internal/mnemonic"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	tui "github.com/aplane-algo/aplane/internal/signerapp/signertui"
	"github.com/aplane-algo/aplane/internal/theme"
	"github.com/aplane-algo/aplane/internal/version"
)

func main() {
	for _, arg := range os.Args[1:] {
		if arg == "--version" || arg == "-version" {
			fmt.Printf("apconsole %s\n", version.String())
			os.Exit(0)
		}
	}

	// Before anything can log: warnings raised while the shell pane's state loads
	// wait in the queue for the pane.
	clientlog.Install(clientlog.StartLevel(slog.LevelWarn), consoleLogs)

	RegisterProviders()

	for _, arg := range os.Args[1:] {
		if arg == "--print-manifest" || arg == "-print-manifest" {
			manifest.PrintAndExit()
		}
	}

	dataDir := flag.String("d", "", "Signer data directory (required for local mode, or set APSIGNER_DATA)")
	clientDataDir := flag.String("client-data", "", "Client data directory for the shell pane (or set APCLIENT_DATA)")
	consoleConfig := flag.String("config", "", "apconsole profile path (default: auto-discover apconsole.yaml)")
	networkLong := flag.String("network", "", "Network context token for the shell pane")
	networkShort := flag.String("n", "", "Network context token for the shell pane")
	remoteMode := flag.Bool("remote", false, "Removed: administration is IPC-only; SSH into the signer host instead")
	noStartDaemon := flag.Bool("no-start-daemon", false, "Do not start apsigner when no local IPC socket exists")
	ipcPathFlag := flag.String("ipc-path", "", "Admin IPC socket path (or set APSIGNER_IPC_PATH)")
	flag.Parse()
	remoteModeSet := flagWasSet("remote")
	dataDirSet := flagWasSet("d")
	clientDataDirSet := flagWasSet("client-data")

	if err := ensureProviders(); err != nil {
		logErrorf("%v", err)
		exitConsole(1)
	}
	network, err := apshellcli.ResolveNetworkOverride(*networkLong, *networkShort)
	if err != nil {
		logErrorf("%v", err)
		exitConsole(2)
	}

	wd, _ := os.Getwd()
	exe, _ := os.Executable()
	startupCfg, err := resolveConsoleStartup(consoleStartupFlags{
		ConfigPath:       *consoleConfig,
		RemoteSet:        remoteModeSet,
		Remote:           *remoteMode,
		SignerDataSet:    dataDirSet,
		SignerData:       *dataDir,
		ClientDataSet:    clientDataDirSet,
		ClientData:       *clientDataDir,
		CurrentDir:       wd,
		ExecutablePath:   exe,
		ClientDataEnv:    os.Getenv("APCLIENT_DATA"),
		SignerDataEnv:    os.Getenv("APSIGNER_DATA"),
		ConsoleConfigEnv: os.Getenv("APCONSOLE_CONFIG"),
	})
	if err != nil {
		logErrorf("%v", err)
		exitConsole(1)
	}

	resolvedDataDir, err := bootstrap.ResolveDataDir(startupCfg.SignerData)
	if err != nil {
		logErrorf("%v", err)
		logErrorf("use -d <path>, set APSIGNER_DATA, or configure signer_data in apconsole.yaml")
		exitConsole(1)
	}
	if accessErr := unix.Access(resolvedDataDir, unix.R_OK|unix.X_OK); accessErr != nil {
		if !os.IsPermission(accessErr) {
			logErrorf("cannot access data directory: %s", resolvedDataDir)
			exitConsole(1)
		}
		ipcPath, err := resolveConsoleIPCPath(resolvedDataDir, *ipcPathFlag, startupCfg.signerDataSource)
		if err != nil {
			logErrorf("%v", err)
			exitConsole(1)
		}
		theme.Init("")
		shellSession, shellStartup := loadShellConsole(startupCfg.ClientData, network)
		shellStartup = append(consoleStartupNoticeLines(startupCfg.Notices), shellStartup...)
		daemon := newDaemonModel(daemonInfo{
			Status:  daemonStatusDisabled,
			DataDir: resolvedDataDir,
			IPCPath: ipcPath,
			Detail:  "systemd attach mode; daemon lifecycle is not managed by apconsole",
		}, nil)
		// The private managed store prevents this operator process from reading
		// node.yaml directly. Keep the shell fail-closed until authenticated
		// admin settings identify the node as a signer.
		os.Exit(startConsole(tui.LocalIPCConnector{Path: ipcPath}, startupCfg.ClientData, "", shellSession, shellStartup, false, nil, daemon))
	}

	startup, err := bootstrap.Load(startupCfg.SignerData)
	if err != nil {
		logErrorf("%v", err)
		logErrorf("use -d <path>, set APSIGNER_DATA, or configure signer_data in apconsole.yaml")
		exitConsole(1)
	}
	ipcPath, err := resolveConsoleIPCPath(startup.DataDir, *ipcPathFlag, startupCfg.signerDataSource)
	if err != nil {
		logErrorf("%v", err)
		exitConsole(1)
	}
	daemonIPCPath, err := resolveDaemonIPCPathForLifecycle(startup.DataDir, startup.Config.IPCPath, !*noStartDaemon)
	if err != nil {
		logErrorf("cannot resolve daemon IPC path: %v", err)
		exitConsole(1)
	}
	// Detect the terminal's background until the signer pane reports the
	// theme saved in the signer's settings.
	theme.Init("auto")
	configureAlgodOnDSAs(startup.Config)
	nodeRole, roleWarning := consoleNodeRole(startup.Paths)
	daemonProcess, daemonStartup := prepareDaemonProcess(startup.DataDir, ipcPath, daemonIPCPath, !*noStartDaemon)
	watchConsoleSignals(daemonProcess)
	if daemonStartup.Status == daemonStatusStarting {
		waitForDaemonReady(ipcPath, daemonProcess, dialUnixSocketForDaemon, daemonReadyTimeout)
	}
	if roleWarning != "" {
		logWarnf("%s", roleWarning)
	}
	var shellSession *apshellcli.Session
	var shellStartup []string
	shellEnabled := shellPaneEnabledForNodeRole(nodeRole)
	if shellEnabled {
		// A daemon this console just started opens its SSH listener after
		// its IPC socket, so give the probe a moment to find it listening.
		var probeWait time.Duration
		if daemonStartup.Status == daemonStatusStarting {
			probeWait = localSignerProbeStartupWait
		}
		trustNotice, err := trustLocalSignerHostKey(startupCfg.ClientData, startup.Config, probeWait)
		if err != nil {
			logWarnf("could not pretrust local signer SSH host key: %v", err)
		}
		shellSession, shellStartup = loadShellConsole(startupCfg.ClientData, network)
		shellStartup = append(consoleStartupNoticeLines(startupCfg.Notices), shellStartup...)
		if trustNotice != "" {
			shellStartup = append(shellStartup, "[config] "+trustNotice)
		}
	}
	daemon := newDaemonModel(daemonStartup, daemonProcessEventChan(daemonProcess))
	if !shellEnabled {
		daemon.lines = append(daemon.lines, cosignerShellDisabledLines(startupCfg.Notices)...)
		daemon.configNotices = len(startupCfg.Notices) > 0
	}

	os.Exit(startConsole(tui.LocalIPCConnector{Path: ipcPath}, startupCfg.ClientData, string(nodeRole), shellSession, shellStartup, shellEnabled, daemonProcess, daemon))
}

// consoleLogs queues diagnostics for the shell pane. Its Close writes what the
// pane never took, so a console with no shell still reports them on exit.
var consoleLogs = clientlog.NewDeferred()

// exitConsole leaves before the TUI starts, writing out any queued diagnostics
// first, because os.Exit skips deferred calls.
func exitConsole(code int) {
	_ = consoleLogs.Close(os.Stderr)
	os.Exit(code)
}

func consoleStartupNoticeLines(notices []string) []string {
	if len(notices) == 0 {
		return nil
	}
	lines := make([]string, 0, len(notices)+1)
	for _, notice := range notices {
		lines = append(lines, "[config] "+notice)
	}
	lines = append(lines, "")
	return lines
}

func flagWasSet(name string) bool {
	wasSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			wasSet = true
		}
	})
	return wasSet
}

// startConsole runs the console program and returns the process exit code. It
// never exits itself: main exits once the deferred calls here have stopped the
// owned apsigner, shut the shell session down and restored stdio, whatever
// ended the program.
func startConsole(connector tui.AdminConnector, dataDir string, initialNodeRole string, shellSession *apshellcli.Session, shellStartup []string, shellEnabled bool, daemonProcess *daemonProcess, daemon daemonModel) int {
	if shellSession != nil {
		defer shellSession.Shutdown()
	}
	if daemonProcess != nil {
		defer daemonProcess.Stop()
	}

	// Hand bubbletea the real terminal handle, then redirect os.Stdout and
	// os.Stderr to /dev/null for the duration of the program. Any code path
	// inside the embedded apshell session, plugin runtime, signer pane, etc.
	// that calls fmt.Print* / log.Print would otherwise write straight to the
	// TTY between bubbletea frames and corrupt the layout. The deferred
	// restore runs after bubbletea exits so post-exit messages still show.
	realStdin := os.Stdin
	realStdout := os.Stdout
	realStderr := os.Stderr
	// addressdisplay.SupportsColor() peeks at os.Stdout to decide whether to emit ANSI.
	// After we redirect to /dev/null it would otherwise return false, killing
	// the color in `keys`/`alias` output. Force it on while bubbletea owns the
	// real terminal — the captured buffer renders to a colored pane.
	addressdisplay.SetColorSupported(true)
	if devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0); err == nil {
		os.Stdin = devnull
		os.Stdout = devnull
		os.Stderr = devnull
		defer func() {
			os.Stdin = realStdin
			os.Stdout = realStdout
			os.Stderr = realStderr
			addressdisplay.ResetColorSupport()
			_ = devnull.Close()
		}()
	}

	model := newModelWithShell(
		connector, shellExecutorForSession(shellSession), shellStartup,
		daemon, shellEnabled, initialNodeRole,
	)
	if shellSession != nil {
		model.shell.logs = consoleLogs
	}
	if width, height, ok := terminalSize(realStdout); ok {
		model.width = width
		model.height = height
	}

	// Bubble Tea's panic catching stays on, and the guard turns a panic in a
	// Cmd goroutine into a quit: whatever panics, the terminal is restored and
	// the program ends, so the deferred calls above still run. The guard keeps
	// the panic's stack for the report below.
	guard, guarded := newPanicGuard(model)
	p := tea.NewProgram(
		guarded,
		tea.WithAltScreen(),
		tea.WithInput(realStdin),
		tea.WithOutput(realStdout),
	)
	// Wire the shell session's SSH host key approval through the TUI. The
	// goroutine running the shell command blocks on the response channel while
	// bubbletea renders the prompt in the shell pane and waits for y/N.
	if shellSession != nil {
		shellSession.SetHostKeyApprovalContext(func(ctx context.Context, host, fingerprint string) (bool, error) {
			resp := make(chan bool, 1)
			p.Send(shellHostKeyApprovalMsg{host: host, fingerprint: fingerprint, response: resp})
			select {
			case approved := <-resp:
				return approved, nil
			case <-ctx.Done():
				p.Send(shellPromptCanceledMsg{hostResponse: resp})
				return false, ctx.Err()
			}
		})
		shellSession.SetProgressLine(func(line string) {
			p.Send(shellProgressLineMsg{text: line})
		})
		shellSession.SetInteractiveLinePromptContext(func(ctx context.Context, prompt string) (string, error) {
			resp := make(chan string, 1)
			p.Send(shellLinePromptMsg{prompt: prompt, response: resp})
			select {
			case line := <-resp:
				return line, nil
			case <-ctx.Done():
				p.Send(shellPromptCanceledMsg{lineResponse: resp})
				return "", ctx.Err()
			}
		})
	}
	consolePhase.Store(consoleRunning)
	final, err := p.Run()
	consolePhase.Store(consoleShuttingDown)
	// Straight away: session shutdown can still log. Records from here on go
	// directly to the terminal. stderr is the only channel left if this fails.
	_ = consoleLogs.Close(realStderr)
	// Whatever ended the program, release what an unfinished backup transfer
	// in the signer pane holds (a staging file, an open archive, a passphrase).
	shutdownSignerPane(guard.finalModel(final))
	if caught := guard.recorded(); caught != nil || errors.Is(err, tea.ErrProgramPanic) {
		reportConsolePanic(realStderr, dataDir, caught)
		return 2
	}
	if err != nil {
		logErrorf("error running console: %v", err)
		return 1
	}
	return 0
}

// reportConsolePanic writes the panic's stack trace to a file, because the
// terminal's scrollback may not keep it, and to stderr.
func reportConsolePanic(stderr io.Writer, dataDir string, caught *consolePanic) {
	if caught == nil {
		_, _ = fmt.Fprintln(stderr, "apconsole panic: no stack trace recorded")
		return
	}
	if path := writePanicTrace(dataDir, caught.value, caught.stack); path != "" {
		_, _ = fmt.Fprintf(stderr, "apconsole panic — stack trace written to %s\n", path)
	}
	_, _ = fmt.Fprintf(stderr, "panic: %v\n\n%s", caught.value, caught.stack)
}

func shellExecutorForSession(session *apshellcli.Session) shellExecutor {
	if session == nil {
		return nil
	}
	return session
}

func terminalSize(f *os.File) (width, height int, ok bool) {
	if f == nil {
		return 0, 0, false
	}
	ws, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
	if err != nil || ws == nil || ws.Col == 0 || ws.Row == 0 {
		return 0, 0, false
	}
	return int(ws.Col), int(ws.Row), true
}

func writePanicTrace(dataDir string, r interface{}, trace []byte) string {
	name := fmt.Sprintf("apconsole-panic-%d.log", time.Now().Unix())
	candidates := []string{}
	if dataDir != "" {
		candidates = append(candidates, filepath.Join(dataDir, name))
	}
	candidates = append(candidates, filepath.Join(os.TempDir(), name))
	for _, p := range candidates {
		body := fmt.Sprintf("apconsole panic at %s\nrecovered: %v\n\n%s", time.Now().Format(time.RFC3339), r, trace)
		if err := os.WriteFile(p, []byte(body), 0o600); err == nil {
			return p
		}
	}
	return ""
}

func daemonProcessEventChan(p *daemonProcess) <-chan daemonEvent {
	if p == nil {
		return nil
	}
	return p.events
}

func ensureProviders() error {
	if len(keygen.GetRegisteredFamilies()) == 0 {
		return fmt.Errorf("no key generators registered - check providers.go imports")
	}
	if len(mnemonic.GetRegisteredFamilies()) == 0 {
		return fmt.Errorf("no mnemonic handlers registered - check providers.go imports")
	}
	if len(algorithm.GetRegisteredFamilies()) == 0 {
		return fmt.Errorf("no algorithm metadata registered - check providers.go imports")
	}
	return nil
}

func configureAlgodOnDSAs(config serverconfig.ServerConfig) {
	cfg, err := config.GetTEALCompileAlgod()
	if err != nil || cfg.Server == "" {
		logWarnf("no algod.%s.server configured - composed Falcon templates unavailable", config.TEALCompileNetwork)
		return
	}

	client, err := algod.MakeClient(cfg.Server, cfg.Token)
	if err != nil {
		logWarnf("failed to create algod client: %v", err)
		logWarnf("composed Falcon templates will be unavailable")
		return
	}

	lsigprovider.ConfigureAlgodClient(client)
}
