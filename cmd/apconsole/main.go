// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"flag"
	"fmt"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"

	"golang.org/x/sys/unix"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/addressdisplay"
	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/apshellcli"
	bootstrap "github.com/aplane-algo/aplane/internal/bootstrap/signer"
	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/manifest"
	"github.com/aplane-algo/aplane/internal/mnemonic"
	tui "github.com/aplane-algo/aplane/internal/signerapp/signertui"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
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

	RegisterProviders()

	for _, arg := range os.Args[1:] {
		if arg == "--print-manifest" || arg == "-print-manifest" {
			manifest.PrintAndExit()
		}
	}

	dataDir := flag.String("d", "", "Signer data directory (required for local mode, or set APSIGNER_DATA)")
	clientDataDir := flag.String("client-data", "", "Client data directory for shell/remote SSH mode (or set APCLIENT_DATA)")
	consoleConfig := flag.String("config", "", "apconsole profile path (default: auto-discover apconsole.yaml)")
	networkLong := flag.String("network", "", "Network context token for the shell pane")
	networkShort := flag.String("n", "", "Network context token for the shell pane")
	remoteMode := flag.Bool("remote", false, "Connect to apsigner over SSH admin subsystem instead of local IPC")
	noStartDaemon := flag.Bool("no-start-daemon", false, "Do not start apsigner when no local IPC socket exists")
	ipcPathFlag := flag.String("ipc-path", "", "Admin IPC socket path (or set APSIGNER_IPC_PATH)")
	flag.Parse()
	remoteModeSet := flagWasSet("remote")
	dataDirSet := flagWasSet("d")
	clientDataDirSet := flagWasSet("client-data")

	// SSH tunnel client emits status messages from background goroutines via
	// fmt.Print* (keepalive failures, "[SSH] Connection closed by remote
	// server", etc). Those would land on the TTY between bubbletea frames and
	// scramble the layout — discard them here.
	sshtunnel.SetStatusWriter(io.Discard)
	// internal/cache uses slog with an os.Stdout handler. Cache hits/misses,
	// integrity checks, and resolution debug logs would otherwise land on the
	// TTY mid-frame and corrupt the layout. Silence them in the TUI host.
	cache.SetLoggerOutput(io.Discard)

	if err := ensureProviders(); err != nil {
		logErrorf("%v", err)
		os.Exit(1)
	}
	network, err := apshellcli.ResolveNetworkOverride(*networkLong, *networkShort)
	if err != nil {
		logErrorf("%v", err)
		os.Exit(2)
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
		os.Exit(1)
	}

	if startupCfg.Mode == consoleModeRemote {
		remoteCfg, err := loadRemoteAdminConfig(startupCfg.ClientData)
		if err != nil {
			logErrorf("%v", err)
			os.Exit(1)
		}
		shellSession, shellStartup := loadShellConsole(remoteCfg.dataDir, network)
		shellStartup = append(consoleStartupNoticeLines(startupCfg.Notices), shellStartup...)
		daemon := newDaemonModel(daemonInfo{
			Status:  daemonStatusDisabled,
			DataDir: remoteCfg.dataDir,
			Detail:  "remote admin mode; daemon lifecycle is not managed by apconsole",
		}, nil)
		startConsole(remoteCfg.connector, remoteCfg.dataDir, "", shellSession, shellStartup, true, nil, daemon)
		return
	}

	resolvedDataDir, err := bootstrap.ResolveDataDir(startupCfg.SignerData)
	if err != nil {
		logErrorf("%v", err)
		logErrorf("use -d <path>, set APSIGNER_DATA, or configure signer_data in apconsole.yaml")
		os.Exit(1)
	}
	if accessErr := unix.Access(resolvedDataDir, unix.R_OK|unix.X_OK); accessErr != nil {
		if !os.IsPermission(accessErr) {
			logErrorf("cannot access data directory: %s", resolvedDataDir)
			os.Exit(1)
		}
		ipcPath, err := resolveConsoleIPCPath(resolvedDataDir, *ipcPathFlag, startupCfg.signerDataSource)
		if err != nil {
			logErrorf("%v", err)
			os.Exit(1)
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
		startConsole(tui.LocalIPCConnector{Path: ipcPath}, startupCfg.ClientData, "", shellSession, shellStartup, false, nil, daemon)
		return
	}

	startup, err := bootstrap.Load(startupCfg.SignerData)
	if err != nil {
		logErrorf("%v", err)
		logErrorf("use -d <path>, set APSIGNER_DATA, or configure signer_data in apconsole.yaml")
		os.Exit(1)
	}
	ipcPath, err := resolveConsoleIPCPath(startup.DataDir, *ipcPathFlag, startupCfg.signerDataSource)
	if err != nil {
		logErrorf("%v", err)
		os.Exit(1)
	}
	daemonIPCPath, err := resolveDaemonIPCPathForLifecycle(startup.DataDir, startup.Config.IPCPath, !*noStartDaemon)
	if err != nil {
		logErrorf("cannot resolve daemon IPC path: %v", err)
		os.Exit(1)
	}
	theme.Init(startup.Config.Theme)
	configureAlgodOnDSAs(startup.Config)
	nodeRole, roleWarning := consoleNodeRole(startup.Paths)
	daemonProcess, daemonStartup := prepareDaemonProcess(startup.DataDir, ipcPath, daemonIPCPath, !*noStartDaemon)
	if daemonStartup.Status == daemonStatusStarting {
		waitForDaemonReady(ipcPath, daemonProcess, daemonReadyTimeout)
	}
	if roleWarning != "" {
		logWarnf("%s", roleWarning)
	}
	var shellSession *apshellcli.Session
	var shellStartup []string
	shellEnabled := shellPaneEnabledForNodeRole(nodeRole)
	if shellEnabled {
		trustNotice, err := trustLocalSignerHostKey(startupCfg.ClientData, startup.Config)
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
		daemon.lines = append(daemon.lines, sentryShellDisabledLines(startupCfg.Notices)...)
	}

	startConsole(tui.LocalIPCConnector{Path: ipcPath}, startupCfg.ClientData, string(nodeRole), shellSession, shellStartup, shellEnabled, daemonProcess, daemon)
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

func startConsole(connector tui.AdminConnector, dataDir string, initialNodeRole string, shellSession *apshellcli.Session, shellStartup []string, shellEnabled bool, daemonProcess *daemonProcess, daemon daemonModel) {
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

	// Disable bubbletea's panic catching so a panic propagates here. We restore
	// the terminal, write the stack trace to a log file (alt-screen mode would
	// otherwise erase it on exit), and then re-panic so the trace also reaches
	// stderr if anything is reading it.
	model := newModelWithShell(
		connector, dataDir, shellExecutorForSession(shellSession), shellStartup,
		daemon, shellEnabled, initialNodeRole,
	)
	if width, height, ok := terminalSize(realStdout); ok {
		model.width = width
		model.height = height
	}

	p := tea.NewProgram(
		model,
		tea.WithAltScreen(),
		tea.WithoutCatchPanics(),
		tea.WithInput(realStdin),
		tea.WithOutput(realStdout),
	)
	if remoteConnector, ok := connector.(*tui.SSHAdminConnector); ok {
		remoteConnector.HostKeyApproval = func(host, fingerprint string) (bool, error) {
			resp := make(chan bool, 1)
			p.Send(shellHostKeyApprovalMsg{host: host, fingerprint: fingerprint, response: resp})
			return <-resp, nil
		}
	}
	// Wire the shell session's SSH host key approval through the TUI. The
	// goroutine running the shell command blocks on the response channel while
	// bubbletea renders the prompt in the shell pane and waits for y/N.
	if shellSession != nil {
		shellSession.SetHostKeyApproval(func(host, fingerprint string) (bool, error) {
			resp := make(chan bool, 1)
			p.Send(shellHostKeyApprovalMsg{host: host, fingerprint: fingerprint, response: resp})
			return <-resp, nil
		})
		shellSession.SetProgressLine(func(line string) {
			p.Send(shellProgressLineMsg{text: line})
		})
		shellSession.SetInteractiveLinePrompt(func(prompt string) (string, error) {
			resp := make(chan string, 1)
			p.Send(shellLinePromptMsg{prompt: prompt, response: resp})
			return <-resp, nil
		})
	}
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		// realStderr is captured because os.Stderr is currently /dev/null
		// (the redirect defer runs after this one in LIFO order).
		// Leave alt screen and re-enable cursor before printing/exiting.
		_, _ = fmt.Fprint(realStderr, "\x1b[?1049l\x1b[?25h")
		trace := debug.Stack()
		path := writePanicTrace(dataDir, r, trace)
		if path != "" {
			_, _ = fmt.Fprintf(realStderr, "apconsole panic — stack trace written to %s\n", path)
		}
		_, _ = fmt.Fprintf(realStderr, "panic: %v\n\n%s", r, trace)
		os.Exit(2)
	}()
	if _, err := p.Run(); err != nil {
		logErrorf("error running console: %v", err)
		os.Exit(1)
	}
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

	logicsigdsa.ConfigureAlgodClient(client)
	logInfof("TEAL compiler configured")
}
