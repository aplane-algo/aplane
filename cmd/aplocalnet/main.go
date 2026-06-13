// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// aplocalnet configures APlane for a running AlgoKit LocalNet.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/aplane-algo/aplane/internal/aplocalnet"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/plugin/discovery"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/theme"
	"github.com/aplane-algo/aplane/internal/version"
)

var (
	titleStyle    lipgloss.Style
	labelStyle    lipgloss.Style
	statusStyle   lipgloss.Style
	warningStyle  lipgloss.Style
	errorStyle    lipgloss.Style
	helpStyle     lipgloss.Style
	selectedStyle lipgloss.Style
)

type checkMsg struct {
	info aplocalnet.LocalNetInfo
	err  error
}

type applyMsg struct {
	result aplocalnet.ApplyResult
	err    error
}

type model struct {
	opts   aplocalnet.Options
	busy   bool
	status string
	info   *aplocalnet.LocalNetInfo
	result *aplocalnet.ApplyResult
	err    string
	width  int
}

func main() {
	var (
		clientDataDir string
		signerDataDir string
		algodURL      string
		algodToken    string
		kmdURL        string
		checkOnly     bool
		applyOnly     bool
		showVersion   bool
	)

	flag.StringVar(&clientDataDir, "client-data", "", "apclient data directory (defaults to APCLIENT_DATA or ~/aplane/apclient)")
	flag.StringVar(&signerDataDir, "signer-data", "", "apsigner data directory (defaults to APSIGNER_DATA or ~/aplane/apsigner)")
	flag.StringVar(&signerDataDir, "d", "", "apsigner data directory")
	flag.StringVar(&algodURL, "algod-url", "", "LocalNet algod URL")
	flag.StringVar(&algodToken, "algod-token", "", "LocalNet algod token")
	flag.StringVar(&kmdURL, "kmd-url", "", "LocalNet KMD URL for the bundled localnet plugin")
	flag.BoolVar(&checkOnly, "check", false, "check LocalNet reachability without writing config")
	flag.BoolVar(&applyOnly, "apply", false, "apply setup without launching the TUI")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Printf("aplocalnet %s\n", version.String())
		return
	}

	resolvedClientDataDir := resolveClientDataDir(clientDataDir)
	resolvedSignerDataDir := resolveSignerDataDir(signerDataDir)
	if applyOnly && (clientTargetSpecified(clientDataDir) || signerTargetSpecified(signerDataDir)) {
		if !clientTargetSpecified(clientDataDir) {
			resolvedClientDataDir = ""
		}
		if !signerTargetSpecified(signerDataDir) {
			resolvedSignerDataDir = ""
		}
	}

	opts := aplocalnet.NormalizeOptions(aplocalnet.Options{
		ClientDataDir: resolvedClientDataDir,
		SignerDataDir: resolvedSignerDataDir,
		AlgodURL:      algodURL,
		AlgodToken:    algodToken,
		KMDURL:        kmdURL,
	})

	switch {
	case checkOnly:
		if err := runCheck(opts); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	case applyOnly:
		if err := runApply(opts); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	theme.Init("auto")
	initStyles()

	p := tea.NewProgram(newModel(opts), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func resolveClientDataDir(flagValue string) string {
	if strings.TrimSpace(flagValue) != "" {
		return flagValue
	}
	if dataDir := apconfig.GetClientDataDir(""); dataDir != "" {
		return dataDir
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, "aplane", "apclient")
	}
	return ""
}

func clientTargetSpecified(flagValue string) bool {
	return strings.TrimSpace(flagValue) != "" || strings.TrimSpace(os.Getenv("APCLIENT_DATA")) != ""
}

func resolveSignerDataDir(flagValue string) string {
	if strings.TrimSpace(flagValue) != "" {
		return flagValue
	}
	if dataDir := serverconfig.GetSignerDataDir(""); dataDir != "" {
		return dataDir
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, "aplane", "apsigner")
	}
	return ""
}

func signerTargetSpecified(flagValue string) bool {
	return strings.TrimSpace(flagValue) != "" || strings.TrimSpace(os.Getenv("APSIGNER_DATA")) != ""
}

func runCheck(opts aplocalnet.Options) error {
	ctx, cancel := context.WithTimeout(context.Background(), aplocalnet.DefaultApplyTimeout)
	defer cancel()
	info, err := aplocalnet.CheckReachable(ctx, opts)
	if err != nil {
		return err
	}
	fmt.Printf("LocalNet reachable at %s\n", info.AlgodURL)
	fmt.Printf("Genesis ID: %s\n", info.GenesisID)
	fmt.Printf("Genesis hash: %s\n", info.GenesisHash)
	fmt.Printf("Last round: %d\n", info.LastRound)
	return nil
}

func runApply(opts aplocalnet.Options) error {
	ctx, cancel := context.WithTimeout(context.Background(), aplocalnet.DefaultApplyTimeout)
	defer cancel()
	result, err := aplocalnet.Apply(ctx, opts)
	if err != nil {
		return err
	}
	printApplyResult(result)
	return nil
}

func printApplyResult(result aplocalnet.ApplyResult) {
	fmt.Printf("LocalNet reachable at %s\n", result.LocalNet.AlgodURL)
	fmt.Printf("Genesis hash: %s\n", result.LocalNet.GenesisHash)
	if result.SignerConfigPath != "" {
		fmt.Printf("Signer config: %s (%s)\n", changedText(result.SignerConfigChanged), result.SignerConfigPath)
	}
	if result.ClientConfigPath != "" {
		fmt.Printf("Client config: %s (%s)\n", changedText(result.ClientConfigChanged), result.ClientConfigPath)
	}
	if result.PluginConfigPath != "" {
		fmt.Printf("Plugin activation: %s (%s)\n", changedText(result.PluginActivationChanged), result.PluginConfigPath)
	}
	if result.EnvConfigPath != "" {
		fmt.Printf("Plugin env: %s (%s)\n", changedText(result.EnvConfigChanged), result.EnvConfigPath)
	}
	for _, warning := range result.Warnings {
		fmt.Printf("Warning: %s\n", warning)
	}
}

func changedText(changed bool) string {
	if changed {
		return "updated"
	}
	return "already current"
}

func initStyles() {
	p := theme.Current()
	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(p.Title)).MarginBottom(1)
	labelStyle = lipgloss.NewStyle().Foreground(lipgloss.Color(p.Subtitle))
	statusStyle = lipgloss.NewStyle().Foreground(lipgloss.Color(p.StatusConnected))
	warningStyle = lipgloss.NewStyle().Foreground(lipgloss.Color(p.Warning))
	errorStyle = lipgloss.NewStyle().Foreground(lipgloss.Color(p.Error))
	helpStyle = lipgloss.NewStyle().Foreground(lipgloss.Color(p.Help))
	selectedStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.SelectedFg)).
		Background(lipgloss.Color(p.Selected))
}

func newModel(opts aplocalnet.Options) model {
	opts = aplocalnet.NormalizeOptions(opts)
	return model{
		opts:   opts,
		busy:   true,
		status: "checking LocalNet",
	}
}

func (m model) Init() tea.Cmd {
	return checkCmd(m.opts)
}

func checkCmd(opts aplocalnet.Options) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), aplocalnet.DefaultApplyTimeout)
		defer cancel()
		info, err := aplocalnet.CheckReachable(ctx, opts)
		return checkMsg{info: info, err: err}
	}
}

func applyCmd(opts aplocalnet.Options) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), aplocalnet.DefaultApplyTimeout)
		defer cancel()
		result, err := aplocalnet.Apply(ctx, opts)
		return applyMsg{result: result, err: err}
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			return m, tea.Quit
		case "r":
			if m.busy {
				return m, nil
			}
			m.busy = true
			m.status = "checking LocalNet"
			m.err = ""
			m.result = nil
			return m, checkCmd(m.opts)
		case "enter":
			if m.busy {
				return m, nil
			}
			m.busy = true
			m.status = "applying setup"
			m.err = ""
			m.result = nil
			return m, applyCmd(m.opts)
		}
	case checkMsg:
		m.busy = false
		if msg.err != nil {
			m.status = "LocalNet unreachable"
			m.err = msg.err.Error()
			m.info = nil
			return m, nil
		}
		m.status = "LocalNet reachable"
		m.info = &msg.info
		m.err = ""
		return m, nil
	case applyMsg:
		m.busy = false
		if msg.err != nil {
			m.status = "setup failed"
			m.err = msg.err.Error()
			m.result = nil
			return m, nil
		}
		m.status = "setup complete"
		m.info = &msg.result.LocalNet
		m.result = &msg.result
		m.err = ""
		return m, nil
	}
	return m, nil
}

func (m model) View() string {
	var sb strings.Builder
	sb.WriteString(titleStyle.Render("aplocalnet - LocalNet Setup"))
	sb.WriteString("\n")

	sb.WriteString(kv("Client data", m.opts.ClientDataDir))
	sb.WriteString(kv("Signer data", m.opts.SignerDataDir))
	sb.WriteString(kv("Algod", m.opts.AlgodURL))
	if m.opts.KMDURL != "" {
		sb.WriteString(kv("KMD", m.opts.KMDURL))
	}
	sb.WriteString(kv("Plugin", filepath.Join(m.opts.ClientDataDir, discovery.AvailableDirName, aplocalnet.PluginName)))
	sb.WriteString("\n")

	var statusLine string
	switch {
	case m.busy:
		statusLine = warningStyle.Render(m.status + "...")
	case m.err != "":
		statusLine = errorStyle.Render(m.status)
	default:
		statusLine = statusStyle.Render(m.status)
	}
	sb.WriteString(labelStyle.Render("Status:") + "      " + statusLine + "\n")

	if m.info != nil {
		sb.WriteString(kv("Genesis ID", m.info.GenesisID))
		sb.WriteString(kv("Genesis hash", m.info.GenesisHash))
		sb.WriteString(kv("Last round", fmt.Sprintf("%d", m.info.LastRound)))
	}
	if m.err != "" {
		sb.WriteString("\n")
		sb.WriteString(errorStyle.Render(wrap(m.err, contentWidth(m.width))))
		sb.WriteString("\n")
	}
	if m.result != nil {
		sb.WriteString("\n")
		if m.result.SignerConfigPath != "" {
			sb.WriteString(kv("Signer config", changedText(m.result.SignerConfigChanged)+" - "+m.result.SignerConfigPath))
		}
		if m.result.ClientConfigPath != "" {
			sb.WriteString(kv("Client config", changedText(m.result.ClientConfigChanged)+" - "+m.result.ClientConfigPath))
		}
		if m.result.PluginConfigPath != "" {
			sb.WriteString(kv("Plugin config", changedText(m.result.PluginActivationChanged)+" - "+m.result.PluginConfigPath))
		}
		if m.result.EnvConfigPath != "" {
			sb.WriteString(kv("Plugin env", changedText(m.result.EnvConfigChanged)+" - "+m.result.EnvConfigPath))
		}
		if m.result.PluginConfigPath != "" {
			if m.result.PluginAvailable {
				sb.WriteString(kv("Plugin payload", "installed"))
			} else {
				sb.WriteString(kv("Plugin payload", "not found"))
			}
		}
		for _, warning := range m.result.Warnings {
			sb.WriteString(warningStyle.Render("Warning: "+warning) + "\n")
		}
	}

	sb.WriteString("\n")
	if m.busy {
		sb.WriteString(helpStyle.Render("q quit"))
	} else {
		sb.WriteString(selectedStyle.Render("apply"))
		sb.WriteString(helpStyle.Render("  r recheck  q quit"))
	}
	sb.WriteString("\n")
	return sb.String()
}

func kv(label, value string) string {
	return labelStyle.Render(fmt.Sprintf("%-13s", label+":")) + " " + value + "\n"
}

func contentWidth(width int) int {
	if width < 40 {
		return 72
	}
	if width > 100 {
		return 100
	}
	return width - 4
}

func wrap(s string, width int) string {
	if width <= 0 || len(s) <= width {
		return s
	}
	words := strings.Fields(s)
	if len(words) == 0 {
		return s
	}
	var lines []string
	line := words[0]
	for _, word := range words[1:] {
		if len(line)+1+len(word) > width {
			lines = append(lines, line)
			line = word
			continue
		}
		line += " " + word
	}
	lines = append(lines, line)
	return strings.Join(lines, "\n")
}
