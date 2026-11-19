// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package manager handles the lifecycle of external plugins
package manager

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/plugin/discovery"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	"github.com/aplane-algo/aplane/internal/plugin/sandbox"
)

const (
	// maxStderrLineBytes bounds one piece of plugin stderr. A longer line is
	// reported in pieces so the pipe keeps draining. It leaves room for the prefix
	// within the logging pipeline's line limit.
	maxStderrLineBytes = 3072
	// maxHeldStderrLines is how many hidden stderr lines each plugin keeps for
	// the report after a failure.
	maxHeldStderrLines = 20
	// stderrDrainWait bounds the wait for a failed plugin's last stderr lines.
	// A plugin that exited reaches EOF at once; one that hung uses all of it.
	stderrDrainWait = 200 * time.Millisecond
)

var (
	ErrNoPluginForCommand     = errors.New("no plugin provides command")
	ErrDuplicatePluginCommand = errors.New("multiple plugins provide command")
	ErrPluginStateInUse       = errors.New("plugin state directory in use")
)

// Instance represents a running plugin instance
type Instance struct {
	Plugin  *discovery.Plugin
	Process *exec.Cmd
	Client  *jsonrpc.Client
	Started time.Time

	stdin     io.WriteCloser
	stdout    io.ReadCloser
	stderr    io.ReadCloser
	stateLock *pluginStateLock

	// stderrDone closes when monitorStderr returns. It is nil for instances
	// that have no stderr monitor.
	stderrDone chan struct{}
	// heldStderr is the newest stderr that wasn't logged, kept for a failure
	// report. It is raw plugin text; the logging handler escapes it.
	heldStderrMu sync.Mutex
	heldStderr   []string
}

// Manager manages external plugin instances
type Manager struct {
	discoverer    *discovery.Discoverer
	instances     map[string]*Instance // key is plugin name
	cachedPlugins []*discovery.Plugin  // cached discovery results
	mu            sync.RWMutex

	// Configuration
	network    string
	algodURL   string
	algodToken string
	indexerURL string

	// dataDir is the apshell data dir; per-plugin state directories live under
	// dataDir/plugin-state/<name>. Empty disables persistent plugin state.
	dataDir string

	startPluginInstanceHook func(*discovery.Plugin, runtimeConfig) (*Instance, error)
	initializePluginHook    func(*Instance, runtimeConfig) error
}

type runtimeConfig struct {
	network    string
	algodURL   string
	algodToken string
	indexerURL string
}

// TestHooks provides narrow manager hooks for package-external tests.
// These are only intended for test code inside this module.
type TestHooks struct {
	StartPluginInstance func(*discovery.Plugin) (*Instance, error)
	InitializePlugin    func(*Instance) error
}

// NewManagerWithDataDir creates a new plugin manager scoped to an apshell data dir.
func NewManagerWithDataDir(dataDir string) *Manager {
	discoverer := discovery.New()
	resolvedDataDir := config.GetClientDataDir("")
	if dataDir != "" {
		discoverer = discovery.NewWithDataDir(dataDir)
		resolvedDataDir = dataDir
	}
	return &Manager{
		discoverer: discoverer,
		instances:  make(map[string]*Instance),
		dataDir:    resolvedDataDir,
	}
}

// pluginStateDir returns (creating if needed) the private, writable, persistent
// state directory for a plugin, mounted read-write in the sandbox. It lives under
// dataDir/plugin-state/<name>, outside the read-only checksummed payload. Returns
// an empty path when no data dir is configured (persistent state disabled).
func (m *Manager) pluginStateDir(name string) (string, error) {
	if m.dataDir == "" {
		return "", nil
	}
	if !validPluginStateName(name) {
		return "", fmt.Errorf("invalid plugin name for state directory: %q", name)
	}
	dir := filepath.Join(m.dataDir, "plugin-state", name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("failed to create plugin state directory: %w", err)
	}
	return dir, nil
}

// validPluginStateName rejects names that could escape the plugin-state directory.
func validPluginStateName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return false
	}
	return name == filepath.Base(name)
}

// SetCachedPluginsForTest seeds the cached discovery result for tests.
func (m *Manager) SetCachedPluginsForTest(plugins []*discovery.Plugin) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cachedPlugins = plugins
}

// SetTestHooks installs narrow lifecycle hooks for package-external tests.
func (m *Manager) SetTestHooks(hooks TestHooks) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if hooks.StartPluginInstance != nil {
		m.startPluginInstanceHook = func(plugin *discovery.Plugin, _ runtimeConfig) (*Instance, error) {
			return hooks.StartPluginInstance(plugin)
		}
	} else {
		m.startPluginInstanceHook = nil
	}
	if hooks.InitializePlugin != nil {
		m.initializePluginHook = func(instance *Instance, _ runtimeConfig) error {
			return hooks.InitializePlugin(instance)
		}
	} else {
		m.initializePluginHook = nil
	}
}

// NewTestInstanceForHooks constructs an Instance for package-external tests.
// It is only intended for test code inside this module.
func NewTestInstanceForHooks(
	plugin *discovery.Plugin,
	process *exec.Cmd,
	client *jsonrpc.Client,
	stdin io.WriteCloser,
	stdout io.ReadCloser,
	stderr io.ReadCloser,
	started time.Time,
) *Instance {
	return &Instance{
		Plugin:  plugin,
		Process: process,
		Client:  client,
		Started: started,
		stdin:   stdin,
		stdout:  stdout,
		stderr:  stderr,
	}
}

// SetConfig configures the manager
func (m *Manager) SetConfig(network, algodURL, algodToken, indexerURL string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.network = network
	m.algodURL = algodURL
	m.algodToken = algodToken
	m.indexerURL = indexerURL
}

// DiscoverPluginsCached returns cached plugin list, discovering if needed.
func (m *Manager) DiscoverPluginsCached() ([]*discovery.Plugin, error) {
	m.mu.RLock()
	if m.cachedPlugins != nil {
		plugins := m.cachedPlugins
		m.mu.RUnlock()
		return plugins, nil
	}
	m.mu.RUnlock()

	// Need to discover - upgrade to write lock
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring write lock
	if m.cachedPlugins != nil {
		return m.cachedPlugins, nil
	}

	plugins, err := m.discoverer.Discover()
	if err != nil {
		return nil, err
	}
	m.cachedPlugins = plugins
	return plugins, nil
}

// FindByCommand finds a plugin that provides the given command (uses cache).
func (m *Manager) FindByCommand(command string) (*discovery.Plugin, error) {
	plugins, err := m.DiscoverPluginsCached()
	if err != nil {
		return nil, err
	}

	var matches []*discovery.Plugin
	for _, plugin := range plugins {
		if plugin.Manifest.FindCommand(command) != nil {
			matches = append(matches, plugin)
		}
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoPluginForCommand, command)
	}
	if len(matches) > 1 {
		names := make([]string, 0, len(matches))
		for _, plugin := range matches {
			names = append(names, plugin.Manifest.Name)
		}
		return nil, fmt.Errorf("%w %q: %v", ErrDuplicatePluginCommand, command, names)
	}
	return matches[0], nil
}

// FindByName finds a plugin by its manifest name (uses cache).
func (m *Manager) FindByName(name string) (*discovery.Plugin, error) {
	plugins, err := m.DiscoverPluginsCached()
	if err != nil {
		return nil, err
	}

	for _, plugin := range plugins {
		if plugin.Manifest.Name == name {
			return plugin, nil
		}
	}
	return nil, fmt.Errorf("plugin not found: %s", name)
}

// ListCommands returns all commands from all plugins (uses cache).
func (m *Manager) ListCommands() ([]string, error) {
	plugins, err := m.DiscoverPluginsCached()
	if err != nil {
		return nil, err
	}

	var commands []string
	for _, plugin := range plugins {
		for _, cmd := range plugin.Manifest.Commands {
			commands = append(commands, cmd.Name)
		}
	}
	return commands, nil
}

// StartPlugin starts a plugin if not already running
func (m *Manager) StartPlugin(pluginName string) (*Instance, error) {
	// Check if already running (read lock)
	m.mu.RLock()
	if inst, ok := m.instances[pluginName]; ok {

		m.mu.RUnlock()
		return inst, nil
	}
	m.mu.RUnlock()

	// Find the plugin using cached discovery (outside lock to avoid deadlock)
	plugin, err := m.FindByName(pluginName)
	if err != nil {
		return nil, err
	}

	cfg := m.configSnapshot()

	// Check if plugin supports current network
	if !plugin.Manifest.SupportsNetwork(cfg.network) {
		return nil, fmt.Errorf("plugin %s doesn't support network %s", pluginName, cfg.network)
	}

	// Snapshot startup hooks under lock, but do not hold the manager lock while
	// starting or initializing the subprocess, which takes as long as the plugin
	// does.
	m.mu.Lock()
	if inst, ok := m.instances[pluginName]; ok {

		m.mu.Unlock()
		return inst, nil
	}
	startFn := m.startPluginInstance
	if m.startPluginInstanceHook != nil {
		startFn = m.startPluginInstanceHook
	}
	initFn := m.initializePlugin
	if m.initializePluginHook != nil {
		initFn = m.initializePluginHook
	}
	m.mu.Unlock()

	instance, err := startFn(plugin, cfg)
	if err != nil {
		return nil, err
	}
	if err := initFn(instance, cfg); err != nil {
		instance.reportHeldStderr()
		instance.Stop()
		return nil, fmt.Errorf("failed to initialize plugin: %w", err)
	}

	m.mu.Lock()
	if inst, ok := m.instances[pluginName]; ok {

		m.mu.Unlock()
		instance.Stop()
		return inst, nil
	}
	m.instances[pluginName] = instance
	m.mu.Unlock()
	return instance, nil
}

// startPluginInstance starts a plugin subprocess
func (m *Manager) startPluginInstance(plugin *discovery.Plugin, cfg runtimeConfig) (*Instance, error) {
	execPath := plugin.Manifest.GetExecutablePath(plugin.Dir)

	stateDir, err := m.pluginStateDir(plugin.Manifest.Name)
	if err != nil {
		return nil, err
	}
	stateLock, err := lockPluginStateDir(stateDir)
	if err != nil {
		return nil, err
	}
	cleanupStateLock := func() {
		if stateLock != nil {
			stateLock.Release()
		}
	}

	// Build environment
	env := append(os.Environ(),
		fmt.Sprintf("APSHELL_NETWORK=%s", cfg.network),
		fmt.Sprintf("APSHELL_ALGOD_URL=%s", cfg.algodURL),
		fmt.Sprintf("APSHELL_ALGOD_TOKEN=%s", cfg.algodToken),
		fmt.Sprintf("APSHELL_INDEXER_URL=%s", cfg.indexerURL),
		"APSHELL_PLUGIN=1",
	)
	if stateDir != "" {
		env = append(env, fmt.Sprintf("APSHELL_PLUGIN_STATE_DIR=%s", stateDir))
	}

	// Build sandboxed command
	sandboxCfg := sandbox.Config{
		PluginName: plugin.Manifest.Name,
		PluginDir:  plugin.Dir,
		StateDir:   stateDir,
		ExecPath:   execPath,
		Args:       plugin.Manifest.Args,
		Env:        env,
	}

	cmd, err := sandbox.BuildCommand(sandboxCfg)
	if err != nil {
		cleanupStateLock()
		return nil, fmt.Errorf("failed to start plugin: %w", err)
	}

	logSandboxBanner(plugin)

	// Create pipes
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cleanupStateLock()
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		cleanupStateLock()
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		cleanupStateLock()
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Start the process
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		_ = stderr.Close()
		cleanupStateLock()
		return nil, fmt.Errorf("failed to start plugin: %w", err)
	}

	// Create JSON-RPC client
	client := jsonrpc.NewClient(stdout, stdin)
	client.Start()

	instance := &Instance{
		Plugin:    plugin,
		Process:   cmd,
		Client:    client,
		Started:   time.Now(),
		stdin:     stdin,
		stdout:    stdout,
		stderr:    stderr,
		stateLock: stateLock,

		stderrDone: make(chan struct{}),
	}

	// Monitor stderr in background
	go instance.monitorStderr()

	return instance, nil
}

// initializePlugin sends the initialize request to the plugin
func (m *Manager) initializePlugin(instance *Instance, cfg runtimeConfig) error {
	params := jsonrpc.InitializeParams{
		Network:    cfg.network,
		AlgodURL:   cfg.algodURL,
		AlgodToken: cfg.algodToken,
		IndexerURL: cfg.indexerURL,
	}

	var result jsonrpc.InitializeResult
	timeout := time.Duration(instance.Plugin.Manifest.Timeout) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	err := instance.Client.CallWithTimeout(jsonrpc.MethodInitialize, params, &result, timeout)
	if err != nil {
		return err
	}

	if !result.Success {
		return fmt.Errorf("plugin initialization failed: %s", result.Message)
	}
	if result.Protocol != jsonrpc.PluginProtocol {
		return fmt.Errorf("unsupported plugin protocol %q: host requires %q", result.Protocol, jsonrpc.PluginProtocol)
	}

	return nil
}

func (m *Manager) configSnapshot() runtimeConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return runtimeConfig{
		network:    m.network,
		algodURL:   m.algodURL,
		algodToken: m.algodToken,
		indexerURL: m.indexerURL,
	}
}

// monitorStderr reads plugin stderr until EOF, one line at a time. It must keep
// reading whether or not the lines are shown: a plugin blocks once the pipe fills.
func (i *Instance) monitorStderr() {
	if i.stderrDone != nil {
		defer close(i.stderrDone)
	}
	reader := bufio.NewReaderSize(i.stderr, maxStderrLineBytes)
	for {
		line, err := reader.ReadSlice('\n')
		if len(line) > 0 {
			i.logStderrLine(string(line))
		}
		if err != nil && !errors.Is(err, bufio.ErrBufferFull) {
			return
		}
	}
}

// pluginLogger returns the logger for what a plugin says. The plugin's name goes
// in its own attribute, never as the component: a plugin chooses its name, and
// the handler shows these records under a prefix a plugin cannot imitate.
func pluginLogger(name string) *slog.Logger {
	return slog.With("component", "plugin", "plugin", name)
}

func (i *Instance) stderrLogger() *slog.Logger {
	return pluginLogger(i.Plugin.Manifest.Name).With("stream", "stderr")
}

func logSandboxBanner(plugin *discovery.Plugin) {
	pluginLogger(plugin.Manifest.Name).Info(fmt.Sprintf("Running in sandbox (%s)", sandbox.GetSandboxInfo()))
}

// logStderrLine logs one line at info, because a plugin's stderr is routine detail
// and nothing in its text can raise that. A line that wouldn't be shown is held
// instead, in case the plugin then fails.
func (i *Instance) logStderrLine(raw string) {
	line := strings.TrimRight(raw, "\r\n")
	logger := i.stderrLogger()
	if logger.Enabled(context.Background(), slog.LevelInfo) {
		logger.Info(line)
		return
	}
	i.holdStderr(line)
}

func (i *Instance) holdStderr(line string) {
	i.heldStderrMu.Lock()
	defer i.heldStderrMu.Unlock()
	i.heldStderr = append(i.heldStderr, line)
	if len(i.heldStderr) > maxHeldStderrLines {
		i.heldStderr = i.heldStderr[len(i.heldStderr)-maxHeldStderrLines:]
	}
}

func (i *Instance) takeHeldStderr() []string {
	i.heldStderrMu.Lock()
	defer i.heldStderrMu.Unlock()
	held := i.heldStderr
	i.heldStderr = nil
	return held
}

// reportHeldStderr logs the held stderr of a plugin that just failed, as warnings
// so they show at the default level, because that output is often the only record
// of why it failed. That is the host's decision; the text still carries the plugin
// prefix. Call it before stopping the instance: Stop closes the pipe, which would
// lose lines still in flight.
func (i *Instance) reportHeldStderr() {
	if i.stderrDone != nil {
		select {
		case <-i.stderrDone:
		case <-time.After(stderrDrainWait):
		}
	}
	logger := i.stderrLogger()
	for _, line := range i.takeHeldStderr() {
		logger.Warn(line)
	}
}

// abandonGrace is how long a plugin whose call was abandoned has to exit
// once its stdin closes, so a stateful plugin can finish writing its own
// state, before it is killed. It bounds how long a cancel waits.
const abandonGrace = time.Second

// ExecuteCommand executes a command on a plugin. It ends when ctx does, and
// then stops the plugin, which is still running the abandoned command,
// within abandonGrace. A ctx already ended starts no plugin.
func (m *Manager) ExecuteCommand(ctx context.Context, pluginName, command string, args []string, pluginContext jsonrpc.Context) (*jsonrpc.ExecuteResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("command not run: %w", err)
	}
	// Start plugin if needed
	instance, err := m.StartPlugin(pluginName)
	if err != nil {
		return nil, err
	}

	params := jsonrpc.ExecuteParams{
		Command: command,
		Args:    args,
		Context: pluginContext,
	}

	var result jsonrpc.ExecuteResult
	if err := m.call(ctx, pluginName, instance, jsonrpc.MethodExecute, params, &result); err != nil {
		return nil, fmt.Errorf("command execution failed: %w", err)
	}
	return &result, nil
}

// call makes one call to a running instance within its manifest's timeout.
// A failed call discards the instance; one abandoned because ctx ended stops
// it within abandonGrace rather than waiting for it to finish what it was
// asked.
func (m *Manager) call(ctx context.Context, pluginName string, instance *Instance, method string, params, result interface{}) error {
	timeout := time.Duration(instance.Plugin.Manifest.Timeout) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	err := instance.Client.CallContext(ctx, method, params, result, timeout)
	if err == nil {
		return nil
	}
	instance.reportHeldStderr()
	if ctx.Err() != nil {
		m.abandonInstance(pluginName, instance)
	} else {
		m.discardInstance(pluginName, instance)
	}
	return err
}

// SignTransactions asks a running plugin to sign the canonical bytes for the slots
// it owns (declared via ExecuteResult.PluginSigners), as part of the pre-sign
// planning flow. It reuses the instance left running after ExecuteCommand, so the
// plugin's signing material is never exported to APlane. It ends when ctx does,
// as ExecuteCommand does, and a ctx already ended starts no plugin.
func (m *Manager) SignTransactions(ctx context.Context, pluginName string, params jsonrpc.SignTransactionsParams) (*jsonrpc.SignTransactionsResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("plugin signTransactions not run: %w", err)
	}
	instance, err := m.StartPlugin(pluginName)
	if err != nil {
		return nil, err
	}

	var result jsonrpc.SignTransactionsResult
	if err := m.call(ctx, pluginName, instance, jsonrpc.MethodSignTransactions, params, &result); err != nil {
		return nil, fmt.Errorf("plugin signTransactions failed: %w", err)
	}
	return &result, nil
}

func (m *Manager) discardInstance(pluginName string, instance *Instance) {
	if m.forgetInstance(pluginName, instance) {
		instance.Stop()
	}
}

// abandonInstance is discardInstance for a plugin whose call was abandoned:
// it gets abandonGrace, not Stop's few seconds, to exit before it is killed.
func (m *Manager) abandonInstance(pluginName string, instance *Instance) {
	if m.forgetInstance(pluginName, instance) {
		instance.stop(abandonGrace)
	}
}

// forgetInstance removes instance as pluginName's running instance, and
// reports whether it was, and so is the caller's to stop.
func (m *Manager) forgetInstance(pluginName string, instance *Instance) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.instances[pluginName]
	if !ok || current != instance {
		return false
	}
	delete(m.instances, pluginName)
	return true
}

// StopAll stops all running plugins
func (m *Manager) StopAll() {
	m.mu.Lock()
	instances := make([]*Instance, 0, len(m.instances))
	for name, instance := range m.instances {
		instances = append(instances, instance)
		delete(m.instances, name)
	}
	m.mu.Unlock()

	for _, instance := range instances {
		stopInstance(instance)
	}
}

// GetRunningPlugins returns a list of running plugin names
func (m *Manager) GetRunningPlugins() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.instances))
	for name := range m.instances {
		names = append(names, name)
	}
	return names
}

// stopInstance asks the plugin to shut down, then stops it. The request is not
// sent if another frame is still being written to the plugin after a brief
// wait, so a plugin that stopped reading its input cannot hold the stop up;
// otherwise its write and its answer get five seconds.
func stopInstance(instance *Instance) {
	if instance.Client != nil {
		_ = instance.Client.Shutdown(5 * time.Second)
	}
	instance.Stop()
}

// Stop terminates a plugin instance, giving its process time to exit.
func (i *Instance) Stop() {
	i.stop(5 * time.Second)
}

// stop terminates the instance: its stdin closes, and its process is killed
// if it has not exited within grace.
func (i *Instance) stop(grace time.Duration) {
	defer func() {
		if i.stateLock != nil {
			i.stateLock.Release()
		}
	}()
	if i.Process == nil {
		return
	}

	// Close pipes (best-effort cleanup)
	_ = i.stdin.Close()
	_ = i.stdout.Close()
	_ = i.stderr.Close()

	// Give process time to exit cleanly
	done := make(chan error, 1)
	go func() {
		done <- i.Process.Wait()
	}()

	select {
	case <-done:
		// Process exited cleanly
	case <-time.After(grace):
		// Force kill (best effort)
		_ = i.Process.Process.Kill()
		<-done
	}

	i.Client.Close()
}
