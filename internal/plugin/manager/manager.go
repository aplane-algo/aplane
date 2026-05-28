// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package manager handles the lifecycle of external plugins
package manager

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aplane-algo/aplane/internal/plugin/discovery"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	"github.com/aplane-algo/aplane/internal/plugin/sandbox"
)

var (
	ErrNoPluginForCommand     = errors.New("no plugin provides command")
	ErrDuplicatePluginCommand = errors.New("multiple plugins provide command")
)

// Instance represents a running plugin instance
type Instance struct {
	Plugin  *discovery.Plugin
	Process *exec.Cmd
	Client  *jsonrpc.Client
	Started time.Time

	lastUsed atomic.Int64

	stdin  io.WriteCloser
	stdout io.ReadCloser
	stderr io.ReadCloser
}

func (i *Instance) touch() {
	i.lastUsed.Store(time.Now().UnixNano())
}

func (i *Instance) lastUsedTime() time.Time {
	return time.Unix(0, i.lastUsed.Load())
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

	stderrWriter io.Writer

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

// NewManager creates a new plugin manager
func NewManager() *Manager {
	return NewManagerWithDataDir("")
}

// NewManagerWithDataDir creates a new plugin manager scoped to an apshell data dir.
func NewManagerWithDataDir(dataDir string) *Manager {
	discoverer := discovery.New()
	if dataDir != "" {
		discoverer = discovery.NewWithDataDir(dataDir)
	}
	return &Manager{
		discoverer:   discoverer,
		instances:    make(map[string]*Instance),
		stderrWriter: os.Stderr,
	}
}

// SetStderrWriter overrides the destination for plugin stderr output and the
// sandbox-startup banner. Pass io.Discard to suppress noise in TUI hosts where
// raw stderr corrupts the display. Defaults to os.Stderr; nil restores it.
func (m *Manager) SetStderrWriter(w io.Writer) {
	if w == nil {
		w = os.Stderr
	}
	m.mu.Lock()
	m.stderrWriter = w
	m.mu.Unlock()
}

func (m *Manager) stderr() io.Writer {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.stderrWriter == nil {
		return os.Stderr
	}
	return m.stderrWriter
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

// DiscoverPlugins finds all available plugins (no caching, always fresh)
func (m *Manager) DiscoverPlugins() ([]*discovery.Plugin, error) {
	return m.discoverer.Discover()
}

// DiscoverPluginsCached returns cached plugin list, discovering if needed.
// Use InvalidateCache() to force re-discovery on next call.
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

// InvalidateCache clears the cached plugin list, forcing re-discovery on next call.
func (m *Manager) InvalidateCache() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cachedPlugins = nil
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
		inst.touch()
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
	// starting or initializing the subprocess. Plugin startup emits stderr
	// through m.stderr(), which also reads manager state.
	m.mu.Lock()
	if inst, ok := m.instances[pluginName]; ok {
		inst.touch()
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
		instance.Stop()
		return nil, fmt.Errorf("failed to initialize plugin: %w", err)
	}

	m.mu.Lock()
	if inst, ok := m.instances[pluginName]; ok {
		inst.touch()
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

	// Build environment
	env := append(os.Environ(),
		fmt.Sprintf("APSHELL_NETWORK=%s", cfg.network),
		fmt.Sprintf("APSHELL_ALGOD_URL=%s", cfg.algodURL),
		fmt.Sprintf("APSHELL_ALGOD_TOKEN=%s", cfg.algodToken),
		fmt.Sprintf("APSHELL_INDEXER_URL=%s", cfg.indexerURL),
		"APSHELL_PLUGIN=1",
	)

	// Build sandboxed command
	sandboxCfg := sandbox.Config{
		PluginDir:    plugin.Dir,
		ExecPath:     execPath,
		Args:         plugin.Manifest.Args,
		Env:          env,
		AllowNetwork: true, // Plugins need algod/indexer access
	}

	cmd, err := sandbox.BuildCommand(sandboxCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to start plugin: %w", err)
	}

	_, _ = fmt.Fprintf(m.stderr(), "[%s] Running in sandbox (%s)\n", plugin.Manifest.Name, sandbox.GetSandboxInfo())

	// Create pipes
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Start the process
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		_ = stderr.Close()
		return nil, fmt.Errorf("failed to start plugin: %w", err)
	}

	// Create JSON-RPC client
	client := jsonrpc.NewClient(stdout, stdin)
	client.Start()

	instance := &Instance{
		Plugin:  plugin,
		Process: cmd,
		Client:  client,
		Started: time.Now(),
		stdin:   stdin,
		stdout:  stdout,
		stderr:  stderr,
	}

	// Monitor stderr in background
	go m.monitorStderr(instance)

	return instance, nil
}

// initializePlugin sends the initialize request to the plugin
func (m *Manager) initializePlugin(instance *Instance, cfg runtimeConfig) error {
	params := jsonrpc.InitializeParams{
		Network:    cfg.network,
		AlgodURL:   cfg.algodURL,
		AlgodToken: cfg.algodToken,
		IndexerURL: cfg.indexerURL,
		Version:    "1.0", // apshell version
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

// monitorStderr reads and logs plugin stderr output
func (m *Manager) monitorStderr(instance *Instance) {
	buf := make([]byte, 1024)
	for {
		n, err := instance.stderr.Read(buf)
		if err != nil {
			break
		}
		if n > 0 {
			_, _ = fmt.Fprintf(m.stderr(), "[%s stderr]: %s", instance.Plugin.Manifest.Name, buf[:n])
		}
	}
}

// ExecuteCommand executes a command on a plugin
func (m *Manager) ExecuteCommand(pluginName, command string, args []string, context jsonrpc.Context) (*jsonrpc.ExecuteResult, error) {
	// Start plugin if needed
	instance, err := m.StartPlugin(pluginName)
	if err != nil {
		return nil, err
	}

	instance.touch()

	params := jsonrpc.ExecuteParams{
		Command: command,
		Args:    args,
		Context: context,
	}

	var result jsonrpc.ExecuteResult
	timeout := time.Duration(instance.Plugin.Manifest.Timeout) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	err = instance.Client.CallWithTimeout(jsonrpc.MethodExecute, params, &result, timeout)
	if err != nil {
		m.discardInstance(pluginName, instance)
		return nil, fmt.Errorf("command execution failed: %w", err)
	}

	return &result, nil
}

func (m *Manager) discardInstance(pluginName string, instance *Instance) {
	m.mu.Lock()
	current, ok := m.instances[pluginName]
	if !ok || current != instance {
		m.mu.Unlock()
		return
	}

	delete(m.instances, pluginName)
	m.mu.Unlock()
	instance.Stop()
}

// StopPlugin stops a running plugin
func (m *Manager) StopPlugin(pluginName string) error {
	m.mu.Lock()
	instance, ok := m.instances[pluginName]
	if !ok {
		m.mu.Unlock()
		return nil // Not running
	}
	delete(m.instances, pluginName)
	m.mu.Unlock()

	stopInstance(instance)
	return nil
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

// CleanupIdlePlugins stops plugins that haven't been used recently
func (m *Manager) CleanupIdlePlugins(idleTimeout time.Duration) {
	m.mu.Lock()
	now := time.Now()
	var idle []*Instance
	for name, instance := range m.instances {
		if now.Sub(instance.lastUsedTime()) > idleTimeout {
			idle = append(idle, instance)
			delete(m.instances, name)
		}
	}
	m.mu.Unlock()

	for _, instance := range idle {
		stopInstance(instance)
	}
}

func stopInstance(instance *Instance) {
	if instance.Client != nil {
		var result jsonrpc.ShutdownResult
		_ = instance.Client.CallWithTimeout(jsonrpc.MethodShutdown, jsonrpc.ShutdownParams{}, &result, 5*time.Second)
	}
	instance.Stop()
}

// Stop terminates a plugin instance
func (i *Instance) Stop() {
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
	case <-time.After(5 * time.Second):
		// Force kill (best effort)
		_ = i.Process.Process.Kill()
		<-done
	}

	i.Client.Close()
}

// IsRunning checks if the plugin process is still running
func (i *Instance) IsRunning() bool {
	if i.Process == nil || i.Process.Process == nil {
		return false
	}

	// Check if process is still alive
	return i.Process.ProcessState == nil
}
