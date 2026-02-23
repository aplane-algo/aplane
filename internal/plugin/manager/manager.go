// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package manager handles the lifecycle of external plugins
package manager

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/aplane-algo/aplane/internal/plugin/discovery"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	"github.com/aplane-algo/aplane/internal/plugin/sandbox"
)

// Instance represents a running plugin instance
type Instance struct {
	Plugin   *discovery.Plugin
	Process  *exec.Cmd
	Client   *jsonrpc.Client
	Started  time.Time
	LastUsed time.Time

	stdin  io.WriteCloser
	stdout io.ReadCloser
	stderr io.ReadCloser
}

// Manager manages external plugin instances
type Manager struct {
	discoverer    *discovery.Discoverer
	instances     map[string]*Instance // key is plugin name
	cachedPlugins []*discovery.Plugin  // cached discovery results
	mu            sync.RWMutex

	// Configuration
	network    string
	apiServer  string
	apiToken   string
	indexerURL string
}

// NewManager creates a new plugin manager
func NewManager() *Manager {
	return &Manager{
		discoverer: discovery.New(),
		instances:  make(map[string]*Instance),
	}
}

// SetConfig configures the manager
func (m *Manager) SetConfig(network, apiServer, apiToken, indexerURL string) {
	m.network = network
	m.apiServer = apiServer
	m.apiToken = apiToken
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

	for _, plugin := range plugins {
		if plugin.Manifest.FindCommand(command) != nil {
			return plugin, nil
		}
	}
	return nil, fmt.Errorf("no plugin provides command: %s", command)
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
		inst.LastUsed = time.Now()
		m.mu.RUnlock()
		return inst, nil
	}
	m.mu.RUnlock()

	// Find the plugin using cached discovery (outside lock to avoid deadlock)
	plugin, err := m.FindByName(pluginName)
	if err != nil {
		return nil, err
	}

	// Check if plugin supports current network
	if !plugin.Manifest.SupportsNetwork(m.network) {
		return nil, fmt.Errorf("plugin %s doesn't support network %s", pluginName, m.network)
	}

	// Acquire write lock for starting the plugin
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check if another goroutine started it while we were discovering
	if inst, ok := m.instances[pluginName]; ok {
		inst.LastUsed = time.Now()
		return inst, nil
	}

	// Start the plugin
	instance, err := m.startPluginInstance(plugin)
	if err != nil {
		return nil, err
	}

	// Initialize the plugin
	if err := m.initializePlugin(instance); err != nil {
		instance.Stop()
		return nil, fmt.Errorf("failed to initialize plugin: %w", err)
	}

	m.instances[pluginName] = instance
	return instance, nil
}

// startPluginInstance starts a plugin subprocess
func (m *Manager) startPluginInstance(plugin *discovery.Plugin) (*Instance, error) {
	execPath := plugin.Manifest.GetExecutablePath(plugin.Dir)

	// Build environment
	env := append(os.Environ(),
		fmt.Sprintf("APSHELL_NETWORK=%s", m.network),
		fmt.Sprintf("APSHELL_API_SERVER=%s", m.apiServer),
		fmt.Sprintf("APSHELL_API_TOKEN=%s", m.apiToken),
		fmt.Sprintf("APSHELL_INDEXER_URL=%s", m.indexerURL),
		"APSHELL_PLUGIN=1",
	)

	// Build sandboxed command
	cfg := sandbox.Config{
		PluginDir:    plugin.Dir,
		ExecPath:     execPath,
		Args:         plugin.Manifest.Args,
		Env:          env,
		AllowNetwork: true, // Plugins need algod/indexer access
	}

	cmd, err := sandbox.BuildCommand(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to start plugin: %w", err)
	}

	fmt.Fprintf(os.Stderr, "[%s] Running in sandbox (%s)\n", plugin.Manifest.Name, sandbox.GetSandboxInfo())

	// Create pipes
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Start the process
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start plugin: %w", err)
	}

	// Create JSON-RPC client
	client := jsonrpc.NewClient(stdout, stdin)
	client.Start()

	instance := &Instance{
		Plugin:   plugin,
		Process:  cmd,
		Client:   client,
		Started:  time.Now(),
		LastUsed: time.Now(),
		stdin:    stdin,
		stdout:   stdout,
		stderr:   stderr,
	}

	// Monitor stderr in background
	go m.monitorStderr(instance)

	return instance, nil
}

// initializePlugin sends the initialize request to the plugin
func (m *Manager) initializePlugin(instance *Instance) error {
	params := jsonrpc.InitializeParams{
		Network:    m.network,
		APIServer:  m.apiServer,
		APIToken:   m.apiToken,
		IndexerURL: m.indexerURL,
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

// monitorStderr reads and logs plugin stderr output
func (m *Manager) monitorStderr(instance *Instance) {
	buf := make([]byte, 1024)
	for {
		n, err := instance.stderr.Read(buf)
		if err != nil {
			break
		}
		if n > 0 {
			fmt.Fprintf(os.Stderr, "[%s stderr]: %s", instance.Plugin.Manifest.Name, buf[:n])
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

	instance.LastUsed = time.Now()

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
		return nil, fmt.Errorf("command execution failed: %w", err)
	}

	return &result, nil
}

// StopPlugin stops a running plugin
func (m *Manager) StopPlugin(pluginName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	instance, ok := m.instances[pluginName]
	if !ok {
		return nil // Not running
	}

	// Send shutdown request
	var result jsonrpc.ShutdownResult
	_ = instance.Client.CallWithTimeout(jsonrpc.MethodShutdown, jsonrpc.ShutdownParams{}, &result, 5*time.Second)

	// Stop the instance
	instance.Stop()

	delete(m.instances, pluginName)
	return nil
}

// StopAll stops all running plugins
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for name, instance := range m.instances {
		// Send shutdown request
		var result jsonrpc.ShutdownResult
		_ = instance.Client.CallWithTimeout(jsonrpc.MethodShutdown, jsonrpc.ShutdownParams{}, &result, 5*time.Second)

		instance.Stop()
		delete(m.instances, name)
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
	defer m.mu.Unlock()

	now := time.Now()
	for name, instance := range m.instances {
		if now.Sub(instance.LastUsed) > idleTimeout {
			// Send shutdown request
			var result jsonrpc.ShutdownResult
			_ = instance.Client.CallWithTimeout(jsonrpc.MethodShutdown, jsonrpc.ShutdownParams{}, &result, 5*time.Second)

			instance.Stop()
			delete(m.instances, name)
		}
	}
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
