// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/manifest"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
	"github.com/aplane-algo/aplane/internal/util"
	utilkeys "github.com/aplane-algo/aplane/internal/util/keys"
	"github.com/aplane-algo/aplane/internal/version"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

func main() {
	// Handle early-exit flags before any other output
	printVersion := flag.Bool("version", false, "Print version and exit")
	printManifest := flag.Bool("print-manifest", false, "Print provider manifest (JSON) for auditing and exit")
	dataDir := flag.String("d", "", "Data directory (required, or set APSIGNER_DATA)")
	flag.Parse()
	if *printVersion {
		fmt.Printf("apsignerd %s\n", version.String())
		os.Exit(0)
	}
	if *printManifest {
		manifest.PrintAndExit()
	}

	// Resolve data directory from -d flag or APSIGNER_DATA env var
	resolvedDataDir := util.RequireSignerDataDir(*dataDir)

	// Register all providers (must be called before using any registries)
	RegisterProviders()

	ensureProviders()

	fmt.Println("Signer - Post-Quantum Signing Server")
	fmt.Println("============================================")
	fmt.Printf("Data directory: %s\n", resolvedDataDir)

	// Plugin audit: Log all registered signature providers at startup
	registeredSigners := signing.GetRegisteredFamilies()
	if len(registeredSigners) > 0 {
		fmt.Printf("✓ Loaded signature providers: %v\n", registeredSigners)
	} else {
		fmt.Printf("⚠ WARNING: No signature providers registered (check plugins.go)\n")
	}
	fmt.Println("--------------------------------------------")

	// Load config file from data directory
	config := util.LoadServerConfig(resolvedDataDir)

	// Parse passphrase timeout from config
	passphraseTimeout, err := util.ParsePassphraseTimeout(config.PassphraseTimeout)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Warning: Invalid passphrase_timeout in config: %v, using default (0)\n", err)
		_ = os.Stderr.Sync()
		passphraseTimeout = 0
	}

	// Use config values for port settings
	port := config.SignerPort

	// Log the session timeout mode
	if passphraseTimeout == 0 {
		fmt.Println("⚠️  Session timeout: never (signer stays unlocked indefinitely)")
		fmt.Println("   Set passphrase_timeout in config for auto-lock after inactivity.")
	} else {
		fmt.Printf("Session timeout: %s (auto-locks after inactivity)\n", passphraseTimeout.String())
	}

	// Validate and set store path (must be done before any key operations)
	if config.StoreDir == "" {
		fmt.Fprintln(os.Stderr, "Error: store must be specified in config.yaml")
		fmt.Fprintln(os.Stderr, "Example: store: store")
		os.Exit(1)
	}
	utilkeys.SetKeystorePath(config.StoreDir)
	fmt.Printf("Store directory: %s\n", utilkeys.KeystorePath())

	// If the store directory doesn't exist, stay locked (apstore init creates it)
	if _, err := os.Stat(utilkeys.KeystorePath()); os.IsNotExist(err) {
		fmt.Println("Store directory not found; staying locked until keystore is initialized via apstore init.")
	}

	// Load or generate API token
	apiToken, err := util.LoadaPlaneToken(auth.DefaultIdentityID)
	if err != nil {
		fmt.Printf("Error: Failed to load API token: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✓ API token loaded from %s\n", util.GetaPlaneTokenPath(auth.DefaultIdentityID))

	// Memory Security: Attempt to disable core dumps and lock memory
	// Results are validated by ValidateStartup below
	runtime := &RuntimeState{}

	if err := disableCoreDumps(); err == nil {
		runtime.CoreDumpsDisabled = true
		fmt.Println("✓ Core dumps disabled")
	}

	// Skip memory locking if DISABLE_MEMORY_LOCK is set (for testing)
	if os.Getenv("DISABLE_MEMORY_LOCK") != "" {
		runtime.MemoryLocked = false
	} else if err := lockMemory(); err == nil {
		runtime.MemoryLocked = true
		fmt.Println("✓ Memory locked (keys will not swap to disk)")
	}

	// Comprehensive startup validation (config + runtime)
	// This handles required vs optional checks and prints warnings
	startupInfo, err := validateStartup(&config, runtime)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Startup validation failed: %v\n", err)
		os.Exit(1)
	}

	// Passphrase handling for encryption
	// Use SecureString to minimize passphrase exposure in memory
	var encPassphrase *crypto.SecureString
	var startLocked bool
	var passphraseSource string // Track source for security audit

	if !startupInfo.KeystoreExists {
		// No keystore — force locked startup, skip passphrase handling entirely
		fmt.Println("\n🔐 Starting in LOCKED state (keystore not initialized)")
		fmt.Println("   Run 'apstore init' to create the keystore, then unlock via apadmin")
		encPassphrase = crypto.NewSecureStringFromBytes(nil)
		startLocked = true
		passphraseSource = "ipc"
	} else if testPass := os.Getenv("TEST_PASSPHRASE"); testPass != "" {
		// Testing mode - unlocks immediately
		// Convert to bytes for secure handling, then zero the intermediate copy
		testPassBytes := []byte(testPass)
		encPassphrase = crypto.NewSecureStringFromBytes(testPassBytes)
		fmt.Println("\n🔐 Using TEST_PASSPHRASE for encryption (testing mode)")
		startLocked = false
		passphraseSource = "TEST_PASSPHRASE"

		// Verify passphrase matches existing control file
		if err := crypto.VerifyPassphraseWithMetadata(testPassBytes, config.StoreDir); err != nil {
			crypto.ZeroBytes(testPassBytes)
			fmt.Fprintf(os.Stderr, "Error: TEST_PASSPHRASE does not match existing keystore\n")
			os.Exit(1)
		}
		crypto.ZeroBytes(testPassBytes)
	} else if len(config.PassphraseCommandArgv) > 0 {
		// Headless mode - obtain passphrase via passphrase command
		cmdCfg := config.PassphraseCommandCfg()
		cmdCfg.Verb = "read"
		passphraseBytes, err := util.RunPassphraseCommand(cmdCfg, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		// Verify passphrase against .keystore
		if err := crypto.VerifyPassphraseWithMetadata(passphraseBytes, config.StoreDir); err != nil {
			crypto.ZeroBytes(passphraseBytes)
			fmt.Fprintf(os.Stderr, "Error: passphrase from passphrase command does not match existing keystore\n")
			fmt.Fprintf(os.Stderr, "       The passphrase_command_argv must return the same passphrase used to create the keystore\n")
			os.Exit(1)
		}
		encPassphrase = crypto.NewSecureStringFromBytes(passphraseBytes)
		fmt.Printf("\n🔐 Passphrase loaded via passphrase command\n")
		fmt.Println("   Starting in UNLOCKED state (headless mode)")
		startLocked = false
		passphraseSource = "passphrase_command"
		crypto.ZeroBytes(passphraseBytes)
	} else {
		// Default: Start in locked state, passphrase via apadmin IPC
		fmt.Println("\n🔐 Starting in LOCKED state")
		fmt.Println("   Connect with apadmin to unlock")
		encPassphrase = crypto.NewSecureStringFromBytes(nil)
		startLocked = true
		passphraseSource = "ipc"
	}

	// Initialize key store (file-based, identity-scoped keys directory)
	keyStore := keystore.NewFileKeyStore(auth.DefaultIdentityID)

	// Scan keys directory (skip if starting locked - keys loaded after unlock)
	// Keys are loaded later via reloadKeys() for both headless and locked modes
	// This ensures consistent initialization through a single code path
	if startLocked {
		fmt.Println("🔒 Keys will be loaded after unlock via apadmin TUI")
	}

	// Create key session for secure key management (uses KeyStore for key retrieval)
	keySession := keystore.NewKeySession(keyStore)

	// Pre-initialize session with passphrase
	// This avoids prompting again on first transaction since we already have the
	// passphrase from terminal (which supports masked input, unlike HTTP prompts)
	_ = encPassphrase.WithBytes(func(p []byte) error {
		keySession.InitializeSession(p)
		return nil
	})

	// Note: encPassphrase is stored in server.encryptionPassphrase and may be replaced
	// at runtime (e.g., by tryUnlock). Shutdown zeroing uses the Signer's field, not this local.

	// Initialize audit logger
	auditLog, err := NewAuditLogger(filepath.Join(resolvedDataDir, "audit.log"))
	if err != nil {
		fmt.Printf("Warning: Failed to initialize audit log: %v\n", err)
		// Continue without audit logging - not fatal
	} else {
		fmt.Println("✓ Audit logging enabled (audit.log)")
	}

	// Log policy settings
	fmt.Printf("Policy settings:\n")
	fmt.Printf("  txn_auto_approve: %v\n", config.EffectiveTxnAutoApprove())
	fmt.Printf("  group_auto_approve: %v\n", config.GroupAutoApprove)
	fmt.Printf("  allow_group_modification: %v\n", config.AllowGroupModification)

	// Warn about unusual configs in interactive mode (not headless)
	if len(config.PassphraseCommandArgv) == 0 {
		printInteractiveModeWarnings(&config)
	}

	// Create authenticator (currently token-based, extensible to mTLS/OIDC)
	authenticator := auth.NewTokenAuthenticator(apiToken)

	// Create authorizer (currently allow-all, extensible to RBAC)
	authorizer := auth.NewAllowAllAuthorizer()

	server := &Signer{
		keyStore:               keyStore,
		keys:                   map[string]map[string]string{auth.DefaultIdentityID: {}},
		keyTypes:               map[string]map[string]string{auth.DefaultIdentityID: {}},
		keyLsigSizes:           map[string]map[string]int{auth.DefaultIdentityID: {}},
		keySession:             keySession,
		sessionTimeout:         passphraseTimeout,
		encryptionPassphrase:   encPassphrase,
		authenticator:          authenticator,
		authorizer:             authorizer,
		auditLog:               auditLog,
		config:                 &config,
		tealCompilerAlgodURL:   config.TEALCompilerAlgodURL,
		tealCompilerAlgodToken: config.TEALCompilerAlgodToken,
	}

	// Configure algod client on all DSA providers that need it (for TEAL compilation)
	configureAlgodOnDSAs(config.TEALCompilerAlgodURL, config.TEALCompilerAlgodToken)

	// Initialize signer hub
	server.hub = NewHub(server)
	if startLocked {
		// Already in locked state by default in NewHub
		fmt.Println("✓ Signer hub initialized (waiting for apadmin connection)")
	} else {
		// Headless mode: load keys using the same path as apadmin unlock
		// This ensures consistent initialization (templates, keys, keyTypes)
		fmt.Println("\nScanning keys/ directory for private keys...")
		if err := server.reloadKeys(); err != nil {
			fmt.Fprintf(os.Stderr, "Error loading keys: %v\n", err)
			os.Exit(1)
		}
		server.hub.SetUnlocked()
		server.resetSessionTimer()

		server.keysLock.RLock()
		keyCount := len(server.keysForIdentity(auth.DefaultIdentityID))
		server.keysLock.RUnlock()
		if keyCount == 0 {
			fmt.Println("⚠️  No private keys found in keys/ directory")
			fmt.Println("Keys must be generated using the apadmin tool:")
			fmt.Println("  1. Run apadmin on this machine (local access required)")
			fmt.Println("  2. Use 'generate' command to create new keys")
			fmt.Println("  3. Use 'import' command to restore from mnemonic")
			fmt.Println("\nServer will start and keys will auto-load when created...")
		}
	}

	// Initialize IPC admin interface
	lockOnDisconnect := config.ShouldLockOnDisconnect()
	server.ipcServer = NewIPCServer(config.IPCPath, server.hub, lockOnDisconnect, passphraseTimeout)
	if err := server.ipcServer.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to start IPC server: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✓ Admin interface: IPC (%s)\n", config.IPCPath)

	// Print consolidated security audit
	printSecurityAudit(passphraseTimeout, &config, config.IPCPath, runtime.CoreDumpsDisabled, runtime.MemoryLocked, lockOnDisconnect, passphraseSource)

	// Log server start
	server.keysLock.RLock()
	defaultKeys := server.keysForIdentity(auth.DefaultIdentityID)
	keyCount := len(defaultKeys)
	keysSnapshot := make(map[string]string, keyCount)
	for k, v := range defaultKeys {
		keysSnapshot[k] = v
	}
	server.keysLock.RUnlock()

	if auditLog != nil {
		auditLog.LogServerStart(keyCount)
	}

	// Create dedicated ServeMux (avoid global default mux)
	// All endpoints except /health require authentication and authorization
	mux := http.NewServeMux()
	mux.HandleFunc("/sign", server.requireAuth(auth.ActionSign, auth.Resource{Type: "transaction"}, server.handleSign))
	mux.HandleFunc("/plan", server.requireAuth(auth.ActionSign, auth.Resource{Type: "transaction"}, server.handlePlan))
	mux.HandleFunc("/keys", server.requireAuth(auth.ActionListKeys, auth.Resource{Type: "keys"}, server.handleKeys))
	mux.HandleFunc("/keytypes", server.requireAuth(auth.ActionListKeys, auth.Resource{Type: "keytypes"}, server.handleKeyTypes))
	mux.HandleFunc("/admin/generate", server.requireAuth(auth.ActionManageKeys, auth.Resource{Type: "key"}, server.handleAdminGenerate))
	mux.HandleFunc("/admin/keys", server.requireAuth(auth.ActionManageKeys, auth.Resource{Type: "key"}, server.handleAdminDelete))
	mux.HandleFunc("/health", server.handleHealth) // Health check is public (no auth required)

	fmt.Printf("\n>> Starting Signer on port %d\n", port)
	fmt.Printf(">> Loaded %d key(s)\n", keyCount)
	i := 1
	for address, keyFile := range keysSnapshot {
		fmt.Printf("   %d. %s\n", i, address)
		fmt.Printf("      Key File: %s\n", keyFile)
		i++
	}
	fmt.Printf("\nEndpoints:\n")
	fmt.Printf("  POST   /sign                    - Sign transactions (handles groups, dummies, fee pooling)\n")
	fmt.Printf("  POST   /plan                    - Preview group building (no signing, no approval)\n")
	fmt.Printf("  GET    /keys                    - List all available signing addresses\n")
	fmt.Printf("  GET    /keytypes                - List available key types and creation parameters\n")
	fmt.Printf("  POST   /admin/generate           - Generate a new key\n")
	fmt.Printf("  DELETE /admin/keys?address=...   - Delete a key (soft delete)\n")
	fmt.Printf("  GET    /health                  - Health check\n")
	fmt.Printf("\nKey Management:\n")
	fmt.Printf("  Use 'apadmin' tool or /admin/* REST endpoints for key operations\n")
	fmt.Printf("  Keys auto-reload when filesystem changes detected\n")

	fmt.Println(strings.Repeat("=", 50))

	// Determine REST API bind address based on SSH tunnel availability
	// If SSH tunnel is enabled: bind to localhost only (secure)
	// If SSH tunnel is disabled: bind to all interfaces (direct access)
	var httpBindAddr string
	if config.SSHEnabled() {
		httpBindAddr = fmt.Sprintf("127.0.0.1:%d", port)
	} else {
		httpBindAddr = fmt.Sprintf("0.0.0.0:%d", port)
	}

	// Create HTTP server with our dedicated mux
	httpServer := &http.Server{
		Addr:              httpBindAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second, // Prevent SlowLoris attacks
	}

	// Create SSH server for public key authenticated connections (if enabled)
	var sshServer *sshtunnel.Server
	var sshServerCtx context.Context
	var sshServerCancel context.CancelFunc

	if config.SSHEnabled() {
		sshServerCtx, sshServerCancel = context.WithCancel(context.Background())

		listenAddr := fmt.Sprintf("0.0.0.0:%d", config.SSH.Port)
		targetAddr := fmt.Sprintf("127.0.0.1:%d", port)

		var err error
		sshServer, err = sshtunnel.NewServer(listenAddr, targetAddr, config.SSH.HostKeyPath, config.SSH.AuthorizedKeysPath, apiToken, config.ShouldAutoRegisterSSHKeys())
		if err != nil {
			fmt.Printf("Error: Failed to create SSH server: %v\n", err)
			os.Exit(1)
		}

		// Set up session callback for audit logging
		if auditLog != nil {
			sshServer.SetSessionCallback(func(remoteAddr, user string, connected bool) {
				if connected {
					auditLog.LogSessionConnected(user, remoteAddr, user)
				} else {
					auditLog.LogSessionDisconnected(user, remoteAddr, user)
				}
			})
		}

		// Set up token provisioning callbacks for SSH-based token requests
		sshServer.SetOperatorCheckCallback(func() bool {
			return server.hub.HasClient()
		})
		sshServer.SetTokenProvisioningCallback(func(identityID, sshFingerprint, remoteAddr string) (string, error) {
			return server.handleTokenProvisioning(identityID, sshFingerprint, remoteAddr)
		})

		if err := sshServer.Start(sshServerCtx); err != nil {
			fmt.Printf("Error: Failed to start SSH server: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("✓ SSH server started on %s (public key authentication)\n", listenAddr)
		fmt.Printf("  Host key fingerprint: %s\n", sshServer.GetHostKeyFingerprint())
		fmt.Printf("✓ REST API listening on %s (localhost only - accessed via SSH tunnel)\n", httpBindAddr)
	} else {
		fmt.Printf("✓ SSH tunnel disabled (no ssh block in config)\n")
		fmt.Printf("✓ REST API listening on %s (direct access - no tunnel)\n", httpBindAddr)
	}

	// Create context for file watcher lifecycle
	watcherCtx, watcherCancel := context.WithCancel(context.Background())
	defer watcherCancel()

	// Start file watcher for auto-reload
	if err := startKeyWatcher(server, watcherCtx); err != nil {
		fmt.Printf("⚠️  Warning: Failed to start file watcher: %v\n", err)
		fmt.Println("Keys will not auto-reload when filesystem changes")
	}

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start server in a goroutine
	serverErr := make(chan error, 1)
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	// Wait for shutdown signal or server error
	select {
	case <-sigChan:
		fmt.Println("\n\n[*] Shutdown signal received, cleaning up...")
	case err := <-serverErr:
		fmt.Printf("\n[X] Server error: %v\n", err)
	}

	// Graceful shutdown with 5 second timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	// Shutdown IPC server if it was started
	if server.ipcServer != nil {
		fmt.Println("[*] Shutting down IPC server...")
		server.ipcServer.Stop()
	}

	// Shutdown SSH server if it was started
	if sshServer != nil {
		fmt.Println("[*] Shutting down SSH server...")
		if sshServerCancel != nil {
			sshServerCancel()
		}
		if err := sshServer.Stop(); err != nil {
			fmt.Printf("Warning: SSH server shutdown error: %v\n", err)
		}
	}

	fmt.Println("[*] Shutting down HTTP server...")
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		fmt.Printf("Warning: Server shutdown error: %v\n", err)
	}

	// Log server stop and close audit log
	if auditLog != nil {
		auditLog.LogServerStop()
		_ = auditLog.Close()
	}

	// Stop session timer
	server.stopSessionTimer()

	// Zero encryption passphrase (use Signer's field, not the startup local which may be stale)
	fmt.Println("[*] Zeroing encryption passphrase...")
	server.passphraseLock.Lock()
	if server.encryptionPassphrase != nil {
		server.encryptionPassphrase.Destroy()
		server.encryptionPassphrase = nil
	}
	server.passphraseLock.Unlock()

	// Zero all cached keys (use Signer's field for same reason)
	fmt.Println("[*] Zeroing cached keys...")
	if server.keySession != nil {
		server.keySession.Destroy()
	}

	fmt.Println("[✓] Shutdown complete")
}

// ensureProviders validates that required providers are registered.
// Uses dynamic registry queries instead of hard-coded provider lists.
func ensureProviders() {
	registered := signing.GetRegisteredFamilies()
	if len(registered) == 0 {
		_, _ = fmt.Fprintf(os.Stderr, "Error: no signing providers registered - check providers.go imports\n")
		os.Exit(1)
	}

	// Verify ed25519 is registered (required for standard Algorand transactions)
	hasEd25519 := false
	for _, kt := range registered {
		if kt == "ed25519" {
			hasEd25519 = true
			break
		}
	}
	if !hasEd25519 {
		_, _ = fmt.Fprintf(os.Stderr, "Error: ed25519 signing provider required but not registered\n")
		os.Exit(1)
	}
}

// printSecurityAudit prints a consolidated security configuration summary
func printSecurityAudit(passphraseTimeout time.Duration, config *util.ServerConfig, ipcPath string, coreDumpsDisabled bool, memoryLocked bool, lockOnDisconnect bool, passphraseSource string) {
	fmt.Println("\n┌────────────────────────────────────────────────────────────┐")
	fmt.Println("│                    Security Configuration                  │")
	fmt.Println("├────────────────────────────────────────────────────────────┤")

	// Passphrase source status
	switch passphraseSource {
	case "passphrase_command":
		fmt.Println("│  Passphrase source: passphrase command (headless)          │")
	case "TEST_PASSPHRASE":
		fmt.Println("│  Passphrase source: env var (testing) [!]                  │")
	default:
		fmt.Println("│  Passphrase source: IPC unlock [OK]                        │")
	}

	// Session timeout status
	if passphraseTimeout == 0 {
		fmt.Println("│  Session timeout:    never [!]                             │")
	} else {
		fmt.Printf("│  Session timeout:    %-36s│\n", passphraseTimeout.String()+" [OK]")
	}

	// Lock on disconnect status
	if lockOnDisconnect {
		fmt.Println("│  Lock on disconnect: yes [OK]                              │")
	} else {
		fmt.Println("│  Lock on disconnect: no [!]                                │")
	}

	// Policy status - single transaction auto-approval
	if config.EffectiveTxnAutoApprove() {
		fmt.Println("│  Txn auto-approve:  ALL [!]                                │")
	} else {
		fmt.Println("│  Txn auto-approve:  disabled [OK]                          │")
	}

	// Policy status - group auto-approval
	if config.GroupAutoApprove {
		fmt.Println("│  Group auto-approve: ALL [!]                               │")
	} else {
		fmt.Println("│  Group auto-approve: disabled [OK]                         │")
	}

	// Validation transactions are always auto-approved (0 ALGO self-send)
	fmt.Println("│  Validate txns:     always auto-approve                     │")

	// IPC path status
	ipcWarning := ""
	if strings.HasPrefix(ipcPath, "/tmp") || strings.HasPrefix(ipcPath, "/var/tmp") {
		ipcWarning = " [!]"
	}
	// 60-char content width: 21 prefix + 38 path + 1 space = 60
	displayPath := ipcPath
	if ipcWarning != "" {
		// With warning: 21 prefix + 34 path + 4 warning + 1 space = 60
		if len(displayPath) > 34 {
			displayPath = "..." + displayPath[len(displayPath)-31:]
		}
		fmt.Printf("│  IPC path:          %-34s%s │\n", displayPath, ipcWarning)
	} else {
		if len(displayPath) > 38 {
			displayPath = "..." + displayPath[len(displayPath)-35:]
		}
		fmt.Printf("│  IPC path:          %-38s │\n", displayPath)
	}

	// Memory protection status
	if coreDumpsDisabled {
		fmt.Println("│  Core dumps:        disabled [OK]                          │")
	} else {
		fmt.Println("│  Core dumps:        enabled [!]                            │")
	}
	if memoryLocked {
		fmt.Println("│  Memory locked:     yes [OK]                               │")
	} else {
		fmt.Println("│  Memory locked:     no [!]                                 │")
	}

	fmt.Println("└────────────────────────────────────────────────────────────┘")
}

// printInteractiveModeWarnings prints warnings for unusual configs in interactive mode.
// These are not errors, just alerts that the user may have misconfigured something.
func printInteractiveModeWarnings(config *util.ServerConfig) {
	var warnings []string

	// Warn if txn_auto_approve is enabled - single transactions will be signed without confirmation
	if config.EffectiveTxnAutoApprove() {
		warnings = append(warnings, "txn_auto_approve:true - ALL single transactions will be signed without confirmation")
	}

	// Warn if group_auto_approve is enabled - groups will be signed without confirmation
	if config.GroupAutoApprove {
		warnings = append(warnings, "group_auto_approve:true - ALL transaction groups will be signed without confirmation")
	}

	// Warn if lock_on_disconnect is false - signer stays unlocked after admin leaves
	if config.LockOnDisconnect != nil && !*config.LockOnDisconnect {
		warnings = append(warnings, "lock_on_disconnect:false - signer stays unlocked when apadmin disconnects")
	}

	// Print warnings if any
	if len(warnings) > 0 {
		fmt.Println("\n⚠️  Interactive mode warnings:")
		for _, w := range warnings {
			fmt.Printf("   • %s\n", w)
		}
	}
}

// configureAlgodOnDSAs sets up the algod client on all DSA providers that support it.
// This enables runtime TEAL compilation for composed providers during key import.
func configureAlgodOnDSAs(algodURL, algodToken string) {
	if algodURL == "" {
		return // No algod configured, providers will use precompiled fallback where available
	}

	client, err := algod.MakeClient(algodURL, algodToken)
	if err != nil {
		fmt.Printf("⚠️  Warning: Failed to create algod client for DSA providers: %v\n", err)
		fmt.Println("   Composed providers will fail without algod; pure falcon1024-v1 will use precompiled fallback")
		return
	}

	logicsigdsa.ConfigureAlgodClient(client)
}
