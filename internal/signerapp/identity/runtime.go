// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package identity owns identity-scoped server runtime state.
// Each Runtime is an independent security domain owning keystore,
// session, lock state, and key indexes for a single identity.
package identity

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"bytes"
	"os"
	"path/filepath"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/storepaths"

	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	signerruntime "github.com/aplane-algo/aplane/internal/signerapp/runtime"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"golang.org/x/crypto/ssh"
)

// ErrDecommissioned is returned when an operation is attempted on a decommissioned identity.
var ErrDecommissioned = fmt.Errorf("identity is decommissioned")

// WatcherStartFunc starts a filesystem watcher for the given directories.
// The watcher should call reloadFn when qualifying changes are detected.
// It runs until ctx is cancelled.
type WatcherStartFunc func(dirs []string, ctx context.Context, reloadFn func() error) error

// Runtime owns all sensitive and mutable state for a single identity.
//
// Lock ordering (acquire outer first; nested order is left to right):
//
//	lifecycleMu  ->  passphraseLock
//	lifecycleMu  ->  keysLock
//	lifecycleMu  ->  watcherMu
//	reloadLock() ->  passphraseLock  ->  keysLock
//
// Per-lock scope:
//
//	passphraseLock  guards keySession, reloadFn, and master-key-derivation paths.
//	keysLock        guards the keys/keyTypes/keyLsigSizes maps. keysetRev is
//	                bumped while keysLock is held (and atomically readable).
//	watcherMu       guards watcherCancel, dirty, and the reloadLock callback
//	                pointer. It is never nested with passphraseLock or keysLock;
//	                reloadFromWatcher copies the callback out before releasing
//	                watcherMu.
//	policyMu        guards policyCfg and storedPolicyCfg. Held alone.
//	sshKeysMu       guards sshKeys. Held alone.
//	lifecycleMu     guards the decommission lease. BeginOperation takes RLock
//	                and returns the RUnlock as the release; Decommission takes
//	                the write Lock and so waits for all in-flight leases. It is
//	                the outer lock when Decommission calls Lock and StopKeyWatcher.
//
// Atomics:
//
//	decommissioned  fast-path lifecycle check before lock acquisition.
//	approval        coordinator pointer; swapped without a mutex.
//	keysetRev       last-published key snapshot revision.
//
// reloadLock is supplied by the process root (Signer.storeMutationLocks[id])
// and is the same per-identity mutation lock that admin paths hold while
// mutating keys/templates/config/policy. Watcher-driven reloads acquire it
// themselves; admin paths that already hold it call Reload directly (see
// reloadFromWatcher).
//
// The full process-wide lock table lives in docs/ARCH_SPEC.md, "Lock Hierarchy".
type Runtime struct {
	id          string
	keyStore    *keystore.FileKeyStore
	keyPaths    storepaths.Paths
	lockRuntime *signerruntime.Runtime

	keySession     *keystore.KeySession
	passphraseLock sync.RWMutex

	keys         map[string]string // address -> keyfile path
	keyTypes     map[string]string // address -> key type
	keyLsigSizes map[string]int    // address -> lsig size
	keysetRev    atomic.Uint64     // Process-local revision of the published key snapshot.
	keysLock     sync.RWMutex

	watcherCancel context.CancelFunc
	watcherMu     sync.Mutex
	dirty         bool // Filesystem changes detected while locked; reconcile on next unlock
	reloadLock    func() sync.Locker

	approval        atomic.Pointer[signerapproval.Coordinator]
	authenticator   auth.Authenticator
	identityCfg     *IdentityConfig
	policyMu        sync.RWMutex
	policyCfg       *policy.Config
	storedPolicyCfg *policy.StoredConfig

	// SSH authorized keys for this identity
	sshKeys   []ssh.PublicKey
	sshKeysMu sync.RWMutex

	// reloadFn performs template registration + key scan + snapshot publish.
	// Injected by the process root after construction.
	// The session parameter is the current keySession; callers already hold
	// passphraseLock so the reload function must not re-acquire it.
	reloadFn func(identityID string, passphrase []byte, session *keystore.KeySession) (*signertemplates.ReloadReport, error)

	// Lifecycle state
	lifecycleMu    sync.RWMutex
	decommissioned atomic.Bool // If true, identity is disabled and should not accept new operations

	// onLocked is called after lock cleanup completes (for IPC notification, etc).
	onLocked func()

	// persistDecommission stores lifecycle state so disabled identities stay
	// disabled across restarts.
	persistDecommission func(identityID string) error
}

// KeyIndexSnapshot is a materialized copy of the runtime key index at one
// published revision.
type KeyIndexSnapshot struct {
	Revision  uint64
	KeyFiles  map[string]string
	KeyTypes  map[string]string
	LSigSizes map[string]int
}

// Config is the construction parameters for an identity Runtime.
type Config struct {
	ID                  string
	KeyStore            *keystore.FileKeyStore
	KeyPaths            storepaths.Paths
	Authenticator       auth.Authenticator // Required. Token authority for this identity.
	SessionTimeout      time.Duration
	ApprovalWait        time.Duration
	UserAutoApprove     *bool
	LockOnDisconnect    bool
	Mode                Mode
	OnLocked            func() // Called after lock transition completes.
	PersistDecommission func(identityID string) error
}

// New creates an identity Runtime in the locked state.
// Panics if Authenticator is nil.
func New(cfg Config) *Runtime {
	if cfg.Authenticator == nil {
		panic("identity.New: Authenticator is required")
	}

	session := keystore.NewKeySession(cfg.KeyStore)
	rt := signerruntime.New()
	userAutoApprove := false
	if cfg.UserAutoApprove != nil {
		userAutoApprove = *cfg.UserAutoApprove
	}

	ir := &Runtime{
		id:                  cfg.ID,
		keyStore:            cfg.KeyStore,
		keyPaths:            cfg.KeyPaths,
		lockRuntime:         rt,
		keySession:          session,
		authenticator:       cfg.Authenticator,
		identityCfg:         NewIdentityConfig(userAutoApprove, cfg.LockOnDisconnect, cfg.SessionTimeout, cfg.ApprovalWait, cfg.Mode),
		keys:                make(map[string]string),
		keyTypes:            make(map[string]string),
		keyLsigSizes:        make(map[string]int),
		onLocked:            cfg.OnLocked,
		persistDecommission: cfg.PersistDecommission,
	}

	rt.SetOnLock(ir.performLock)
	return ir
}

// SetReloadFunc sets the function used to reload keys and templates.
// Safe for concurrent use; the function is stored under passphraseLock.
// The function receives the keySession directly because callers of
// reloadLocked already hold passphraseLock; the function must not
// re-acquire it.
func (ir *Runtime) SetReloadFunc(fn func(identityID string, passphrase []byte, session *keystore.KeySession) (*signertemplates.ReloadReport, error)) {
	ir.passphraseLock.Lock()
	ir.reloadFn = fn
	ir.passphraseLock.Unlock()
}

// SetReloadMutationLock sets the identity-scoped lock watcher-triggered reloads
// acquire before scanning disk. Admin mutations that already hold this lock call
// Reload directly and must not re-enter it.
func (ir *Runtime) SetReloadMutationLock(fn func() sync.Locker) {
	ir.watcherMu.Lock()
	ir.reloadLock = fn
	ir.watcherMu.Unlock()
}

// --- Identity ---

// ID returns the identity ID this runtime belongs to.
func (ir *Runtime) ID() string {
	return ir.id
}

// Policy returns a copy of the effective policy for this identity.
func (ir *Runtime) Policy() *policy.Config {
	ir.policyMu.RLock()
	defer ir.policyMu.RUnlock()
	if ir.policyCfg == nil {
		return nil
	}
	return ir.policyCfg.Clone()
}

// StoredPolicy returns a copy of the stored policy snapshot that produced the
// currently active effective policy, if one is available.
func (ir *Runtime) StoredPolicy() *policy.StoredConfig {
	ir.policyMu.RLock()
	defer ir.policyMu.RUnlock()
	if ir.storedPolicyCfg == nil {
		return nil
	}
	return ir.storedPolicyCfg.Clone()
}

// PolicySnapshot returns copies of the active stored and effective policy
// state. The stored snapshot can be nil when the effective policy was injected
// by tests or compatibility code instead of loaded from policy.yaml.
func (ir *Runtime) PolicySnapshot() (*policy.StoredConfig, *policy.Config) {
	ir.policyMu.RLock()
	defer ir.policyMu.RUnlock()
	var stored *policy.StoredConfig
	if ir.storedPolicyCfg != nil {
		stored = ir.storedPolicyCfg.Clone()
	}
	var effective *policy.Config
	if ir.policyCfg != nil {
		effective = ir.policyCfg.Clone()
	}
	return stored, effective
}

// SetPolicy installs the effective policy for this identity.
func (ir *Runtime) SetPolicy(cfg *policy.Config) {
	ir.SetPolicyState(nil, cfg)
}

// SetPolicyState installs the stored policy snapshot and the effective policy
// for this identity as one atomic runtime update.
func (ir *Runtime) SetPolicyState(stored *policy.StoredConfig, cfg *policy.Config) {
	ir.policyMu.Lock()
	defer ir.policyMu.Unlock()
	if cfg == nil {
		ir.storedPolicyCfg = nil
		ir.policyCfg = nil
		return
	}
	if stored == nil {
		ir.storedPolicyCfg = nil
	} else {
		ir.storedPolicyCfg = stored.Clone()
	}
	ir.policyCfg = cfg.Clone()
}

// --- Lock state ---

// GetState returns the current lock state.
func (ir *Runtime) GetState() signerruntime.SignerState {
	return ir.lockRuntime.GetState()
}

// IsUnlocked reports whether this identity is currently unlocked.
func (ir *Runtime) IsUnlocked() bool {
	return ir.lockRuntime.IsUnlocked()
}

// SetUnlocked marks this identity as unlocked without side effects.
func (ir *Runtime) SetUnlocked() {
	ir.lockRuntime.SetUnlocked()
}

// Lock transitions this identity to the locked state.
func (ir *Runtime) Lock() {
	ir.lockRuntime.Lock()
}

// TryUnlock attempts to unlock with the given passphrase.
// Returns (success, keyCount, errorMessage).
// The passphrase bytes are NOT zeroed by this function.
// Fails if the identity has been decommissioned.
func (ir *Runtime) TryUnlock(passphrase []byte, onUnlocked func()) (bool, int, string) {
	if ir.decommissioned.Load() {
		return false, 0, ErrDecommissioned.Error()
	}
	return ir.lockRuntime.TryUnlock(ir.performUnlock(passphrase), onUnlocked)
}

// --- Approval ---

// SetApprovalCoordinator installs the approval coordinator for this identity.
// Safe for concurrent use; the coordinator is stored atomically.
func (ir *Runtime) SetApprovalCoordinator(c *signerapproval.Coordinator) {
	ir.approval.Store(c)
}

// Approval returns the approval coordinator, or nil if not set.
func (ir *Runtime) Approval() *signerapproval.Coordinator {
	return ir.approval.Load()
}

// PendingSignCount returns the number of pending sign approval requests.
func (ir *Runtime) PendingSignCount() int {
	c := ir.approval.Load()
	if c == nil {
		return 0
	}
	return c.PendingSignCount()
}

// HandleSignApprovalResponse routes a sign approval response to the coordinator.
func (ir *Runtime) HandleSignApprovalResponse(msg *signerapproval.SignResponse) {
	if c := ir.approval.Load(); c != nil {
		c.HandleSignResponse(msg)
	}
}

// BeginSigningRequest tracks a live signer request until the returned cleanup
// function is called.
func (ir *Runtime) BeginSigningRequest(ctx context.Context, requestID string) (context.Context, func()) {
	c := ir.approval.Load()
	if c == nil {
		if ctx == nil {
			ctx = context.Background()
		}
		return ctx, func() {}
	}
	return c.BeginSignRequest(ctx, requestID)
}

// CancelSigningApproval cancels one pending signing approval request.
func (ir *Runtime) CancelSigningApproval(requestID, reason string) signerapproval.SignRequestCancelResult {
	if c := ir.approval.Load(); c != nil {
		return c.CancelSignRequest(requestID, reason)
	}
	return signerapproval.SignRequestCancelResult{State: signerapproval.SignRequestCancelStateNotFound}
}

// RequestSigningApproval requests operator approval for a signing operation.
func (ir *Runtime) RequestSigningApproval(requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (bool, error) {
	response, err := ir.RequestSigningApprovalResponseContext(context.Background(), requestID, address, txnSender, description, firstValid, lastValid, violations, timeout)
	if err != nil {
		return false, err
	}
	return response.Approved, nil
}

func (ir *Runtime) RequestSigningApprovalResponse(requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (signerapproval.SignResponse, error) {
	return ir.RequestSigningApprovalResponseContext(context.Background(), requestID, address, txnSender, description, firstValid, lastValid, violations, timeout)
}

func (ir *Runtime) RequestSigningApprovalContext(ctx context.Context, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (bool, error) {
	response, err := ir.RequestSigningApprovalResponseContext(ctx, requestID, address, txnSender, description, firstValid, lastValid, violations, timeout)
	if err != nil {
		return false, err
	}
	return response.Approved, nil
}

func (ir *Runtime) RequestSigningApprovalResponseContext(ctx context.Context, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (signerapproval.SignResponse, error) {
	if ir.decommissioned.Load() {
		return signerapproval.SignResponse{}, ErrDecommissioned
	}
	c := ir.approval.Load()
	if c == nil {
		return signerapproval.SignResponse{}, fmt.Errorf("approval coordinator not initialized")
	}
	return c.RequestSigningApprovalResponseContext(ctx, requestID, address, txnSender, description, firstValid, lastValid, violations, timeout)
}

// FailAllPendingApprovals fails all pending approval requests with the given reason.
func (ir *Runtime) FailAllPendingApprovals(reason string) {
	if c := ir.approval.Load(); c != nil {
		c.FailAllPendingRequests(reason)
	}
}

// HandleTokenProvisioningApprovalResponse routes a token provisioning response.
func (ir *Runtime) HandleTokenProvisioningApprovalResponse(msg *signerapproval.TokenProvisioningResponse) {
	if c := ir.approval.Load(); c != nil {
		c.HandleTokenProvisioningResponse(msg)
	}
}

// RequestTokenProvisioning requests operator approval for token provisioning.
func (ir *Runtime) RequestTokenProvisioning(requestID, identityID, sshFingerprint, remoteAddr string, timeout time.Duration) (bool, error) {
	return ir.RequestTokenProvisioningContext(context.Background(), requestID, identityID, sshFingerprint, remoteAddr, timeout)
}

func (ir *Runtime) RequestTokenProvisioningContext(ctx context.Context, requestID, identityID, sshFingerprint, remoteAddr string, timeout time.Duration) (bool, error) {
	if ir.decommissioned.Load() {
		return false, ErrDecommissioned
	}
	c := ir.approval.Load()
	if c == nil {
		return false, fmt.Errorf("approval coordinator not initialized")
	}
	return c.RequestTokenProvisioningContext(ctx, requestID, identityID, sshFingerprint, remoteAddr, timeout)
}

// --- Lifecycle ---

// IsDecommissioned returns whether this identity has been decommissioned.
// A decommissioned identity should not accept new operations.
func (ir *Runtime) IsDecommissioned() bool {
	return ir.decommissioned.Load()
}

// BeginOperation acquires a runtime activity lease for a caller that is about
// to perform non-interruptible identity work, such as final signing. If
// decommission wins the race first, BeginOperation fails. If the caller wins,
// Decommission waits for the returned release function before completing.
func (ir *Runtime) BeginOperation() (func(), error) {
	ir.lifecycleMu.RLock()
	if ir.decommissioned.Load() {
		ir.lifecycleMu.RUnlock()
		return nil, ErrDecommissioned
	}
	return ir.lifecycleMu.RUnlock, nil
}

// Decommission marks the identity as disabled. Locks the identity if unlocked,
// stops the watcher, and prevents future unlock attempts.
// Does not delete any data — decommissioning is logical, not physical.
// If persisting decommission state fails, the runtime remains active and
// pending approvals are left untouched.
func (ir *Runtime) Decommission() error {
	ir.lifecycleMu.Lock()
	defer ir.lifecycleMu.Unlock()

	if ir.decommissioned.Load() {
		return nil
	}
	if ir.persistDecommission != nil {
		if err := ir.persistDecommission(ir.id); err != nil {
			return err
		}
	}
	ir.decommissioned.Store(true)
	ir.FailAllPendingApprovals("identity decommissioned")
	if ir.IsUnlocked() {
		ir.Lock()
	}
	ir.StopKeyWatcher()
	return nil
}

// --- Identity config ---

// Config returns the identity-scoped configuration.
func (ir *Runtime) Config() *IdentityConfig {
	return ir.identityCfg
}

// --- Token authority ---

// Authenticator returns the authenticator for this identity.
func (ir *Runtime) Authenticator() auth.Authenticator {
	return ir.authenticator
}

// --- SSH authorized keys ---

// AuthorizedKeysPath returns the path to this identity's authorized_keys file.
func (ir *Runtime) AuthorizedKeysPath() string {
	return filepath.Join(ir.keyPaths.Root(), "identities", ir.id, ".ssh", "authorized_keys")
}

// LoadAuthorizedKeys loads SSH public keys from this identity's authorized_keys file.
func (ir *Runtime) LoadAuthorizedKeys() error {
	path := ir.AuthorizedKeysPath()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		// No file yet — TOFU mode
		ir.sshKeysMu.Lock()
		ir.sshKeys = nil
		ir.sshKeysMu.Unlock()
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to read authorized keys: %w", err)
	}

	var keys []ssh.PublicKey
	rest := data
	for len(rest) > 0 {
		key, _, _, r, parseErr := ssh.ParseAuthorizedKey(rest)
		if parseErr != nil {
			return fmt.Errorf("failed to parse authorized keys: %w", parseErr)
		}
		keys = append(keys, key)
		rest = r
	}

	ir.sshKeysMu.Lock()
	ir.sshKeys = keys
	ir.sshKeysMu.Unlock()
	return nil
}

// HasAuthorizedKey checks whether the given SSH public key is authorized for this identity.
func (ir *Runtime) HasAuthorizedKey(key ssh.PublicKey) bool {
	ir.sshKeysMu.RLock()
	defer ir.sshKeysMu.RUnlock()
	keyBytes := key.Marshal()
	for _, allowed := range ir.sshKeys {
		if bytes.Equal(allowed.Marshal(), keyBytes) {
			return true
		}
	}
	return false
}

// EnrollAuthorizedKey adds a public key to this identity's authorized_keys file.
// Idempotent — skips if the key is already enrolled.
func (ir *Runtime) EnrollAuthorizedKey(key ssh.PublicKey) error {
	ir.sshKeysMu.Lock()
	defer ir.sshKeysMu.Unlock()

	// Check for duplicate
	keyBytes := key.Marshal()
	for _, existing := range ir.sshKeys {
		if bytes.Equal(existing.Marshal(), keyBytes) {
			return nil // Already enrolled
		}
	}

	// Write to file
	keyLine := string(ssh.MarshalAuthorizedKey(key))
	path := ir.AuthorizedKeysPath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open authorized_keys: %w", err)
	}
	if _, err := f.WriteString(keyLine); err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to write key: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close authorized_keys: %w", err)
	}

	ir.sshKeys = append(ir.sshKeys, key)
	return nil
}

// --- Key access ---

// KnownAddresses returns a set of addresses this identity holds keys for.
func (ir *Runtime) KnownAddresses() map[string]bool {
	ir.keysLock.RLock()
	defer ir.keysLock.RUnlock()
	addrs := make(map[string]bool, len(ir.keys))
	for addr := range ir.keys {
		addrs[addr] = true
	}
	return addrs
}

// FindKeyFile returns the key file path for the given address.
func (ir *Runtime) FindKeyFile(address string) (string, error) {
	ir.keysLock.RLock()
	keyFile, exists := ir.keys[address]
	ir.keysLock.RUnlock()
	if !exists {
		return "", fmt.Errorf("no key found for address: %s", address)
	}
	return keyFile, nil
}

// KeyCount returns the number of keys currently loaded.
func (ir *Runtime) KeyCount() int {
	ir.keysLock.RLock()
	defer ir.keysLock.RUnlock()
	return len(ir.keys)
}

// KeysetRevision returns the process-local revision of the published key snapshot.
// The value starts at zero on process start and increments after each successful
// snapshot publish.
func (ir *Runtime) KeysetRevision() uint64 {
	return ir.keysetRev.Load()
}

// KeyIndexSnapshot returns copies of the key maps from one published revision.
// Safe for concurrent use. Returns zero values if the identity is decommissioned.
func (ir *Runtime) KeyIndexSnapshot() KeyIndexSnapshot {
	if ir.decommissioned.Load() {
		return KeyIndexSnapshot{}
	}
	ir.keysLock.RLock()
	defer ir.keysLock.RUnlock()

	snapshot := KeyIndexSnapshot{
		Revision:  ir.keysetRev.Load(),
		KeyFiles:  make(map[string]string, len(ir.keys)),
		KeyTypes:  make(map[string]string, len(ir.keyTypes)),
		LSigSizes: make(map[string]int, len(ir.keyLsigSizes)),
	}
	for k, v := range ir.keys {
		snapshot.KeyFiles[k] = v
	}
	for k, v := range ir.keyTypes {
		snapshot.KeyTypes[k] = v
	}
	for k, v := range ir.keyLsigSizes {
		snapshot.LSigSizes[k] = v
	}
	return snapshot
}

// KeySnapshot returns copies of the key maps. Safe for concurrent use.
// Returns empty maps if the identity is decommissioned.
func (ir *Runtime) KeySnapshot() (keys, keyTypes map[string]string, lsigSizes map[string]int) {
	snapshot := ir.KeyIndexSnapshot()
	return snapshot.KeyFiles, snapshot.KeyTypes, snapshot.LSigSizes
}

// PublishSnapshot replaces the key maps with new data from a reload.
func (ir *Runtime) PublishSnapshot(keys, keyTypes map[string]string, lsigSizes map[string]int) {
	if ir.decommissioned.Load() {
		return
	}
	ir.keysLock.Lock()
	ir.keys = keys
	ir.keyTypes = keyTypes
	ir.keyLsigSizes = lsigSizes
	ir.keysetRev.Add(1)
	ir.keysLock.Unlock()
}

// --- KeyStore access ---

// KeyStore returns the underlying file key store.
func (ir *Runtime) KeyStore() *keystore.FileKeyStore {
	return ir.keyStore
}

// KeyPaths returns the keystore path configuration.
func (ir *Runtime) KeyPaths() storepaths.Paths {
	return ir.keyPaths
}

// WithMasterKey runs fn with the cached master key.
// Returns ErrDecommissioned if the identity has been decommissioned.
func (ir *Runtime) WithMasterKey(fn func([]byte) error) error {
	if ir.decommissioned.Load() {
		return ErrDecommissioned
	}
	return ir.keyStore.WithMasterKey(fn)
}

// SnapshotKeySession returns the current key session under the passphrase lock.
// Returns nil if the identity is decommissioned.
func (ir *Runtime) SnapshotKeySession() *keystore.KeySession {
	if ir.decommissioned.Load() {
		return nil
	}
	ir.passphraseLock.RLock()
	session := ir.keySession
	ir.passphraseLock.RUnlock()
	return session
}

// --- Reload ---

// Reload rescans keys using the cached master key (no passphrase needed).
// Admin mutation paths call this directly while holding the identity mutation lock;
// watcher paths must use reloadFromWatcher so they acquire that lock themselves.
func (ir *Runtime) Reload() (*signertemplates.ReloadReport, error) {
	if ir.decommissioned.Load() {
		return nil, ErrDecommissioned
	}
	ir.passphraseLock.RLock()
	defer ir.passphraseLock.RUnlock()
	return ir.reloadLocked(nil)
}

// ReloadWithPassphrase initializes the master key from passphrase and scans keys.
// Caller must NOT hold passphraseLock.
func (ir *Runtime) ReloadWithPassphrase(passphrase []byte) (*signertemplates.ReloadReport, error) {
	if ir.decommissioned.Load() {
		return nil, ErrDecommissioned
	}
	ir.passphraseLock.Lock()
	defer ir.passphraseLock.Unlock()
	return ir.reloadLocked(passphrase)
}

func (ir *Runtime) reloadLocked(passphrase []byte) (*signertemplates.ReloadReport, error) {
	if ir.reloadFn == nil {
		return nil, fmt.Errorf("reload function not configured")
	}
	// Pass keySession directly — caller holds passphraseLock.
	return ir.reloadFn(ir.id, passphrase, ir.keySession)
}

// --- Watcher ---

// EnsureKeyWatcher starts the file watcher if not already running.
// Watches the keys directory and key type state/template records.
// The watcher stays running across lock/unlock transitions: when unlocked
// it reloads immediately; when locked it marks the identity dirty for
// reconciliation on the next unlock.
// If the identity was marked dirty while locked, triggers an immediate reload.
func (ir *Runtime) EnsureKeyWatcher(startFn WatcherStartFunc) {
	if ir.decommissioned.Load() {
		return
	}
	ir.watcherMu.Lock()
	wasDirty := ir.dirty
	ir.dirty = false
	alreadyRunning := ir.watcherCancel != nil
	ir.watcherMu.Unlock()

	// Reconcile any changes that accumulated while locked
	if wasDirty {
		ir.reconcileDirty()
	}

	if alreadyRunning {
		return
	}

	// Watch keys dir and key type state/template records.
	// The identity dir catches creation of intermediate directories so the
	// watcher can dynamically add them.
	dirs := []string{
		ir.keyPaths.IdentityDir(ir.id),
		ir.keyPaths.KeysDir(ir.id),
		ir.keyPaths.KeyTypeRecordsDir(ir.id),
	}

	// The reload callback either reloads (if unlocked) or marks dirty (if locked)
	reloadOrDirty := func() error {
		if ir.IsUnlocked() {
			_, err := ir.reloadFromWatcher()
			return err
		}
		ir.MarkDirty()
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	if err := startFn(dirs, ctx, reloadOrDirty); err != nil {
		cancel()
		fmt.Printf("⚠️  Warning: Failed to start file watcher: %v\n", err)
		fmt.Println("Keys will not auto-reload when filesystem changes")
		return
	}

	ir.watcherMu.Lock()
	ir.watcherCancel = cancel
	ir.watcherMu.Unlock()
}

// MarkDirty records that filesystem changes were detected while locked.
// The identity will reconcile (reload) on the next unlock.
func (ir *Runtime) MarkDirty() {
	ir.watcherMu.Lock()
	ir.dirty = true
	ir.watcherMu.Unlock()
}

func (ir *Runtime) reconcileDirty() {
	if _, err := ir.reloadFromWatcher(); err != nil {
		fmt.Printf("⚠️  Dirty-state reconciliation failed for identity %s: %v\n", ir.id, err)
	} else {
		fmt.Printf("✓ Reconciled pending filesystem changes for identity %s\n", ir.id)
	}
}

func (ir *Runtime) reloadFromWatcher() (*signertemplates.ReloadReport, error) {
	ir.watcherMu.Lock()
	lockFn := ir.reloadLock
	ir.watcherMu.Unlock()
	if lockFn == nil {
		return ir.Reload()
	}
	lock := lockFn()
	if lock == nil {
		return ir.Reload()
	}
	lock.Lock()
	defer lock.Unlock()
	return ir.Reload()
}

// StopKeyWatcher stops the file watcher if running.
func (ir *Runtime) StopKeyWatcher() {
	ir.watcherMu.Lock()
	defer ir.watcherMu.Unlock()

	if ir.watcherCancel != nil {
		ir.watcherCancel()
		ir.watcherCancel = nil
	}
}

// --- Shutdown ---

// Destroy cleans up the identity runtime for shutdown.
// Blocks until in-flight key operations complete.
func (ir *Runtime) Destroy() {
	ir.StopKeyWatcher()
	if ir.keySession != nil {
		ir.keySession.Destroy()
	}
	if ir.keyStore != nil {
		ir.keyStore.ClearMasterKey()
	}
}

// --- Internal ---

func (ir *Runtime) performLock() {
	// Watcher stays running — it will mark dirty instead of reloading while locked.
	// StopKeyWatcher is only called on shutdown via Destroy().

	ir.passphraseLock.Lock()
	if ir.keySession != nil {
		ir.keySession.Destroy()
		if ir.keyStore != nil {
			ir.keySession = keystore.NewKeySession(ir.keyStore)
		} else {
			ir.keySession = nil
		}
	}
	if ir.keyStore != nil {
		ir.keyStore.ClearMasterKey()
	}
	ir.passphraseLock.Unlock()

	ir.keysLock.Lock()
	ir.keys = make(map[string]string)
	ir.keyTypes = make(map[string]string)
	ir.keyLsigSizes = make(map[string]int)
	ir.keysetRev.Add(1)
	ir.keysLock.Unlock()

	fmt.Println("🔒 Signer locked - sensitive data cleared from memory")

	if ir.onLocked != nil {
		ir.onLocked()
	}
}

func (ir *Runtime) performUnlock(passphrase []byte) func() (int, error) {
	return func() (int, error) {
		if err := crypto.VerifyPassphraseWithMetadata(passphrase, ir.keyPaths.KeystoreMetadataDir(ir.id)); err != nil {
			return 0, fmt.Errorf("invalid passphrase")
		}

		if _, err := ir.ReloadWithPassphrase(passphrase); err != nil {
			return 0, fmt.Errorf("failed to load keys: %v", err)
		}

		keyCount := ir.KeyCount()
		fmt.Printf("🔓 Signer unlocked (%d keys loaded)\n", keyCount)
		return keyCount, nil
	}
}
