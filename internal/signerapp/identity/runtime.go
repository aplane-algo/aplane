// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package identity owns identity-scoped server runtime state.
// Each Runtime is an independent security domain owning keystore,
// session, lock state, and key indexes for a single identity.
package identity

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/storepaths"

	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	signerruntime "github.com/aplane-algo/aplane/internal/signerapp/runtime"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"golang.org/x/crypto/ssh"
)

// WatcherStartFunc starts a filesystem watcher for the given directories.
// The watcher should call reloadFn when qualifying changes are detected.
// It runs until ctx is cancelled.
type WatcherStartFunc func(dirs []string, ctx context.Context, reloadFn func() error) error

// Runtime owns all sensitive and mutable state for a single identity.
//
// Lock ordering (acquire outer first; nested order is left to right):
//
//	reloadLock() ->  passphraseLock  ->  keysLock
//	reloadLock() ->  lsigprovider.registerMu
//
// Per-lock scope:
//
//	passphraseLock  guards keySession, reloadFn, and keyring-unlock paths.
//	keysLock        guards the keys/keyTypes/keyMetadata maps. keysetRev is
//	                bumped while keysLock is held (and atomically readable).
//	watcherMu       guards watcherCancel, dirty, and the reloadLock callback
//	                pointer. It is never nested with passphraseLock or keysLock;
//	                reloadFromWatcher copies the callback out before releasing
//	                watcherMu.
//	policyMu        guards policyCfg/storedPolicyCfg and
//	                sentryPolicyCfg/storedSentryPolicyCfg. Held alone.
//	sshKeysMu       guards sshKeys. Held alone.
//
// Atomics:
//
//	approval        coordinator pointer; swapped without a mutex.
//	keysetRev       last-published key snapshot revision.
//
// reloadLock is supplied by the process root (Signer.storeMutationLock)
// and is the same process-wide mutation lock that admin paths hold while
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

	keys        map[string]string // address -> keyfile path
	keyTypes    map[string]string // address -> key type
	keyMetadata map[string]KeyPublicMetadata
	keysetRev   atomic.Uint64 // Process-local revision of the published key snapshot.
	keysLock    sync.RWMutex

	watcherCancel   context.CancelFunc
	watcherMu       sync.Mutex
	watcherStarting bool // A watcher start is in flight; prevents duplicate starts
	dirty           bool // Filesystem changes detected while locked; reconcile on next unlock
	reloadLock      func() sync.Locker

	approval              atomic.Pointer[signerapproval.Coordinator]
	authenticator         auth.Authenticator
	identityCfg           *IdentityConfig
	nodeRole              noderole.Role
	policyMu              sync.RWMutex
	policyCfg             *policy.Config
	storedPolicyCfg       *policy.StoredConfig
	sentryPolicyCfg       *policy.Config
	storedSentryPolicyCfg *policy.StoredConfig

	// SSH authorized keys for this identity
	sshKeys   []ssh.PublicKey
	sshKeysMu sync.RWMutex

	// reloadFn performs template registration + key scan + snapshot publish.
	// Injected by the process root after construction.
	// The session parameter is the current keySession; callers already hold
	// passphraseLock so the reload function must not re-acquire it.
	reloadFn func(passphrase []byte, session *keystore.KeySession) (*signertemplates.ReloadReport, error)

	// onLocked is called after lock cleanup completes (for IPC notification, etc).
	onLocked func()
}

// StoreMaintenanceToken is an opaque authorization to republish an identity
// after a store-wide mutation has cleared its runtime signing state.
type StoreMaintenanceToken struct {
	runtime signerruntime.MaintenanceToken
}

// KeyIndexSnapshot is a materialized copy of the runtime key index at one
// published revision.
type KeyIndexSnapshot struct {
	Revision    uint64
	KeyFiles    map[string]string
	KeyTypes    map[string]string
	KeyMetadata map[string]KeyPublicMetadata
}

// KeyPublicMetadata is the non-secret portion of a scanned key published with
// the runtime key index at one revision.
type KeyPublicMetadata struct {
	Category             string
	PublicKeyHex         string
	Parameters           map[string]string
	BoundedAuthorization *boundedmeta.Metadata
	LogicSigResources    *lsigresource.Profile
}

// Config is the construction parameters for an identity Runtime.
type Config struct {
	ID               string
	KeyStore         *keystore.FileKeyStore
	KeyPaths         storepaths.Paths
	Authenticator    auth.Authenticator // Required. Token authority for this identity.
	SessionTimeout   time.Duration
	ApprovalWait     time.Duration
	UserAutoApprove  *bool
	LockOnDisconnect bool
	NodeRole         noderole.Role
	OnLocked         func() // Called after lock transition completes.
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
	nodeRole := cfg.NodeRole
	if nodeRole == "" {
		nodeRole = noderole.DefaultRole()
	}

	ir := &Runtime{
		id:            cfg.ID,
		keyStore:      cfg.KeyStore,
		keyPaths:      cfg.KeyPaths,
		lockRuntime:   rt,
		keySession:    session,
		authenticator: cfg.Authenticator,
		identityCfg:   NewIdentityConfig(userAutoApprove, cfg.LockOnDisconnect, cfg.SessionTimeout, cfg.ApprovalWait),
		nodeRole:      nodeRole,
		keys:          make(map[string]string),
		keyTypes:      make(map[string]string),
		keyMetadata:   make(map[string]KeyPublicMetadata),
		onLocked:      cfg.OnLocked,
	}

	rt.SetOnLock(ir.performLockCleanup)
	return ir
}

// SetReloadFunc sets the function used to reload keys and templates.
// Safe for concurrent use; the function is stored under passphraseLock.
// The function receives the keySession directly because callers of
// reloadLocked already hold passphraseLock; the function must not
// re-acquire it.
func (ir *Runtime) SetReloadFunc(fn func(passphrase []byte, session *keystore.KeySession) (*signertemplates.ReloadReport, error)) {
	ir.passphraseLock.Lock()
	ir.reloadFn = fn
	ir.passphraseLock.Unlock()
}

// SetReloadMutationLock sets the process-wide lock watcher-triggered reloads
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

// NodeRole returns the immutable role declared by the signer data root.
func (ir *Runtime) NodeRole() noderole.Role {
	return ir.nodeRole
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

// SentryPolicy returns a copy of the effective sentry component policy
// for this identity.
func (ir *Runtime) SentryPolicy() *policy.Config {
	ir.policyMu.RLock()
	defer ir.policyMu.RUnlock()
	if ir.sentryPolicyCfg == nil {
		return nil
	}
	return ir.sentryPolicyCfg.Clone()
}

// StoredSentryPolicy returns a copy of the stored sentry policy snapshot
// that produced the currently active effective sentry policy, if one is
// available.
func (ir *Runtime) StoredSentryPolicy() *policy.StoredConfig {
	ir.policyMu.RLock()
	defer ir.policyMu.RUnlock()
	if ir.storedSentryPolicyCfg == nil {
		return nil
	}
	return ir.storedSentryPolicyCfg.Clone()
}

// SentryPolicySnapshot returns copies of the active stored and effective
// sentry policy state.
func (ir *Runtime) SentryPolicySnapshot() (*policy.StoredConfig, *policy.Config) {
	ir.policyMu.RLock()
	defer ir.policyMu.RUnlock()
	var stored *policy.StoredConfig
	if ir.storedSentryPolicyCfg != nil {
		stored = ir.storedSentryPolicyCfg.Clone()
	}
	var effective *policy.Config
	if ir.sentryPolicyCfg != nil {
		effective = ir.sentryPolicyCfg.Clone()
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

// SetSentryPolicy installs the effective sentry policy for this
// identity.
func (ir *Runtime) SetSentryPolicy(cfg *policy.Config) {
	ir.SetSentryPolicyState(nil, cfg)
}

// SetSentryPolicyState installs the stored sentry policy snapshot and
// the effective sentry policy for this identity as one atomic runtime
// update.
func (ir *Runtime) SetSentryPolicyState(stored *policy.StoredConfig, cfg *policy.Config) {
	ir.policyMu.Lock()
	defer ir.policyMu.Unlock()
	if cfg == nil {
		ir.storedSentryPolicyCfg = nil
		ir.sentryPolicyCfg = nil
		return
	}
	if stored == nil {
		ir.storedSentryPolicyCfg = nil
	} else {
		ir.storedSentryPolicyCfg = stored.Clone()
	}
	ir.sentryPolicyCfg = cfg.Clone()
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

// IsRecovery reports that the keyring is available only for explicit
// activation reconciliation; signing remains locked.
func (ir *Runtime) IsRecovery() bool {
	return ir.lockRuntime.IsRecovery()
}

// PromoteRecoveryToUnlocked atomically transitions recovery -> unlocked,
// refusing if a racing lock already left recovery (the lock wins).
func (ir *Runtime) PromoteRecoveryToUnlocked() bool {
	return ir.lockRuntime.PromoteRecoveryToUnlocked()
}

// SetUnlocked marks this identity as unlocked without side effects.
func (ir *Runtime) SetUnlocked() {
	ir.lockRuntime.SetUnlocked()
}

// SetRecovery marks this identity as recovery-blocked without permitting
// signing. Production unlock paths should use TryRecoveryUnlock.
func (ir *Runtime) SetRecovery() {
	ir.lockRuntime.SetRecovery()
}

// TryRecoveryUnlock opens the keyring without scanning or publishing
// active credentials, then enters recovery state.
func (ir *Runtime) TryRecoveryUnlock(passphrase []byte) (bool, string) {
	return ir.lockRuntime.TryRecovery(func() error {
		ir.passphraseLock.Lock()
		defer ir.passphraseLock.Unlock()
		if err := ir.keyStore.Unlock(passphrase); err != nil {
			return fmt.Errorf("invalid passphrase")
		}
		return nil
	})
}

// Lock transitions this identity to the locked state.
func (ir *Runtime) Lock() {
	if ir.lockRuntime.Lock() {
		ir.notifyLocked()
	}
}

// BeginStoreMaintenance blocks signing and clears sensitive runtime state
// without broadcasting a user-visible lock transition. The caller must pair
// it with FinishStoreMaintenance.
func (ir *Runtime) BeginStoreMaintenance() StoreMaintenanceToken {
	return StoreMaintenanceToken{runtime: ir.lockRuntime.BeginMaintenance()}
}

// FinishStoreMaintenance republishes the identity only after the caller has
// rebuilt it from a settled store. Failure, or a racing explicit Lock, leaves
// the identity locked and broadcasts that final state.
func (ir *Runtime) FinishStoreMaintenance(
	token StoreMaintenanceToken,
	republish bool,
) bool {
	if ir.lockRuntime.FinishMaintenance(token.runtime, republish) {
		return true
	}
	ir.notifyLocked()
	return false
}

// TryUnlock attempts to unlock with the given passphrase.
// Returns (success, keyCount, errorMessage).
// The passphrase bytes are NOT zeroed by this function.
func (ir *Runtime) TryUnlock(passphrase []byte, onUnlocked func()) (bool, int, string) {
	ok, keyCount, errMsg := ir.lockRuntime.TryUnlock(ir.performUnlock(passphrase), onUnlocked)
	if !ok && errMsg == signerruntime.LockedDuringUnlockMessage {
		ir.notifyLocked()
	}
	return ok, keyCount, errMsg
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
	c := ir.approval.Load()
	if c == nil {
		return false, fmt.Errorf("approval coordinator not initialized")
	}
	return c.RequestTokenProvisioningContext(ctx, requestID, identityID, sshFingerprint, remoteAddr, timeout)
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
// Safe for concurrent use.
func (ir *Runtime) KeyIndexSnapshot() KeyIndexSnapshot {
	ir.keysLock.RLock()
	defer ir.keysLock.RUnlock()

	snapshot := KeyIndexSnapshot{
		Revision:    ir.keysetRev.Load(),
		KeyFiles:    make(map[string]string, len(ir.keys)),
		KeyTypes:    make(map[string]string, len(ir.keyTypes)),
		KeyMetadata: make(map[string]KeyPublicMetadata, len(ir.keyMetadata)),
	}
	for k, v := range ir.keys {
		snapshot.KeyFiles[k] = v
	}
	for k, v := range ir.keyTypes {
		snapshot.KeyTypes[k] = v
	}
	for k, v := range ir.keyMetadata {
		v.Parameters = maps.Clone(v.Parameters)
		v.BoundedAuthorization = boundedmeta.Clone(v.BoundedAuthorization)
		if v.LogicSigResources != nil {
			cloned := v.LogicSigResources.Clone()
			v.LogicSigResources = &cloned
		}
		snapshot.KeyMetadata[k] = v
	}
	return snapshot
}

// KeySnapshot returns copies of the three key index maps only — callers that
// need per-key metadata use KeyIndexSnapshot, which additionally deep-clones
// it. Safe for concurrent use.
func (ir *Runtime) KeySnapshot() (keys, keyTypes map[string]string) {
	ir.keysLock.RLock()
	defer ir.keysLock.RUnlock()
	keys = maps.Clone(ir.keys)
	keyTypes = maps.Clone(ir.keyTypes)
	if keys == nil {
		keys = map[string]string{}
	}
	if keyTypes == nil {
		keyTypes = map[string]string{}
	}
	return keys, keyTypes
}

// PublishSnapshot replaces the key maps with new data from a reload.
func (ir *Runtime) PublishSnapshot(keys, keyTypes map[string]string) {
	metadata := make(map[string]KeyPublicMetadata)
	if ir.keyStore != nil {
		// GetSigningSummary builds a fresh caller-owned copy per call, so its
		// maps and metadata are adopted here without another clone layer.
		summaries := ir.keyStore.GetSigningSummary()
		publicKeys := ir.keyStore.GetPublicKeyHexMap()
		metadata = make(map[string]KeyPublicMetadata, len(summaries))
		for selector, summary := range summaries {
			metadata[selector] = KeyPublicMetadata{
				Category: summary.Category, PublicKeyHex: publicKeys[selector], Parameters: summary.Parameters,
				BoundedAuthorization: summary.BoundedAuthorization,
				LogicSigResources:    summary.LogicSigResources,
			}
		}
	}
	ir.keysLock.Lock()
	ir.keys = keys
	ir.keyTypes = keyTypes
	ir.keyMetadata = metadata
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

// WithKeyring runs fn with the identity's open keyring.
func (ir *Runtime) WithKeyring(fn func(*crypto.Keyring) error) error {
	return ir.keyStore.WithKeyring(fn)
}

// SnapshotKeySession returns the current key session under the passphrase lock.
func (ir *Runtime) SnapshotKeySession() *keystore.KeySession {
	ir.passphraseLock.RLock()
	session := ir.keySession
	ir.passphraseLock.RUnlock()
	return session
}

// --- Reload ---

// Reload rescans keys using the cached keyring (no passphrase needed).
// Admin mutation paths call this directly while holding the identity mutation lock;
// watcher paths must use reloadFromWatcher so they acquire that lock themselves.
func (ir *Runtime) Reload() (*signertemplates.ReloadReport, error) {
	ir.passphraseLock.RLock()
	defer ir.passphraseLock.RUnlock()
	return ir.reloadLocked(nil)
}

// ReloadWithPassphrase opens the keyring with the passphrase and scans keys.
// Caller must NOT hold passphraseLock.
func (ir *Runtime) ReloadWithPassphrase(passphrase []byte) (*signertemplates.ReloadReport, error) {
	ir.passphraseLock.Lock()
	defer ir.passphraseLock.Unlock()
	return ir.reloadLocked(passphrase)
}

func (ir *Runtime) reloadLocked(passphrase []byte) (*signertemplates.ReloadReport, error) {
	if ir.reloadFn == nil {
		return nil, fmt.Errorf("reload function not configured")
	}
	// Pass keySession directly — caller holds passphraseLock.
	return ir.reloadFn(passphrase, ir.keySession)
}

// --- Watcher ---

// EnsureKeyWatcher starts the file watcher if not already running.
// Watches the keys directory and key type state/template records.
// The watcher stays running across lock/unlock transitions: when unlocked
// it reloads immediately; when locked it marks the identity dirty for
// reconciliation on the next unlock.
// If the identity was marked dirty while locked, triggers an immediate reload.
func (ir *Runtime) EnsureKeyWatcher(startFn WatcherStartFunc) {
	ir.watcherMu.Lock()
	wasDirty := ir.dirty
	ir.dirty = false
	// Claim the start under the same critical section as the running check so
	// two concurrent callers cannot both start a watcher (the loser used to
	// leak its fsnotify watcher when the winner's cancel was overwritten).
	alreadyRunning := ir.watcherCancel != nil || ir.watcherStarting
	if !alreadyRunning {
		ir.watcherStarting = true
	}
	ir.watcherMu.Unlock()

	// Reconcile any changes that accumulated while locked. This takes the
	// reload lock, so it must run outside watcherMu.
	if wasDirty {
		ir.reconcileDirty()
	}

	if alreadyRunning {
		return
	}

	// Watch keys dir and key type state/template records, resolved through
	// the active layout: on a generational store the namespaces live inside
	// the generation CURRENT names. The identity dir catches creation of
	// intermediate directories and CURRENT pointer replacement (a reload
	// candidate); a pointer flip re-arms the watcher on the new generation's
	// directories via StopKeyWatcher + EnsureKeyWatcher in the flipping
	// operation, since fsnotify watches bind to inodes.
	dirs := []string{ir.keyPaths.ProductDir()}
	if active, err := genstore.ResolveActive(ir.keyPaths, ir.id); err == nil {
		dirs = append(dirs, active.KeysDir(), active.KeyTypeRecordsDir())
	} else {
		// An unresolvable layout still gets the identity-dir watch so a
		// repaired CURRENT triggers a reload; reload itself fails closed.
		dirs = append(
			dirs,
			ir.keyPaths.LegacyKeysDir(),
			ir.keyPaths.LegacyKeyTypeRecordsDir(),
		)
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
		ir.watcherMu.Lock()
		ir.watcherStarting = false
		ir.watcherMu.Unlock()
		fmt.Printf("⚠️  Warning: Failed to start file watcher: %v\n", err)
		fmt.Println("Keys will not auto-reload when filesystem changes")
		return
	}

	ir.watcherMu.Lock()
	ir.watcherStarting = false
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
		ir.keyStore.ClearKeys()
	}
}

// --- Internal ---

func (ir *Runtime) performLockCleanup() {
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
		ir.keyStore.ClearKeys()
	}
	ir.passphraseLock.Unlock()

	ir.keysLock.Lock()
	ir.keys = make(map[string]string)
	ir.keyTypes = make(map[string]string)
	ir.keyMetadata = make(map[string]KeyPublicMetadata)
	ir.keysetRev.Add(1)
	ir.keysLock.Unlock()

	fmt.Println("🔒 Signer locked - sensitive data cleared from memory")
}

func (ir *Runtime) notifyLocked() {
	if ir.onLocked != nil {
		ir.onLocked()
	}
}

func (ir *Runtime) performUnlock(passphrase []byte) func() (int, error) {
	return func() (int, error) {
		if err := crypto.VerifyPassphraseWithKeyring(passphrase, ir.keyPaths.KeystoreMetadataDir()); err != nil {
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
