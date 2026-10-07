// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package productruntime owns the product signing-state runtime.
package productruntime

import (
	"context"
	"fmt"
	"maps"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/clientregistry"
	"github.com/aplane-algo/aplane/internal/signerapp/enrollqueue"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
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

// Runtime owns all sensitive and mutable state for the product store.
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
//	                cosignerPolicyCfg/storedCosignerPolicyCfg. Held alone.
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

	approval   atomic.Pointer[signerapproval.Coordinator]
	runtimeCfg *RuntimeConfig
	nodeRole   noderole.Role
	policyMu   sync.RWMutex
	nodePolicy *policyruntime.NodePolicy

	// Enrolled client keys for this identity: the validated view of the
	// authorized_keys registry. The daemon is its only writer; see
	// publishRegistry for the validate, publish, install sequence.
	clients   *clientregistry.Registry
	pending   *enrollqueue.Queue // Enrollment requests waiting for the operator
	clientsMu sync.RWMutex       // Guards clients and pending together, so approval is one step

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

// Config is the construction parameters for the product Runtime.
type Config struct {
	KeyStore         *keystore.FileKeyStore
	KeyPaths         storepaths.Paths
	SessionTimeout   time.Duration
	ApprovalWait     time.Duration
	UserAutoApprove  *bool
	LockOnDisconnect bool
	NodeRole         noderole.Role
	OnLocked         func() // Called after lock transition completes.
}

// New creates a product Runtime in the locked state.
func New(cfg Config) *Runtime {
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
		keyStore:    cfg.KeyStore,
		keyPaths:    cfg.KeyPaths,
		lockRuntime: rt,
		keySession:  session,
		runtimeCfg:  NewRuntimeConfig(userAutoApprove, cfg.LockOnDisconnect, cfg.SessionTimeout, cfg.ApprovalWait),
		nodeRole:    nodeRole,
		keys:        make(map[string]string),
		keyTypes:    make(map[string]string),
		keyMetadata: make(map[string]KeyPublicMetadata),
		onLocked:    cfg.OnLocked,
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

// NodeRole returns the immutable role declared by the signer data root.
func (ir *Runtime) NodeRole() noderole.Role {
	return ir.nodeRole
}

// Policy returns a copy of the compiled signer policy, or nil on a cosigner
// node or before policy loads.
func (ir *Runtime) Policy() *policy.Config {
	return ir.NodePolicy().SignerConfig()
}

// CosignerPolicies returns copies of the compiled per-key cosigner policies.
func (ir *Runtime) CosignerPolicies() map[string]*policy.Config {
	return ir.NodePolicy().CosignerConfigs()
}

// NodePolicy returns the node's active verified policy, or nil before policy
// loads. The returned value is immutable and must not be modified.
func (ir *Runtime) NodePolicy() *policyruntime.NodePolicy {
	ir.policyMu.RLock()
	defer ir.policyMu.RUnlock()
	return ir.nodePolicy
}

// SetNodePolicy installs the node's verified policy as one atomic runtime
// update. nil clears it, which rejects every request that needs policy.
func (ir *Runtime) SetNodePolicy(p *policyruntime.NodePolicy) {
	ir.policyMu.Lock()
	defer ir.policyMu.Unlock()
	ir.nodePolicy = p
}

// SetPolicy installs a compiled signer policy without stored documents. It
// exists for tests that inject policy directly.
func (ir *Runtime) SetPolicy(cfg *policy.Config) {
	if cfg == nil {
		ir.SetNodePolicy(nil)
		return
	}
	ir.SetNodePolicy(&policyruntime.NodePolicy{Role: noderole.RoleSigner, Signer: cfg.Clone()})
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

// --- Product runtime config ---

// Config returns the product runtime configuration.
func (ir *Runtime) Config() *RuntimeConfig {
	return ir.runtimeCfg
}

// --- Token authority ---

// --- Enrolled client keys ---

// AuthorizedKeysPath returns the product store's authorized_keys path.
func (ir *Runtime) AuthorizedKeysPath() string {
	return filepath.Join(ir.keyPaths.ProductDir(), ".ssh", "authorized_keys")
}

// LoadAuthorizedKeys loads and validates the enrolled-key registry. A
// rejected file is an error naming the offending line; the caller refuses to
// serve rather than run with a registry it could not read completely. The
// file is read only here, at startup: afterwards the daemon is its only
// writer and an external edit takes effect at the next start.
func (ir *Runtime) LoadAuthorizedKeys() error {
	reg, err := clientregistry.Load(ir.AuthorizedKeysPath())
	if err != nil {
		return err
	}
	ir.clientsMu.Lock()
	ir.clients = reg
	ir.clientsMu.Unlock()
	return nil
}

func (ir *Runtime) registry() *clientregistry.Registry {
	ir.clientsMu.RLock()
	defer ir.clientsMu.RUnlock()
	return ir.clients
}

// HasAuthorizedKey reports whether key is currently enrolled.
func (ir *Runtime) HasAuthorizedKey(key ssh.PublicKey) bool {
	return ir.registry().Has(key)
}

// EnrolledKey returns the enrollment entry for a key fingerprint.
func (ir *Runtime) EnrolledKey(fingerprint string) (clientregistry.Entry, bool) {
	return ir.registry().LookupFingerprint(fingerprint)
}

// EnrolledKeys returns the enrolled keys in registry order.
func (ir *Runtime) EnrolledKeys() []clientregistry.Entry {
	return ir.registry().Entries()
}

// publishRegistry applies mutate to the current registry and, if it changed
// anything, validates the complete candidate, publishes it atomically, and
// installs it as the runtime view, all under one lock. An invalid candidate
// or a failed publish leaves the current registry and connections untouched.
// Installation is an assignment and cannot fail after publication, so the
// published file and the live view never disagree.
func (ir *Runtime) publishRegistry(mutate func(current *clientregistry.Registry) (next *clientregistry.Registry, changed bool, err error)) (bool, error) {
	ir.clientsMu.Lock()
	defer ir.clientsMu.Unlock()
	return ir.publishRegistryLocked(mutate)
}

// publishRegistryLocked is publishRegistry with clientsMu held.
func (ir *Runtime) publishRegistryLocked(mutate func(current *clientregistry.Registry) (next *clientregistry.Registry, changed bool, err error)) (bool, error) {
	current := ir.clients
	if current == nil {
		current, _ = clientregistry.Parse(nil)
	}
	next, changed, err := mutate(current)
	if err != nil {
		return false, err
	}
	if !changed {
		return false, nil
	}
	if _, err := clientregistry.Parse(next.Marshal()); err != nil {
		return false, fmt.Errorf("candidate registry is invalid: %w", err)
	}
	if err := clientregistry.Publish(ir.AuthorizedKeysPath(), next); err != nil {
		// The write may have failed before or after the rename, so the
		// registry on disk is either the old one or the new one. Adopt
		// whatever is there rather than keep authority the file no longer
		// grants; if the file cannot be read back, grant nothing.
		reloaded, loadErr := clientregistry.Load(ir.AuthorizedKeysPath())
		if loadErr != nil {
			ir.clients, _ = clientregistry.Parse(nil)
			return false, fmt.Errorf("%w (registry unreadable after the failed publish, all client keys refused until it is repaired: %v)", err, loadErr)
		}
		ir.clients = reloaded
		return false, err
	}
	ir.clients = next
	return true, nil
}

// EnrollAuthorizedKey enrolls key with a display label. Enrolling a key that
// is already enrolled changes nothing and writes nothing.
func (ir *Runtime) EnrollAuthorizedKey(key ssh.PublicKey, label string) error {
	_, err := ir.publishRegistry(func(current *clientregistry.Registry) (*clientregistry.Registry, bool, error) {
		next, added := current.WithKey(key, label)
		return next, added, nil
	})
	return err
}

// RevokeAuthorizedKey removes the key with the given fingerprint from the
// registry and returns its entry. The caller closes the key's connections
// after this returns; a connection authenticating meanwhile re-checks
// enrollment against the installed view and is refused.
func (ir *Runtime) RevokeAuthorizedKey(fingerprint string) (clientregistry.Entry, error) {
	var revoked clientregistry.Entry
	_, err := ir.publishRegistry(func(current *clientregistry.Registry) (*clientregistry.Registry, bool, error) {
		entry, ok := current.LookupFingerprint(fingerprint)
		if !ok {
			return nil, false, clientregistry.ErrNotEnrolled
		}
		revoked = entry
		next, err := current.WithoutFingerprint(fingerprint)
		if err != nil {
			return nil, false, err
		}
		return next, true, nil
	})
	return revoked, err
}

// RevokeAllAuthorizedKeys empties the registry and returns the entries it
// held.
func (ir *Runtime) RevokeAllAuthorizedKeys() ([]clientregistry.Entry, error) {
	var revoked []clientregistry.Entry
	_, err := ir.publishRegistry(func(current *clientregistry.Registry) (*clientregistry.Registry, bool, error) {
		revoked = current.Entries()
		if len(revoked) == 0 {
			return current, false, nil
		}
		next, _ := clientregistry.Parse(nil)
		return next, true, nil
	})
	return revoked, err
}

// --- Pending enrollment requests ---

// PendingEnrollmentsPath returns the product store's enrollment queue path.
func (ir *Runtime) PendingEnrollmentsPath() string {
	return filepath.Join(ir.keyPaths.ProductDir(), ".ssh", enrollqueue.FileName)
}

// LoadEnrollmentQueue loads the persisted enrollment requests. Like the
// registry it is read only at startup; the daemon is its only writer.
func (ir *Runtime) LoadEnrollmentQueue() error {
	q, err := enrollqueue.Load(ir.PendingEnrollmentsPath(), time.Now())
	if err != nil {
		return err
	}
	ir.clientsMu.Lock()
	ir.pending = q
	ir.clientsMu.Unlock()
	return nil
}

// publishQueueLocked publishes next as the enrollment queue and installs it,
// with clientsMu held.
func (ir *Runtime) publishQueueLocked(next *enrollqueue.Queue) error {
	if err := enrollqueue.Publish(ir.PendingEnrollmentsPath(), next); err != nil {
		return err
	}
	ir.pending = next
	return nil
}

func (ir *Runtime) pendingLocked() *enrollqueue.Queue {
	if ir.pending == nil {
		ir.pending = &enrollqueue.Queue{}
	}
	return ir.pending
}

// QueueEnrollment records a client's request to be enrolled. A key that is
// already enrolled is reported as such and nothing is queued; otherwise the
// request waits for the operator, and added reports whether it was new
// rather than a refresh of a request already waiting. enrollqueue.ErrQueueFull
// refuses a new request when the queue is at its cap.
func (ir *Runtime) QueueEnrollment(key ssh.PublicKey, label, remoteAddr string) (pending bool, added bool, err error) {
	ir.clientsMu.Lock()
	defer ir.clientsMu.Unlock()
	if ir.clients != nil && ir.clients.Has(key) {
		return false, false, nil
	}
	next, _, added, err := ir.pendingLocked().WithRequest(key, label, remoteAddr, time.Now())
	if err != nil {
		return false, false, err
	}
	if err := ir.publishQueueLocked(next); err != nil {
		return false, false, err
	}
	return true, added, nil
}

// PendingEnrollments returns the requests waiting for the operator, oldest
// first, without those that lapsed.
func (ir *Runtime) PendingEnrollments() []enrollqueue.Entry {
	ir.clientsMu.RLock()
	defer ir.clientsMu.RUnlock()
	return ir.pending.Pruned(time.Now()).Entries()
}

// ApproveEnrollment enrolls the key of a pending request and removes the
// request. label, when set, replaces the label the client asked for. The
// registry is published before the queue, so a failure between the two
// leaves an enrolled key whose request is still listed; approving it again
// is a no-op for the registry and clears the request.
func (ir *Runtime) ApproveEnrollment(fingerprint, label string) (enrollqueue.Entry, error) {
	ir.clientsMu.Lock()
	defer ir.clientsMu.Unlock()
	entry, ok := ir.pendingLocked().Pruned(time.Now()).Lookup(fingerprint)
	if !ok {
		return enrollqueue.Entry{}, enrollqueue.ErrNotPending
	}
	if label == "" {
		label = entry.Label
	}
	if _, err := ir.publishRegistryLocked(func(current *clientregistry.Registry) (*clientregistry.Registry, bool, error) {
		next, added := current.WithKey(entry.Key, label)
		return next, added, nil
	}); err != nil {
		return enrollqueue.Entry{}, err
	}
	next, _, err := ir.pendingLocked().WithoutFingerprint(fingerprint)
	if err != nil {
		return enrollqueue.Entry{}, err
	}
	if err := ir.publishQueueLocked(next); err != nil {
		return enrollqueue.Entry{}, err
	}
	entry.Label = label
	return entry, nil
}

// RejectEnrollment removes a pending request without enrolling its key.
func (ir *Runtime) RejectEnrollment(fingerprint string) (enrollqueue.Entry, error) {
	ir.clientsMu.Lock()
	defer ir.clientsMu.Unlock()
	next, entry, err := ir.pendingLocked().WithoutFingerprint(fingerprint)
	if err != nil {
		return enrollqueue.Entry{}, err
	}
	if err := ir.publishQueueLocked(next); err != nil {
		return enrollqueue.Entry{}, err
	}
	return entry, nil
}

// ImportClientKey enrolls a public key the operator supplied directly, the
// pre-enrollment path. A pending request for the same key is cleared. added
// reports whether the key was new to the registry.
func (ir *Runtime) ImportClientKey(key ssh.PublicKey, label string) (added bool, err error) {
	ir.clientsMu.Lock()
	defer ir.clientsMu.Unlock()
	added, err = ir.publishRegistryLocked(func(current *clientregistry.Registry) (*clientregistry.Registry, bool, error) {
		next, added := current.WithKey(key, label)
		return next, added, nil
	})
	if err != nil {
		return false, err
	}
	if next, _, err := ir.pendingLocked().WithoutFingerprint(ssh.FingerprintSHA256(key)); err == nil {
		if err := ir.publishQueueLocked(next); err != nil {
			return added, err
		}
	}
	return added, nil
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

// ActivePaths returns the generation authenticated by the runtime's most
// recent successful root unlock or reload.
func (ir *Runtime) ActivePaths() (storepaths.GenPaths, error) {
	if ir.keyStore == nil {
		return storepaths.GenPaths{}, fmt.Errorf("product key store is not configured: %w", keystore.ErrStoreLocked)
	}
	return ir.keyStore.ActivePaths()
}

// ActiveKeyPaths returns a path configuration bound to the runtime's
// authenticated active generation. Routine mutation helpers may pass this
// capability through existing Paths-based APIs without consulting a public pointer.
func (ir *Runtime) ActiveKeyPaths() (storepaths.Paths, error) {
	active, err := ir.ActivePaths()
	if err != nil {
		return storepaths.Paths{}, err
	}
	return ir.keyPaths.BindActive(active)
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
// Admin mutation paths call this directly while holding the store mutation lock;
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

	// Watch keys and key-type records through the authenticated generation
	// capability. The identity directory observes store-root replacement; a
	// root commit re-arms the watcher on the newly selected generation because
	// fsnotify watches bind to inodes.
	dirs := []string{ir.keyPaths.ProductDir()}
	if active, err := ir.ActivePaths(); err == nil {
		dirs = append(dirs, active.KeysDir(), active.KeyTypeRecordsDir())
	} else {
		fmt.Printf("⚠️  Warning: cannot watch the active generation's keys: %v\n", err)
		fmt.Println("Only store-root replacement will trigger a key reload")
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
		fmt.Printf("⚠️  Dirty-state reconciliation failed for product store: %v\n", err)
	} else {
		fmt.Println("✓ Reconciled pending filesystem changes for product store")
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

// Destroy cleans up the product runtime for shutdown.
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
		if err := crypto.VerifyPassphraseWithStoreRoot(passphrase, ir.keyPaths.KeystoreMetadataDir()); err != nil {
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
