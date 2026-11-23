// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package productruntime owns the product signing-state runtime.
package productruntime

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aplane-algo/aplane/pkg/signerapi"

	"github.com/aplane-algo/aplane/internal/asaset"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/crypto"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/signerapp/clientregistry"
	"github.com/aplane-algo/aplane/internal/signerapp/enrollqueue"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
	"github.com/aplane-algo/aplane/internal/signerapp/unlockconfig"
	"github.com/aplane-algo/aplane/internal/sourcetokens"
	"github.com/aplane-algo/aplane/internal/stagetable"
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
//	reloadLock() ->  signerruntime stateMu (an unlock attempt's reading,
//	                 checks and fence; Unlock holds reloadLock across all)
//	reloadLock() ->  lsigprovider.registerMu
//	keyUseMu     ->  signerruntime stateMu (read)
//	signerruntime stateMu (read)  ->  rotatingStatusMu
//	signerruntime stateMu (read)  ->  sourceTokens
//	passphraseLock                ->  sourceTokens
//	passphraseLock                ->  lsigprovider.registerMu (a publish)
//	passphraseLock                ->  signerruntime stateMu (a reload's
//	                                  entry into recovery)
//
// Per-lock scope:
//
//	passphraseLock  guards keySession, buildFn, reloadEffects, and
//	                keyring-unlock paths; a reload on the keyring in service
//	                holds it for reading from its build to its install.
//	keysLock        guards the keys/keyTypes/keyMetadata maps. keysetRev is
//	                bumped while keysLock is held (and atomically readable).
//	watcherMu       guards watcherCancel, dirty, and the reloadLock callback
//	                pointer. It is never nested with passphraseLock or keysLock;
//	                reloadFromWatcher copies the callback out before releasing
//	                watcherMu.
//	policyMu        guards nodePolicy, asaSet and policyAlerts. Held alone.
//	clientsMu       guards clients, pending and their unsynced and intended
//	                markers. Held alone.
//	keyUseMu        guards the key-use context and destroyed. KeyUseContext
//	                and LockCancelContext read the lock state (IsUnlocked)
//	                while holding it; every other holder takes it alone.
//	rotatingStatusMu guards the published rotating status. PublishRotatingStatus
//	                takes it inside WhileGeneration, under the state lock's
//	                read side; every other holder takes it alone.
//	sourceTokens    the source token index holder's own lock, a leaf.
//	                ReplaceSourceTokens takes it inside WhileGeneration;
//	                reload publication and lock cleanup take it under
//	                passphraseLock.
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
// The full process-wide lock table lives in docs/ARCH_OVERVIEW.md, "Lock Hierarchy".
type Runtime struct {
	keyStore    *keystore.FileKeyStore
	keyPaths    storepaths.Paths
	lockRuntime *signerruntime.Runtime

	// unlockMethod is fixed at construction: a helper written later takes
	// effect at the next start.
	unlockMethod string

	// stageTables is the process's single owner of rotating accounts' stage
	// address tables (identities/default/stages), a derivable cache.
	stageTables *stagetable.Store
	stageWork   chan struct{}

	// Key users are holders of loaded key material outside the session (the
	// stage table worker and the rotating sign path). Lock cancels their context and waits for them to
	// release before it clears the session, so no copy of a seed outlives
	// the unlocked state.
	keyUseMu     sync.Mutex
	keyUseCtx    context.Context
	keyUseCancel context.CancelFunc
	keyUsers     sync.WaitGroup
	// destroyed is set under keyUseMu when shutdown begins (EndKeyUses, or
	// Destroy alone). From then on KeyUseContext refuses every key use as it
	// does while locked, since shutdown does not lock the signer.
	destroyed bool

	// Rotating account status from the last background pass: warnings need
	// action, notes are information. Published to /status and apadmin.
	rotatingStatusMu sync.Mutex
	rotatingAlerts   []string
	rotatingNotes    []string
	rotatingAccounts []signerapi.RotatingAccountStatus

	keySession     *keystore.KeySession
	passphraseLock sync.RWMutex
	// providers is the LogicSig provider registry this runtime's reloads
	// register templates in: the process-wide one, which every identity in
	// the process shares (see ProviderRegistry).
	providers   signertemplates.ProviderRegistry
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

	// buildFn and reloadEffects are the reload's build and what it tells
	// the process, guarded by passphraseLock (SetBuildFunc).
	buildFn       BuildFunc
	reloadEffects ReloadEffects

	approval   atomic.Pointer[signerapproval.Coordinator]
	runtimeCfg *RuntimeConfig
	nodeRole   noderole.Role
	policyMu   sync.RWMutex
	nodePolicy *policyruntime.NodePolicy
	// asaSet is the node's verified ASA set, published with nodePolicy so the
	// two are always read as one view; policyAlerts are the admission
	// problems of the stored documents, computed when they load.
	asaSet       *asaset.Set
	policyAlerts []string

	// sourceTokens holds the source token index a reload decrypted, which
	// the cosigner's external checks read tokens from. The index is
	// immutable; a reload, a token set or a token remove publishes a new
	// one, and the old one is zeroed once its last reader releases. Lock
	// cleanup clears it after the key users have drained, and a locked
	// runtime holds none.
	sourceTokens sourcetokens.Holder

	// Enrolled client keys for this identity: the validated view of the
	// authorized_keys registry. The daemon is its only writer; see
	// publishRegistry for the validate, publish, install sequence. A nil
	// clients or pending is empty: every method used on them is nil-safe.
	clients   *clientregistry.Registry
	pending   *enrollqueue.Queue // Enrollment requests waiting for the operator
	clientsMu sync.RWMutex       // Guards clients and pending together, so approval is one step
	// clientsUnsynced records a registry publish that failed after its
	// rename: the file holds the intended registry but may not survive a
	// crash. The next registry operation re-publishes it before doing
	// anything else, so no retry is acknowledged on top of an unsynced file.
	clientsUnsynced bool
	// clientsIntended is set when the registry file could not be read back
	// after a failed publish. The outcome on disk is then unknown, so the
	// change is reported as applied and this is the registry it intended.
	// clients meanwhile is a placeholder that refuses every key and is
	// never published; the next registry operation waits for the file to
	// be readable and then publishes clientsIntended, so what was reported
	// is what the file ends up holding.
	clientsIntended *clientregistry.Registry
	// pendingUnsynced and pendingIntended are the same markers for the
	// enrollment queue file.
	pendingUnsynced bool
	pendingIntended *enrollqueue.Queue

	// onLocked is called after lock cleanup completes (for IPC notification, etc).
	onLocked func()
	// onReloadRecovery is called with the cause after a reload entered
	// recovery (SetReloadRecoveryHook). Guarded by watcherMu.
	onReloadRecovery func(cause error)
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
	BaseKeyType          string
	PublicKeyHex         string
	Parameters           map[string]string
	BoundedAuthorization *boundedmeta.Metadata
	LogicSigResources    *lsigresource.Profile
	// SigningArgs is a LogicSig key's declared runtime arguments, in order.
	SigningArgs []lsigprovider.RuntimeArgDef
	// ValidRekeyTarget is the valid_rekey_target the aplane key recorded when
	// it was created.
	ValidRekeyTarget bool
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
	// UnlockMethod is the auto-unlock method the runtime started with (see
	// unlockconfig.UnlockConfig.Method); empty means "none".
	UnlockMethod string
	OnLocked     func() // Called after lock transition completes.
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
	unlockMethod := cfg.UnlockMethod
	if unlockMethod == "" {
		unlockMethod = unlockconfig.MethodNone
	}

	ir := &Runtime{
		providers:    lsigprovider.ProcessRegistry{},
		keyStore:     cfg.KeyStore,
		keyPaths:     cfg.KeyPaths,
		stageTables:  stagetable.NewStore(cfg.KeyPaths),
		stageWork:    make(chan struct{}, 1),
		lockRuntime:  rt,
		keySession:   session,
		runtimeCfg:   NewRuntimeConfig(userAutoApprove, cfg.LockOnDisconnect, cfg.SessionTimeout, cfg.ApprovalWait),
		nodeRole:     nodeRole,
		unlockMethod: unlockMethod,
		keys:         make(map[string]string),
		keyTypes:     make(map[string]string),
		keyMetadata:  make(map[string]KeyPublicMetadata),
		onLocked:     cfg.OnLocked,
	}
	ir.keysetRev.Store(initialKeysetRevision())

	rt.SetOnLock(ir.performLockCleanup)
	return ir
}

// keysetRevisionBits bounds the random starting revision. Starting below 2^52
// leaves 2^52 publishes before the revision passes 2^53, the largest integer
// a JSON number carries exactly in JavaScript.
const keysetRevisionBits = 52

// initialKeysetRevision is where a process's keyset revision counts from: a
// random value, so a restarted signer does not report the revisions the
// previous process did, and a client that cached a key list under one of them
// sees a different revision and refreshes.
func initialKeysetRevision() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return binary.BigEndian.Uint64(b[:]) >> (64 - keysetRevisionBits)
}

// SetReloadMutationLock sets the process-wide lock watcher-triggered reloads
// acquire before scanning disk. Admin mutations that already hold this lock call
// Reload directly and must not re-enter it.
func (ir *Runtime) SetReloadMutationLock(fn func() sync.Locker) {
	ir.watcherMu.Lock()
	ir.reloadLock = fn
	ir.watcherMu.Unlock()
}

// SetReloadRecoveryHook sets the function a reload calls once its failure
// rule has entered recovery, with the cause. Nothing else tells anyone:
// the reload ran for a watcher event or as one step of an admin change, with
// no request that reports the state. The process root logs the entry and
// pushes the state to the admin session.
func (ir *Runtime) SetReloadRecoveryHook(fn func(cause error)) {
	ir.watcherMu.Lock()
	ir.onReloadRecovery = fn
	ir.watcherMu.Unlock()
}

// NodeRole returns the immutable role declared by the signer data root.
func (ir *Runtime) NodeRole() noderole.Role {
	return ir.nodeRole
}

// UnlockMethod is the auto-unlock method this runtime started with; anything
// but unlockconfig.MethodNone means it is headless.
func (ir *Runtime) UnlockMethod() string {
	return ir.unlockMethod
}

// NodePolicy returns the node's active verified policy, or nil before policy
// loads. The returned value is immutable and must not be modified. A signing
// request captures one NodePolicy when its service is built and resolves
// every slot against it.
func (ir *Runtime) NodePolicy() *policyruntime.NodePolicy {
	ir.policyMu.RLock()
	defer ir.policyMu.RUnlock()
	return ir.nodePolicy
}

// PolicyState returns the node's verified policy and ASA set (its operator's
// confirmations; the built-ins are always known) read under one lock, so the
// two always belong to the same unlock or reload. Both are nil before policy
// loads, and both are immutable. Read them together through this method:
// separate reads could straddle a reload.
func (ir *Runtime) PolicyState() (*policyruntime.NodePolicy, *asaset.Set) {
	ir.policyMu.RLock()
	defer ir.policyMu.RUnlock()
	return ir.nodePolicy, ir.asaSet
}

// SetVerifiedPolicyState installs the node's verified policy and ASA set,
// with the admission alerts of its stored documents, as one atomic runtime
// update, so no reader sees one without the others.
func (ir *Runtime) SetVerifiedPolicyState(p *policyruntime.NodePolicy, set *asaset.Set, alerts []string) {
	ir.policyMu.Lock()
	defer ir.policyMu.Unlock()
	ir.nodePolicy, ir.asaSet, ir.policyAlerts = p, set, slices.Clone(alerts)
}

// PublishSourceTokens installs the source token index a reload decrypted
// from the generation it just verified, and retires the one it replaces. It
// is called from the reload, which holds passphraseLock, so a lock cleanup,
// which clears the index under the same lock, lands wholly before or after
// it; a reload after the cleanup has no keyring to decrypt with.
func (ir *Runtime) PublishSourceTokens(next *sourcetokens.Index) {
	ir.sourceTokens.Publish(next)
}

// ReplaceSourceTokens publishes the index with one selector's tokens replaced
// by f's, nil for none, after a token set or remove has written the file. It
// publishes only while the signer is unlocked in generation, the session the
// write began in, and reports whether it did: a lock that came first has
// cleared the index, and the next unlock's reload reads the file. f is
// copied; the caller still zeroes it.
func (ir *Runtime) ReplaceSourceTokens(generation uint64, selector string, f *sourcetokens.File) bool {
	return ir.lockRuntime.WhileGeneration(generation, func() {
		ir.sourceTokens.Replace(selector, f)
	})
}

// SourceTokenFor returns the token set for source under a cosigner policy
// selector (a Witness Key ID, or "default"), and false when none is set or
// the signer is locked. It is not gated on the signer's state: its one
// caller, the external check step, holds a key use, which only an unlocked
// signer grants, and a step a lock or a recovery overtakes must end as
// locked, not as a missing token. It reads the index published at the time of the
// call, holding a reader for the lookup, and is safe for concurrent use. The
// external check step calls it inside its key use, so a lock cannot clear
// the index while a lookup reads it. It has the shape of
// externalcheck.TokenFor.
//
// The token comes back as a Go string, which cannot be zeroed: the check
// puts it in a request header, and that copy lasts until the request is
// garbage collected. Zeroing at lock covers the index, not those copies.
func (ir *Runtime) SourceTokenFor(selector, source string) (string, bool) {
	return ir.sourceTokens.TokenFor(selector, source)
}

// SourceTokenNamesFor returns the source names one cosigner policy selector
// has a token for, from the index published at the time of the call: the
// live tokens a policy check's missing-token advisory checks a document
// against. known is false unless the signer is unlocked: a locked signer has
// no index, and one in recovery may hold an index of a generation the store
// has since left, so which tokens are set is not known.
func (ir *Runtime) SourceTokenNamesFor(selector string) (names []string, known bool) {
	if !ir.IsUnlocked() {
		return nil, false
	}
	return ir.sourceTokens.NamesFor(selector)
}

// StatusAlerts are every alert a status report carries for this identity:
// rotating account alerts, then policy admission alerts.
func (ir *Runtime) StatusAlerts() []string {
	return append(ir.RotatingAlerts(), ir.PolicyAlerts()...)
}

// PolicyAlerts are the admission problems of the node's stored policy
// documents: networks the node does not know, assets outside its ASA set,
// and the like. A stored document keeps working; these say what to fix.
func (ir *Runtime) PolicyAlerts() []string {
	ir.policyMu.RLock()
	defer ir.policyMu.RUnlock()
	return slices.Clone(ir.policyAlerts)
}

// --- Lock state ---

// GetState returns the current lock state.
func (ir *Runtime) GetState() signerruntime.SignerState {
	return ir.lockRuntime.GetState()
}

// ErrNeitherUnlockedNorRecovery is RequireUnlockedOrRecovery's refusal. It
// wraps keystore.ErrStoreLocked.
var ErrNeitherUnlockedNorRecovery = fmt.Errorf("signer is locked: %w", keystore.ErrStoreLocked)

// RequireUnlockedOrRecovery refuses a store change that reached the store
// mutation lock on a signer neither unlocked nor in recovery. A handler's
// gate ran before the request queued on the lock, and a lock since then
// leaves the keyring open until its cleanup has run: a change there whose
// reload failed would call SetRecovery on a locked signer, which does
// nothing. The caller holds the store mutation lock. Restore, rollback and
// reconcile use it.
func (ir *Runtime) RequireUnlockedOrRecovery() error {
	switch ir.GetState() {
	case signerruntime.SignerStateUnlocked, signerruntime.SignerStateRecovery:
		return nil
	}
	return ErrNeitherUnlockedNorRecovery
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
	ok := ir.lockRuntime.PromoteRecoveryToUnlocked()
	if ok {
		ir.WakeStageWork()
	}
	return ok
}

// SetUnlocked marks this identity as unlocked without the fence an unlock
// attempt passes. No production path calls it: an unlock request publishes
// through Unlock, and a reconcile leaves recovery through
// PromoteRecoveryToUnlocked. Tests use it to set up an unlocked runtime;
// test/arch keeps it out of production code.
func (ir *Runtime) SetUnlocked() {
	ir.lockRuntime.SetUnlocked()
	ir.WakeStageWork()
}

// SetRecovery moves this identity into recovery without the recovery view:
// the keys and the source token index stay, and the hook is not told. No
// production path calls it: every entry into recovery publishes the view
// (EnterRecovery, and the reload's failure rule). Tests use it to land a
// recovery where none can land in production, inside an unlock's held load,
// to exercise the unlock's fence; test/arch keeps it out of production code.
func (ir *Runtime) SetRecovery() {
	if ir.lockRuntime.SetRecovery() {
		ir.cancelKeyUses()
		ir.endSignRequests()
	}
}

// endSignRequests ends every approval wait in flight when the session ends,
// so no request from it is left waiting for, or showing, an approval; those
// answer that the session ended. Requests that are planning or signing are
// not interrupted here: the session check refuses one that has not passed it,
// and the cut of its key use refuses a rotating sign. Ordinary and component
// signing register no key use, so one already past the check is stopped only
// by a key load after the lock cleanup cleared the session, or after an
// entry into recovery stopped it (ARCH_SIGNING.md, session end).
// The lock cleanup calls it first, before it waits for key users, so a lock,
// the start of store maintenance and an unlock that lost to a lock withdraw
// at once; entering recovery, which runs no cleanup, calls it directly.
func (ir *Runtime) endSignRequests() {
	if c := ir.approval.Load(); c != nil {
		c.EndSessionSignRequests()
	}
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

// UnlockOutcome is how an unlock request that did not fail ended.
type UnlockOutcome struct {
	// Recovery is set when the request left the signer in recovery: its
	// reconcile or its load found the store needing it, or the reload of
	// changes seen while locked, run once it published, entered recovery.
	Recovery bool
	// KeyCount is the published key count of an unlocked signer.
	KeyCount int
	// Cause is why the request entered recovery. It is nil when the reload of
	// changes seen while locked entered recovery, which told the admin
	// session and the log itself.
	Cause error
}

// Unlock runs an unlock request, all of it under one hold of the store
// mutation lock: the state read, the passphrase check, the reconcile, the
// load and the publish, or the entry into recovery when the reconcile or the
// load finds the store needing it. Every entry into recovery, every
// reconcile's promotion out of it and a passphrase change's republish hold
// the same lock, so none lands inside a request, and an unlock that arrives
// during a passphrase change waits for it and finds the new passphrase.
//
// The request reads the lock generation and the session once, at its start
// (signerruntime.Runtime.BeginAttempt), and checks that reading before its
// reconcile, before its load, and at both of its ends. A lock that lands at
// any point after the reading wins: the request answers
// signerruntime.ErrLockedDuringUnlock, has reconciled and loaded nothing it
// had not done yet, and leaves the signer locked whichever way it would have
// ended.
//
// A request that finds the signer unlocked checks the passphrase and answers
// with the session's key count; it reconciles, loads and publishes nothing.
// For a signer locked or in recovery the store root is opened with the
// passphrase once, which is that request's passphrase check; reconcile runs
// with the keyring it opened, and the load opens the root again. A
// passphrase that does not open the root ends the request there, with
// ErrInvalidPassphrase.
//
// onUnlocked runs after the store mutation lock is released, once the
// request has published: it starts the watcher, whose reload of changes seen
// while locked takes that lock. It returns the outcome, or the error of a
// request that neither unlocked the signer nor entered recovery. The
// passphrase bytes are not zeroed.
func (ir *Runtime) Unlock(passphrase []byte, reconcile func(*crypto.Keyring) error, onUnlocked func()) (UnlockOutcome, error) {
	release := ir.lockStoreMutation()
	outcome, published, err := ir.unlockHeld(passphrase, reconcile)
	release()
	if err != nil || !published {
		return outcome, err
	}
	fmt.Printf("🔓 Signer unlocked (%d keys loaded)\n", outcome.KeyCount)
	ir.WakeStageWork()
	if onUnlocked != nil {
		onUnlocked()
	}
	// The watcher's reload of changes seen while locked can find a defect
	// that appeared after this request's own load and enter recovery. That
	// reload told the admin session itself.
	if ir.IsRecovery() {
		return UnlockOutcome{Recovery: true}, nil
	}
	return outcome, nil
}

// unlockHeld is Unlock's work under the store mutation lock. published
// reports that it published the unlocked state.
func (ir *Runtime) unlockHeld(passphrase []byte, reconcile func(*crypto.Keyring) error) (outcome UnlockOutcome, published bool, err error) {
	attempt := ir.lockRuntime.BeginAttempt()
	if attempt.State() == signerruntime.SignerStateUnlocked {
		outcome, err := ir.answerFromSession(attempt, passphrase)
		return outcome, false, err
	}
	kr, _, err := openStoreRoot(ir.keyPaths.ProductDir(), passphrase)
	if err != nil {
		return UnlockOutcome{}, false, unlockFailure(err)
	}
	defer kr.Zero()
	if ir.lockRuntime.LostToLock(attempt) {
		return UnlockOutcome{}, false, signerruntime.ErrLockedDuringUnlock
	}
	if err := reconcile(kr); err != nil {
		// The store needs recovery: the attempt builds for recovery's view,
		// so it is bound to what the root selects and shows the policy the
		// build verified.
		owned, loaded, buildErr := ir.buildWithPassphrase(passphrase)
		end := buildEnd(loaded, buildErr)
		outcome, err := ir.unlockIntoRecovery(attempt, owned, loaded, err)
		ir.afterReload(end)
		return outcome, false, err
	}
	if ir.lockRuntime.LostToLock(attempt) {
		return UnlockOutcome{}, false, signerruntime.ErrLockedDuringUnlock
	}
	owned, loaded, buildErr := ir.buildWithPassphrase(passphrase)
	if buildErr != nil {
		end := buildEnd(loaded, buildErr)
		outcome, err := ir.unlockBuildFailed(attempt, owned, loaded, fmt.Errorf("failed to load keys: %w", buildErr))
		ir.afterReload(end)
		return outcome, false, err
	}
	report := ir.publishUnlock(owned, loaded)
	end := reloadEnd{notices: report.TemplateNotices, warnings: report.TemplateWarnings, rejected: rejectedLogicSigKeys(loaded.Contents)}
	switch err := ir.lockRuntime.PublishUnlocked(attempt); {
	case errors.Is(err, signerruntime.ErrLockedDuringUnlock):
		// The attempt locked the runtime for its cleanup, which cleared
		// what the publish installed: no key went into service, so no
		// reload is recorded.
		ir.notifyLocked()
		ir.afterReload(end)
		return UnlockOutcome{}, false, err
	case errors.Is(err, signerruntime.ErrRecoveryDuringUnlock):
		// Under the one hold no entry into recovery reaches this fence; it
		// stays as a layered guard, and recovery then keeps what the
		// publish installed until its reconcile.
		ir.afterReload(end)
		return UnlockOutcome{Recovery: true, Cause: err}, false, nil
	}
	end.published, end.keyCount = true, report.KeyCount
	ir.afterReload(end)
	return UnlockOutcome{KeyCount: report.KeyCount}, true, nil
}

// answerFromSession answers a request that found the signer unlocked, from
// the session in service: it checks the passphrase and answers with the
// session's key count, and reconciles, loads and publishes nothing. A load
// there would replace the keyring, the policy, the key maps and the source
// token index under the session in service. A lock during the check wins:
// the request answers that the signer locked, and does not unlock it again.
// A wrong passphrase is refused whatever came meanwhile.
func (ir *Runtime) answerFromSession(attempt signerruntime.Attempt, passphrase []byte) (UnlockOutcome, error) {
	if err := verifyUnlockPassphrase(passphrase, ir.keyPaths); err != nil {
		return UnlockOutcome{}, err
	}
	keyCount := ir.KeyCount()
	if !ir.lockRuntime.Unchanged(attempt) {
		return UnlockOutcome{}, signerruntime.ErrLockedDuringUnlock
	}
	return UnlockOutcome{KeyCount: keyCount}, nil
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

// RequestSigningApprovalPrompt shows prompt to the operator and waits for the
// answer.
func (ir *Runtime) RequestSigningApprovalPrompt(ctx context.Context, prompt signerapproval.Prompt, timeout time.Duration) (signerapproval.SignResponse, error) {
	c := ir.approval.Load()
	if c == nil {
		return signerapproval.SignResponse{}, fmt.Errorf("approval coordinator not initialized")
	}
	return c.RequestSigningApprovalPrompt(ctx, prompt, timeout)
}

// FailAllPendingApprovals withdraws every prompt delivered to the apadmin
// session that is ending (Coordinator.FailAllPendingRequests).
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

// ErrAppliedNotDurable reports a registry or enrollment-queue change that
// is installed and in force but whose file may not survive a crash: the
// publish failed after its rename. The caller treats the change as made
// (audits it, acts on it) and still reports the error; the next operation on
// that file re-publishes it before doing anything else.
var ErrAppliedNotDurable = errors.New("change applied but not yet durable")

// ErrAlreadyEnrolled reports a rejection of a request whose key is already
// in the registry (an approval that enrolled the key but could not clear
// its request). Rejecting would drop the request while the key stays
// usable, so the operator approves again to clear it or revokes the key.
var ErrAlreadyEnrolled = errors.New("key is already enrolled")

// publishRegistry applies mutate to the current registry and, if it changed
// anything, validates the complete candidate, publishes it atomically and
// durably, and installs it as the runtime view, all under one lock. It
// reports whether the live view now holds the mutated registry. An invalid
// candidate or a publish that fails before its rename leaves the current
// registry and connections untouched. Installation is an assignment and
// cannot fail after publication, so the published file and the live view
// never disagree.
//
// A publish can also fail after its rename (the directory fsync): the file
// then holds the intended registry, which the runtime adopts so it never
// keeps authority the file no longer grants, but the file may not survive a
// crash. The change is then reported as applied together with an error
// wrapping ErrAppliedNotDurable, so the caller records the authority change
// separately from its durability outcome. That state is remembered, and the
// next call re-publishes the file before applying mutate, so a retry
// succeeds only once a sync has.
func (ir *Runtime) publishRegistry(mutate func(current *clientregistry.Registry) (next *clientregistry.Registry, changed bool, err error)) (bool, error) {
	ir.clientsMu.Lock()
	defer ir.clientsMu.Unlock()
	return ir.publishRegistryLocked(mutate)
}

// publishRegistryLocked is publishRegistry with clientsMu held.
func (ir *Runtime) publishRegistryLocked(mutate func(current *clientregistry.Registry) (next *clientregistry.Registry, changed bool, err error)) (bool, error) {
	if err := ir.ensureRegistryDurableLocked(); err != nil {
		return false, err
	}
	// Taken after the re-publish, which may have read the file again.
	next, changed, err := mutate(ir.clients)
	if err != nil {
		return false, err
	}
	if !changed {
		return false, nil
	}
	if _, err := clientregistry.Parse(next.Marshal()); err != nil {
		return false, fmt.Errorf("candidate registry is invalid: %w", err)
	}
	applied, err := ir.publishRegistryFileLocked(next)
	if err != nil {
		if applied {
			return true, fmt.Errorf("%w: %w", ErrAppliedNotDurable, err)
		}
		return false, err
	}
	return true, nil
}

// ensureRegistryDurableLocked re-publishes the registry left by an earlier
// failed write, so nothing is acknowledged on the strength of the unsynced
// file: neither a retried change nor an answer that reads the registry,
// such as "already enrolled". Its failure never wraps ErrAppliedNotDurable:
// the change it re-publishes was reported when it was made.
func (ir *Runtime) ensureRegistryDurableLocked() error {
	if !ir.clientsUnsynced {
		return nil
	}
	if ir.clientsIntended != nil {
		// What the runtime holds is the placeholder, not the registry:
		// publishing it would write every enrolled key out of the file.
		// Wait until the file reads again, then publish the registry the
		// failed write intended, whichever of the two the file holds.
		if _, err := clientregistry.Load(ir.AuthorizedKeysPath()); err != nil {
			return fmt.Errorf("registry is unreadable after an earlier failed write; repair %s: %w", ir.AuthorizedKeysPath(), err)
		}
		if err := clientregistry.Publish(ir.AuthorizedKeysPath(), ir.clientsIntended); err != nil {
			// Not durable yet. Keep the commitment and keep refusing every
			// key: adopting what the file holds now could undo a change
			// that was reported made, a revocation included.
			return fmt.Errorf("registry from an earlier failed write is still not durable: %w", err)
		}
		ir.clients = ir.clientsIntended
		ir.clientsUnsynced = false
		ir.clientsIntended = nil
		return nil
	}
	if _, err := ir.publishRegistryFileLocked(ir.clients); err != nil {
		return fmt.Errorf("registry from an earlier failed write is still not durable: %w", err)
	}
	return nil
}

// publishRegistryFileLocked writes reg durably and installs it as the
// runtime view. On failure the view follows the file, whichever registry it
// now holds, and the registry is marked as needing a successful sync;
// applied then reports whether the file, and so the view, holds reg.
func (ir *Runtime) publishRegistryFileLocked(reg *clientregistry.Registry) (applied bool, err error) {
	if err := clientregistry.Publish(ir.AuthorizedKeysPath(), reg); err != nil {
		ir.clientsUnsynced = true
		reloaded, loadErr := clientregistry.Load(ir.AuthorizedKeysPath())
		if loadErr != nil {
			// The file holds the old registry or reg, and which cannot be
			// known: refuse every key until it can be read, and commit to
			// reg, which the next registry operation publishes.
			ir.clients, _ = clientregistry.Parse(nil)
			ir.clientsIntended = reg
			return true, fmt.Errorf("%w (registry unreadable after the failed publish, all client keys refused until it is repaired: %v)", err, loadErr)
		}
		ir.clients = reloaded
		ir.clientsIntended = nil
		return bytes.Equal(reloaded.Marshal(), reg.Marshal()), err
	}
	ir.clients = reg
	ir.clientsUnsynced = false
	ir.clientsIntended = nil
	return true, nil
}

// EnrollAuthorizedKey enrolls key with a display label and reports whether
// the key is now enrolled when it was not before. Enrolling a key that is
// already enrolled changes nothing and writes nothing. enrolled can be true
// alongside an error wrapping ErrAppliedNotDurable: the key is then usable
// and the caller audits the enrollment even though the write is not durable.
func (ir *Runtime) EnrollAuthorizedKey(key ssh.PublicKey, label string) (enrolled bool, err error) {
	return ir.publishRegistry(func(current *clientregistry.Registry) (*clientregistry.Registry, bool, error) {
		next, added := current.WithKey(key, label)
		return next, added, nil
	})
}

// RevokeAuthorizedKey removes the key with the given fingerprint from the
// registry and returns its entry. revoked reports that the live view no
// longer holds the key, which can hold alongside an error wrapping
// ErrAppliedNotDurable; the caller then closes the key's connections and
// audits the revocation regardless. A connection authenticating meanwhile
// re-checks enrollment against the installed view and is refused.
func (ir *Runtime) RevokeAuthorizedKey(fingerprint string) (clientregistry.Entry, bool, error) {
	var found clientregistry.Entry
	revoked, err := ir.publishRegistry(func(current *clientregistry.Registry) (*clientregistry.Registry, bool, error) {
		entry, ok := current.LookupFingerprint(fingerprint)
		if !ok {
			return nil, false, clientregistry.ErrNotEnrolled
		}
		found = entry
		next, err := current.WithoutFingerprint(fingerprint)
		if err != nil {
			return nil, false, err
		}
		return next, true, nil
	})
	return found, revoked, err
}

// RevokeAllAuthorizedKeys empties the registry and returns the entries it
// held. revoked has the same meaning as for RevokeAuthorizedKey.
func (ir *Runtime) RevokeAllAuthorizedKeys() (entries []clientregistry.Entry, revoked bool, err error) {
	revoked, err = ir.publishRegistry(func(current *clientregistry.Registry) (*clientregistry.Registry, bool, error) {
		entries = current.Entries()
		if len(entries) == 0 {
			return current, false, nil
		}
		next, _ := clientregistry.Parse(nil)
		return next, true, nil
	})
	return entries, revoked, err
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
// with clientsMu held. It follows the registry rule: a publish that fails
// after its rename installs the queue the file now holds and, when that is
// next, reports the change as applied with an error wrapping
// ErrAppliedNotDurable, so the caller records the change separately from
// its durability outcome.
func (ir *Runtime) publishQueueLocked(next *enrollqueue.Queue) error {
	applied, err := ir.publishQueueFileLocked(next)
	if err != nil && applied {
		return fmt.Errorf("%w: %w", ErrAppliedNotDurable, err)
	}
	return err
}

// publishQueueFileLocked writes next durably and installs it. On failure
// the view follows the file, whichever queue it now holds, and the queue is
// marked as needing a successful sync; applied then reports whether the
// file, and so the view, holds next.
func (ir *Runtime) publishQueueFileLocked(next *enrollqueue.Queue) (applied bool, err error) {
	if err := enrollqueue.Publish(ir.PendingEnrollmentsPath(), next); err != nil {
		// As for the registry: the file is either the old queue or the new
		// one, so serve what it holds; an unreadable queue holds nothing.
		// Either way it may not be durable, which the next queue operation
		// repairs before acknowledging anything.
		ir.pendingUnsynced = true
		now := time.Now()
		reloaded, loadErr := enrollqueue.Load(ir.PendingEnrollmentsPath(), now)
		if loadErr != nil {
			// As for the registry: commit to next, which the next queue
			// operation publishes once the file reads again.
			ir.pending = &enrollqueue.Queue{}
			ir.pendingIntended = next
			return true, fmt.Errorf("%w (queue unreadable after the failed publish, waiting requests hidden until it is repaired: %v)", err, loadErr)
		}
		ir.pending = reloaded
		ir.pendingIntended = nil
		return bytes.Equal(reloaded.Marshal(), next.Pruned(now).Marshal()), err
	}
	ir.pending = next
	ir.pendingUnsynced = false
	ir.pendingIntended = nil
	return true, nil
}

// ensureQueueDurableLocked re-publishes the queue left by an earlier failed
// write, so a retried operation is acknowledged only once the file is
// durable rather than on the strength of the unsynced file. Its failure
// never wraps ErrAppliedNotDurable: the change it re-publishes was reported
// when it was made.
func (ir *Runtime) ensureQueueDurableLocked() error {
	if !ir.pendingUnsynced {
		return nil
	}
	if ir.pendingIntended != nil {
		// As for the registry: the empty queue held is a placeholder, and
		// publishing it would drop every waiting request from the file.
		if _, err := enrollqueue.Load(ir.PendingEnrollmentsPath(), time.Now()); err != nil {
			return fmt.Errorf("enrollment queue is unreadable after an earlier failed write; repair %s: %w", ir.PendingEnrollmentsPath(), err)
		}
		if err := enrollqueue.Publish(ir.PendingEnrollmentsPath(), ir.pendingIntended); err != nil {
			// As for the registry: keep the commitment rather than adopt
			// what the file holds, which could bring back a cleared request.
			return fmt.Errorf("enrollment queue from an earlier failed write is still not durable: %w", err)
		}
		ir.pending = ir.pendingIntended
		ir.pendingUnsynced = false
		ir.pendingIntended = nil
		return nil
	}
	if _, err := ir.publishQueueFileLocked(ir.pending); err != nil {
		return fmt.Errorf("enrollment queue from an earlier failed write is still not durable: %w", err)
	}
	return nil
}

// QueueEnrollment records a client's request to be enrolled. A key that is
// already enrolled is reported as such and nothing is queued; otherwise the
// request waits for the operator, and added reports whether it was new
// rather than a refresh of a request already waiting. enrollqueue.ErrQueueFull
// refuses a new request when the queue is at its cap. A request that is
// queued by a write that is not yet durable is reported as pending together
// with an error wrapping ErrAppliedNotDurable.
func (ir *Runtime) QueueEnrollment(key ssh.PublicKey, label, remoteAddr string) (pending bool, added bool, err error) {
	ir.clientsMu.Lock()
	defer ir.clientsMu.Unlock()
	// "Already enrolled" is a success answer read from the registry, so it
	// is given only once the registry is durable.
	if err := ir.ensureRegistryDurableLocked(); err != nil {
		return false, false, err
	}
	if ir.clients.Has(key) {
		return false, false, nil
	}
	if err := ir.ensureQueueDurableLocked(); err != nil {
		return false, false, err
	}
	next, _, added, err := ir.pending.WithRequest(key, label, remoteAddr, time.Now())
	if err != nil {
		return false, false, err
	}
	if err := ir.publishQueueLocked(next); err != nil {
		if errors.Is(err, ErrAppliedNotDurable) {
			return true, added, err
		}
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
// request. label, when set, replaces the label the client asked for.
// enrolled reports that the key is now in the live registry when it was not
// before, and cleared that the request is now gone from the live queue; the
// caller audits the enrollment and announces either change whether or not
// err is set. The registry is published before the queue, and a registry
// write that is not yet durable (err wrapping ErrAppliedNotDurable) still
// goes on to clear the request, so only a failure of the queue write itself
// leaves an enrolled key whose request is still listed. Approving it again
// is a no-op for the registry and clears the request; rejecting it is
// refused with ErrAlreadyEnrolled.
func (ir *Runtime) ApproveEnrollment(fingerprint, label string) (entry enrollqueue.Entry, enrolled, cleared bool, err error) {
	ir.clientsMu.Lock()
	defer ir.clientsMu.Unlock()
	if err := ir.ensureQueueDurableLocked(); err != nil {
		return enrollqueue.Entry{}, false, false, err
	}
	entry, ok := ir.pending.Pruned(time.Now()).Lookup(fingerprint)
	if !ok {
		return enrollqueue.Entry{}, false, false, enrollqueue.ErrNotPending
	}
	if label == "" {
		label = entry.Label
	}
	entry.Label = label
	enrolled, registryErr := ir.publishRegistryLocked(func(current *clientregistry.Registry) (*clientregistry.Registry, bool, error) {
		next, added := current.WithKey(entry.Key, label)
		return next, added, nil
	})
	if registryErr != nil && !errors.Is(registryErr, ErrAppliedNotDurable) {
		return entry, enrolled, false, registryErr
	}
	next, _, err := ir.pending.WithoutFingerprint(fingerprint)
	if err != nil {
		return entry, enrolled, false, err
	}
	if err := ir.publishQueueLocked(next); err != nil {
		cleared = errors.Is(err, ErrAppliedNotDurable)
		if registryErr != nil {
			return entry, enrolled, cleared, fmt.Errorf("%w; clearing the request also failed: %v", registryErr, err)
		}
		return entry, enrolled, cleared, err
	}
	return entry, enrolled, true, registryErr
}

// RejectEnrollment removes a pending request without enrolling its key.
// rejected reports that the request is gone from the live queue, which can
// hold alongside an error wrapping ErrAppliedNotDurable; the caller audits
// the rejection regardless. A request whose key is already enrolled is
// refused with ErrAlreadyEnrolled rather than silently left enrolled.
func (ir *Runtime) RejectEnrollment(fingerprint string) (entry enrollqueue.Entry, rejected bool, err error) {
	ir.clientsMu.Lock()
	defer ir.clientsMu.Unlock()
	if err := ir.ensureQueueDurableLocked(); err != nil {
		return enrollqueue.Entry{}, false, err
	}
	// The already-enrolled check reads the registry, so it must be the
	// registry and not the placeholder an unreadable file leaves.
	if err := ir.ensureRegistryDurableLocked(); err != nil {
		return enrollqueue.Entry{}, false, err
	}
	next, entry, err := ir.pending.WithoutFingerprint(fingerprint)
	if err != nil {
		return enrollqueue.Entry{}, false, err
	}
	if ir.clients.Has(entry.Key) {
		return entry, false, ErrAlreadyEnrolled
	}
	if err := ir.publishQueueLocked(next); err != nil {
		return entry, errors.Is(err, ErrAppliedNotDurable), err
	}
	return entry, true, nil
}

// ImportClientKey enrolls a public key the operator supplied directly, the
// pre-enrollment path. A pending request for the same key is cleared. added
// reports whether the key is now in the live registry when it was not
// before, and cleared that a waiting request for it is now gone from the
// live queue; as for ApproveEnrollment the caller audits the enrollment and
// announces either change whether or not err is set, and a registry write
// that is not yet durable (err wrapping ErrAppliedNotDurable) still goes on
// to clear the request.
func (ir *Runtime) ImportClientKey(key ssh.PublicKey, label string) (added, cleared bool, err error) {
	ir.clientsMu.Lock()
	defer ir.clientsMu.Unlock()
	if err := ir.ensureQueueDurableLocked(); err != nil {
		return false, false, err
	}
	added, registryErr := ir.publishRegistryLocked(func(current *clientregistry.Registry) (*clientregistry.Registry, bool, error) {
		next, added := current.WithKey(key, label)
		return next, added, nil
	})
	if registryErr != nil && !errors.Is(registryErr, ErrAppliedNotDurable) {
		return added, false, registryErr
	}
	if next, _, err := ir.pending.WithoutFingerprint(ssh.FingerprintSHA256(key)); err == nil {
		if err := ir.publishQueueLocked(next); err != nil {
			cleared = errors.Is(err, ErrAppliedNotDurable)
			if registryErr != nil {
				return added, cleared, fmt.Errorf("%w; clearing the request also failed: %v", registryErr, err)
			}
			return added, cleared, err
		}
		cleared = true
	}
	return added, cleared, registryErr
}

// --- Key access ---

// KnownAddresses returns every address this identity holds an aplane key
// for, of any key type: the set the rekey warning reads.
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
// The value starts at a random point on process start and increments after each
// successful snapshot publish; clients compare it for equality only.
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
		v.SigningArgs = slices.Clone(v.SigningArgs)
		if v.LogicSigResources != nil {
			cloned := v.LogicSigResources.Clone()
			v.LogicSigResources = &cloned
		}
		snapshot.KeyMetadata[k] = v
	}
	return snapshot
}

// KeySnapshot returns copies of the two key index maps only — callers that
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
		metadata = keyMetadataOf(ir.keyStore.GetSigningSummary(), ir.keyStore.GetPublicKeyHexMap())
	}
	ir.setKeyMaps(keys, keyTypes, metadata)
}

// publishKeys replaces the key maps with the ones contents gives, and
// returns how many keys it holds.
func (ir *Runtime) publishKeys(contents keystore.Contents) int {
	keys := contents.KeyFiles()
	ir.setKeyMaps(keys, contents.KeyTypes(), keyMetadataOf(contents.SigningSummaries(), contents.PublicKeyHexes()))
	return len(keys)
}

func (ir *Runtime) setKeyMaps(keys, keyTypes map[string]string, metadata map[string]KeyPublicMetadata) {
	ir.keysLock.Lock()
	ir.keys = keys
	ir.keyTypes = keyTypes
	ir.keyMetadata = metadata
	ir.keysetRev.Add(1)
	ir.keysLock.Unlock()
}

// keyMetadataOf builds each key's public metadata. The summaries are fresh
// caller-owned copies, so their maps are adopted without another clone.
func keyMetadataOf(summaries map[string]keystore.SigningSummary, publicKeys map[string]string) map[string]KeyPublicMetadata {
	metadata := make(map[string]KeyPublicMetadata, len(summaries))
	for selector, summary := range summaries {
		metadata[selector] = KeyPublicMetadata{
			Category: summary.Category, BaseKeyType: summary.BaseKeyType, PublicKeyHex: publicKeys[selector], Parameters: summary.Parameters,
			BoundedAuthorization: summary.BoundedAuthorization,
			LogicSigResources:    summary.LogicSigResources,
			SigningArgs:          summary.SigningArgs,
			ValidRekeyTarget:     summary.ValidRekeyTarget,
		}
	}
	return metadata
}

// --- KeyStore access ---

// ProviderRegistry is the LogicSig provider registry this runtime's reloads
// register templates in and read from. It is the process-wide registry: key
// type names are shared by every identity in the process. A reload reaches
// the registry through it alone, so a registry per identity can replace it.
func (ir *Runtime) ProviderRegistry() signertemplates.ProviderRegistry {
	return ir.providers
}

// KeyStore returns the underlying file key store.
func (ir *Runtime) KeyStore() *keystore.FileKeyStore {
	return ir.keyStore
}

// KeyPaths returns the keystore path configuration.
func (ir *Runtime) KeyPaths() storepaths.Paths {
	return ir.keyPaths
}

// StageTables returns the owner of rotating accounts' stage address tables.
func (ir *Runtime) StageTables() *stagetable.Store {
	return ir.stageTables
}

// SetRotatingStatus replaces the published rotating account warnings, notes
// and per-account status and reports whether the warnings or notes changed.
// The per-account status is always replaced: its counters move on every
// pass, and they are not what apadmin is notified about.
func (ir *Runtime) SetRotatingStatus(warnings, notes []string, accounts []signerapi.RotatingAccountStatus) bool {
	ir.rotatingStatusMu.Lock()
	defer ir.rotatingStatusMu.Unlock()
	ir.rotatingAccounts = slices.Clone(accounts)
	if slices.Equal(ir.rotatingAlerts, warnings) && slices.Equal(ir.rotatingNotes, notes) {
		return false
	}
	ir.rotatingAlerts = slices.Clone(warnings)
	ir.rotatingNotes = slices.Clone(notes)
	return true
}

// PublishRotatingStatus is SetRotatingStatus for a stage table pass that ran
// in the unlocked session generation names. It publishes only while that
// session is still the current one, checked together with the write, so a
// pass that a lock overtook publishes nothing: the lock's cancellation
// reaches the pass's context after the lock itself, and the context alone
// does not say the session is over. published reports whether the status was
// written, changed whether its warnings or notes differ from before.
func (ir *Runtime) PublishRotatingStatus(generation uint64, warnings, notes []string, accounts []signerapi.RotatingAccountStatus) (changed, published bool) {
	published = ir.lockRuntime.WhileGeneration(generation, func() {
		changed = ir.SetRotatingStatus(warnings, notes, accounts)
	})
	return changed, published
}

// RotatingAccountStatuses returns the per-account rotating status from the
// last pass.
func (ir *Runtime) RotatingAccountStatuses() []signerapi.RotatingAccountStatus {
	ir.rotatingStatusMu.Lock()
	defer ir.rotatingStatusMu.Unlock()
	return slices.Clone(ir.rotatingAccounts)
}

// RotatingAlerts returns the rotating account warnings from the last pass.
func (ir *Runtime) RotatingAlerts() []string {
	ir.rotatingStatusMu.Lock()
	defer ir.rotatingStatusMu.Unlock()
	return slices.Clone(ir.rotatingAlerts)
}

// RotatingNotes returns the rotating account notes from the last pass.
func (ir *Runtime) RotatingNotes() []string {
	ir.rotatingStatusMu.Lock()
	defer ir.rotatingStatusMu.Unlock()
	return slices.Clone(ir.rotatingNotes)
}

// keyUseDrainWarnAfter is how long Lock waits for key users before it says
// so. It keeps waiting: a lock that returned while a seed was still in
// memory would be a lie, so a user that fails to release stalls the lock
// visibly rather than letting it complete. Users hold key material only
// across its load and derivations, never across a disk write; the one network
// read inside a window (a stateless-hash rotating sign's last chain read) runs
// under the key-use context, which the lock cancels. In practice the wait is
// one derivation.
const keyUseDrainWarnAfter = 5 * time.Second

// KeyUseContext registers a holder of loaded key material. The
// returned context is cancelled the moment the signer locks, and release must
// be called once the caller holds no key material; Lock waits for every
// registered user to release before it clears the session. While the signer
// is locked, and once EndKeyUses has begun, the returned context is already
// cancelled and release is a no-op.
func (ir *Runtime) KeyUseContext(parent context.Context) (context.Context, func()) {
	if parent == nil {
		parent = context.Background()
	}
	ir.keyUseMu.Lock()
	if ir.destroyed || !ir.IsUnlocked() {
		ir.keyUseMu.Unlock()
		ctx, cancel := context.WithCancel(parent)
		cancel()
		return ctx, func() {}
	}
	if ir.keyUseCtx == nil || ir.keyUseCtx.Err() != nil {
		ir.keyUseCtx, ir.keyUseCancel = context.WithCancel(context.Background())
	}
	base := ir.keyUseCtx
	ir.keyUsers.Add(1)
	ir.keyUseMu.Unlock()

	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(base, cancel)
	var once sync.Once
	return ctx, func() {
		once.Do(func() {
			stop()
			cancel()
			ir.keyUsers.Done()
		})
	}
}

// LockCancelContext returns a context that is cancelled when the signer
// locks, without registering a key user: Lock does not wait for it. It is
// for work that must stop at lock but holds no key material, such as a
// background pass's chain reads and pacing sleeps. While the signer is
// locked, and once EndKeyUses has begun, the returned context is already
// cancelled.
func (ir *Runtime) LockCancelContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	ir.keyUseMu.Lock()
	if ir.destroyed || !ir.IsUnlocked() {
		ir.keyUseMu.Unlock()
		cancel()
		return ctx, cancel
	}
	if ir.keyUseCtx == nil || ir.keyUseCtx.Err() != nil {
		ir.keyUseCtx, ir.keyUseCancel = context.WithCancel(context.Background())
	}
	base := ir.keyUseCtx
	ir.keyUseMu.Unlock()
	stop := context.AfterFunc(base, cancel)
	return ctx, func() { stop(); cancel() }
}

// cancelKeyUses cancels, under keyUseMu, the contexts of the key uses and
// lock-cancel contexts handed out, without waiting for them.
func (ir *Runtime) cancelKeyUses() {
	ir.keyUseMu.Lock()
	if ir.keyUseCancel != nil {
		ir.keyUseCancel()
	}
	ir.keyUseMu.Unlock()
}

// drainKeyUsers cancels every key user's context and waits for them to
// release their key material. Its caller has already made KeyUseContext
// refuse new users, so none can register meanwhile: a lock runs it inside the
// lock transition, after the state is locked, and EndKeyUses after setting
// destroyed. A lock gives it a context that never ends and waits for as long
// as it takes, printing warning if that is more than keyUseDrainWarnAfter.
// Only EndKeyUses bounds the wait; drainKeyUsers reports whether every user had
// released by the time ctx ended.
func (ir *Runtime) drainKeyUsers(ctx context.Context, warning string) bool {
	ir.cancelKeyUses()

	done := make(chan struct{})
	go func() {
		ir.keyUsers.Wait()
		close(done)
	}()
	var warnAfter <-chan time.Time
	if warning != "" {
		warn := time.NewTimer(keyUseDrainWarnAfter)
		defer warn.Stop()
		warnAfter = warn.C
	}
	for {
		select {
		case <-done:
			return true
		case <-warnAfter:
			fmt.Printf("⚠️  Warning: %s\n", warning)
		case <-ctx.Done():
			select {
			case <-done:
				return true
			default:
				return false
			}
		}
	}
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

// IsContentDefect reports whether a reload failed for a content defect in
// the selected generation: one that fails its validation, or two key files
// that resolve to one address. Reload enters recovery for one.
func IsContentDefect(err error) bool {
	return signertemplates.IsGenerationValidationErr(err) || errors.Is(err, apkeys.ErrAddressCollision)
}

// ReloadWithPassphrase builds the generation the store root selects with a
// keyring opened from passphrase and installs it, keyring included: a
// passphrase change's republish, under store maintenance with the signer
// locked, before FinishStoreMaintenance. A build that fails installs
// nothing, and the keyring it opened is zeroed; a role conflict fails the
// node closed. Caller must NOT hold passphraseLock.
func (ir *Runtime) ReloadWithPassphrase(passphrase []byte) (*signertemplates.ReloadReport, error) {
	owned, loaded, err := ir.buildWithPassphrase(passphrase)
	if err != nil {
		end := buildEnd(loaded, err)
		loaded.Discard()
		if owned != nil {
			owned.Zero()
		}
		ir.afterReload(end)
		return nil, err
	}
	report := ir.publishUnlock(owned, loaded)
	ir.afterReload(reloadEnd{published: true, keyCount: report.KeyCount, notices: report.TemplateNotices, warnings: report.TemplateWarnings, rejected: rejectedLogicSigKeys(loaded.Contents)})
	return report, nil
}

// --- Watcher ---

// EnsureKeyWatcher starts the file watcher if not already running.
// Watches the keys directory and key type state/template records.
// The watcher stays running across lock/unlock transitions: when unlocked
// it reloads immediately; when locked or in recovery it marks the identity
// dirty for reconciliation on the next unlock (reloadFromWatcher).
// If the identity was marked dirty, it reconciles at once on an unlocked
// signer and leaves it marked otherwise.
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
	// capability. The identity directory observes store-root replacement.
	// fsnotify watches bind to inodes, so a root commit leaves these watches
	// on the superseded generation until a caller re-arms the watcher
	// (restore, rollback, and reconcile do).
	dirs := []string{ir.keyPaths.ProductDir()}
	if active, err := ir.ActivePaths(); err == nil {
		dirs = append(dirs, active.KeysDir(), active.KeyTypeRecordsDir())
	} else {
		fmt.Printf("⚠️  Warning: cannot watch the active generation's keys: %v\n", err)
		fmt.Println("Only store-root replacement will trigger a key reload")
	}

	// The reload callback either reloads (if unlocked) or marks dirty
	// (otherwise), deciding under the store mutation lock.
	reloadOrDirty := func() error {
		_, err := ir.reloadFromWatcher()
		return err
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
	switch reloaded, err := ir.reloadFromWatcher(); {
	case err != nil:
		fmt.Printf("⚠️  Dirty-state reconciliation failed for product store: %v\n", err)
	case reloaded:
		fmt.Println("✓ Reconciled pending filesystem changes for product store")
	}
}

// reloadFromWatcher reloads for a change the watcher saw, or, on a signer
// not unlocked, marks the store dirty for the next unlock that publishes to
// reconcile. It reports whether it reloaded. It checks the state under the
// store mutation lock, as every other caller of Reload does: a lock can land
// while it waits for the lock, and the next unlock reconciles what the
// watcher saw. A reload that finds the root moved, or a defect, enters
// recovery by the failure rule.
func (ir *Runtime) reloadFromWatcher() (bool, error) {
	release := ir.lockStoreMutation()
	defer release()
	if !ir.IsUnlocked() {
		ir.MarkDirty()
		return false, nil
	}
	_, err := ir.Reload()
	return true, err
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

// ErrInvalidPassphrase is an unlock's failure for the request's passphrase:
// it does not open the store root. It reads "invalid passphrase", the text
// the admin client shows, and is crypto.ErrInvalidPassphrase to errors.Is.
// A load that fails because the store root no longer opens with a passphrase
// already checked wraps crypto.ErrInvalidPassphrase but is not this: it is a
// failed unlock, not a wrong passphrase.
var ErrInvalidPassphrase error = invalidPassphrase{}

type invalidPassphrase struct{}

func (invalidPassphrase) Error() string { return "invalid passphrase" }
func (invalidPassphrase) Unwrap() error { return crypto.ErrInvalidPassphrase }

// unlockFailure classifies a store-root open error for an unlock: a
// passphrase that does not open the root is ErrInvalidPassphrase, and any other
// failure (an unreadable or damaged root) keeps its cause, so it is reported
// as a failed unlock rather than a wrong passphrase.
func unlockFailure(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, crypto.ErrInvalidPassphrase):
		return ErrInvalidPassphrase
	default:
		return fmt.Errorf("store root could not be opened: %w", err)
	}
}

// ErrKeyUseInFlight reports a key user that still held its own copy of key
// material when EndKeyUses stopped waiting for it.
var ErrKeyUseInFlight = errors.New("a key use still held key material at the shutdown deadline")

// EndKeyUses is the bounded first step of shutdown. It stops the key watcher
// and makes KeyUseContext refuse every new key use, as a lock does, without
// locking the signer (which would run the lock cleanup and its unbounded
// drain). Then, like a lock, it cancels the registered key users and waits for
// them to release their key material, but only until ctx ends, since the
// process exits right after. It returns ErrKeyUseInFlight if one had not
// released by then. Destroy follows it.
func (ir *Runtime) EndKeyUses(ctx context.Context) error {
	ir.refuseKeyUses()
	if !ir.drainKeyUsers(ctx, "") {
		return ErrKeyUseInFlight
	}
	return nil
}

// refuseKeyUses stops the key watcher and makes KeyUseContext refuse every
// new key use from now on. It is idempotent.
func (ir *Runtime) refuseKeyUses() {
	ir.StopKeyWatcher()
	ir.keyUseMu.Lock()
	ir.destroyed = true
	ir.keyUseMu.Unlock()
}

// Destroy clears the session and zeroes the keyring for shutdown. It first
// stops the key watcher, refuses new key uses and cancels the ones already
// registered, as EndKeyUses does, so it is safe without EndKeyUses before it,
// but it does not wait for the registered key users: that bounded wait is
// EndKeyUses's, which shutdown runs first. It
// takes the passphrase lock, so a lock cleanup racing shutdown (an admin
// session closing on its way out) cannot interleave with it. That lock, the
// session's and the keystore's are taken without a bound: a holder stalled
// inside one (a decryption on a hung filesystem) holds Destroy, so shutdown
// records its stop before calling it.
//
// Clearing them under a key user still registered (one EndKeyUses gave up on,
// or any when Destroy runs alone) is safe: the user decrypted its own copy
// under the keystore's read lock (FileKeyStore.Get) or a counted reference
// (WithKeyring), both of which ClearKeys and the session's Destroy wait for,
// so it keeps working on that copy, and any load
// it starts afterward fails as locked. Its copy is zeroed when it releases,
// or reclaimed by the operating system at the process exit that follows. The
// source token index is retired the same way: a lookup still reading it keeps
// it intact until it releases, and it is zeroed then.
func (ir *Runtime) Destroy() {
	ir.refuseKeyUses()
	// As drainKeyUsers does first, without waiting for them.
	ir.cancelKeyUses()
	ir.passphraseLock.Lock()
	defer ir.passphraseLock.Unlock()
	if ir.keySession != nil {
		ir.keySession.Destroy()
	}
	if ir.keyStore != nil {
		ir.keyStore.ClearKeys()
	}
	ir.sourceTokens.Clear()
}

// --- Internal ---

func (ir *Runtime) performLockCleanup() {
	// Watcher stays running — it will mark dirty instead of reloading while locked.
	// StopKeyWatcher is only called on shutdown, by EndKeyUses and Destroy.

	// The session is over: withdraw every signing request in flight before
	// waiting for anything, so no approval stays up through the drain.
	ir.endSignRequests()

	// Holders of key material go first, so clearing the session
	// below really is the end of every copy of a seed.
	ir.drainKeyUsers(context.Background(), "lock is waiting for key users to release key material")

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
	// The drain above has ended every external check lookup, so nothing
	// reads the index and it is zeroed now. While locked there is none.
	ir.sourceTokens.Clear()
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

// IsUnlockedIn reports whether the signer is unlocked in the session
// generation names (LockGeneration): still unlocked, and not left and
// re-entered since, by a lock or by a recovery and a reconcile.
func (ir *Runtime) IsUnlockedIn(generation uint64) bool {
	return ir.lockRuntime.WhileGeneration(generation, func() {})
}

// UnlockedGeneration returns the session generation and whether the signer
// is unlocked in it, read together.
func (ir *Runtime) UnlockedGeneration() (uint64, bool) {
	return ir.lockRuntime.UnlockedGeneration()
}

// LockGeneration returns the lock runtime's session generation, advanced by
// every lock and maintenance transition and by every entry into recovery, one
// from recovery included. Per-session state is keyed by it.
func (ir *Runtime) LockGeneration() uint64 {
	return ir.lockRuntime.LockGeneration()
}

// openStoreRoot opens the store root with an unlock request's passphrase: the
// request's passphrase check for a signer that is not unlocked. Tests replace
// it to land a transition during the open.
var openStoreRoot = crypto.OpenStoreRootStore

// verifyUnlockPassphrase checks an unlock's passphrase against the store
// root, classified for the lock runtime as unlockFailure does. Tests replace
// it to land a transition during the check.
var verifyUnlockPassphrase = func(passphrase []byte, paths storepaths.Paths) error {
	return unlockFailure(crypto.VerifyPassphraseWithStoreRoot(passphrase, paths.ProductDir()))
}

// lockStoreMutation takes the process-wide store mutation lock, when the
// process root has set one (SetReloadMutationLock), and returns its release.
func (ir *Runtime) lockStoreMutation() (release func()) {
	ir.watcherMu.Lock()
	lockFn := ir.reloadLock
	ir.watcherMu.Unlock()
	if lockFn == nil {
		return func() {}
	}
	lock := lockFn()
	if lock == nil {
		return func() {}
	}
	lock.Lock()
	return lock.Unlock
}

// WakeStageWork requests a discovery pass after inventory or recovery changes.
func (ir *Runtime) WakeStageWork() {
	select {
	case ir.stageWork <- struct{}{}:
	default:
	}
}
func (ir *Runtime) StageWork() <-chan struct{} { return ir.stageWork }
