// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package productruntime

import (
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/internal/asaset"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keyclass"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
	signerruntime "github.com/aplane-algo/aplane/internal/signerapp/runtime"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/sourcetokens"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// Loaded is one consistent view of the generation the store root selects,
// built whole before any of it is installed (BuildFunc) and installed whole
// by a publish. It owns the source token index it holds until a publish takes
// it or Discard zeroes it.
type Loaded struct {
	// Selection is the generation the store root selected, authenticated;
	// nil when the root did not authenticate.
	Selection *storepaths.GenPaths
	// PolicyVerified is set once Policy, ASASet and Alerts are verified for
	// Selection.
	PolicyVerified bool
	Policy         *policyruntime.NodePolicy
	ASASet         *asaset.Set
	Alerts         []string
	Tokens         *sourcetokens.Index
	// Templates are the generation's templates prepared and checked, with
	// nothing registered.
	Templates signertemplates.PreparedTemplates
	// Contents is the key scan, with the selection it was bound to.
	Contents keystore.Contents
}

// Discard zeroes what l owns, its token index, for a Loaded that is not
// published.
func (l *Loaded) Discard() {
	if l != nil {
		l.Tokens.Discard()
		l.Tokens = nil
	}
}

// BuildFunc builds the generation the store root selects with kr, the keyring
// in service, and changes no live state: it registers no provider, writes no
// audit record and notifies no one. On a failure it returns, with the error,
// what it had established: the selection when the root authenticated, and
// the policy when it verified it.
type BuildFunc func(kr *crypto.Keyring) (*Loaded, error)

// ReloadEffects are what a reload tells the process after its locks are
// released.
type ReloadEffects struct {
	Audit             signertemplates.AuditLogger
	NotifyKeysChanged func(keyCount int)
	Info              func(string)
	Warn              func(string)
	// NodeFailClosed fails the node closed for a role conflict a build
	// found.
	NodeFailClosed func(error)
}

// SetBuildFunc sets the build a reload runs and what it tells the process.
// The process root wires it (startup.WireReloadFunc); tests inject a build
// result through it.
func (ir *Runtime) SetBuildFunc(fn BuildFunc, effects ReloadEffects) {
	ir.passphraseLock.Lock()
	ir.buildFn = fn
	ir.reloadEffects = effects
	ir.passphraseLock.Unlock()
}

// ErrReconcileStateChanged reports that a lock overtook the reconcile
// (during its store step, build, or promotion); the lock stands.
var ErrReconcileStateChanged = errors.New("a lock overtook store reconciliation")

// ErrEnteredRecovery marks a reload's failure that ended in recovery's view:
// a role conflict, a store in doubt, a root that moved or does not
// authenticate, or a content defect (reloadView). errors.Is finds it on the
// error a reload returns; the error reads as its cause. A failure that kept
// the view in service, or that met a locked signer, does not carry it.
var ErrEnteredRecovery = errors.New("the reload entered recovery")

type enteredRecovery struct{ error }

func (e enteredRecovery) Unwrap() error        { return e.error }
func (e enteredRecovery) Is(target error) bool { return target == ErrEnteredRecovery }

// errBuildNotConfigured is the build failure of a runtime no build was
// wired into.
var errBuildNotConfigured = errors.New("build function not configured")

// errCommitUncertain is the cause of the recovery an uncertain store-root
// commit enters.
var errCommitUncertain = errors.New("the store-root commit may or may not have landed")

// reloadMode is what a reload's caller knows about the store.
type reloadMode struct {
	// inDoubt: the caller found the store in doubt, for cause, so the reload
	// ends in recovery whatever its build returns.
	inDoubt bool
	cause   error
	// reconcile: a reconcile's reload, which publishes the whole view in
	// recovery too, and then promotes recovery to unlocked when it began in
	// recovery (fromRecovery) or finds the signer still unlocked.
	reconcile    bool
	fromRecovery bool
	// failureInDoubt: a build that fails leaves the store in doubt (an
	// explicit reconcile's).
	failureInDoubt bool
}

// reloadEnd is what a reload did under passphraseLock, for the steps that
// follow its release.
type reloadEnd struct {
	report *signertemplates.ReloadReport
	err    error
	// published: the whole view, with keyCount keys.
	published bool
	keyCount  int
	// recovery: the reload entered recovery, for cause.
	recovery   bool
	cause      error
	failClosed error
	notices    []string
	warnings   []string
	rejected   []apkeys.KeyScanWarning
	detached   []keystore.DetachedKeyring
}

// FollowCommit brings the runtime onto what a store-root commit left the
// root selecting (genstore.MintOutcomeOf). The caller holds the store
// mutation lock, and calls it after its WithKeyring callback has returned.
//
// After an uncertain commit the reload ends in recovery whatever its build
// finds, with the recovery view of what the root now selects. After a commit
// that landed it publishes the new generation; a build that fails there
// enters recovery, because the root has moved off the generation in service
// (reloadView). It returns the reload's report and, for a commit that
// landed, its error. A commit that did not happen needs nothing.
func (ir *Runtime) FollowCommit(outcome genstore.MintOutcome) (*signertemplates.ReloadReport, error) {
	switch outcome {
	case genstore.Uncertain:
		report, _ := ir.reloadView(reloadMode{inDoubt: true, cause: errCommitUncertain})
		return report, nil
	case genstore.Committed:
		return ir.Reload()
	}
	return nil, nil
}

// Reload builds the generation the store root selects with the keyring in
// service and publishes it, or publishes recovery's view or keeps the view
// in service, by the failure rule (reloadView); no passphrase is needed. A
// failure that entered recovery carries ErrEnteredRecovery. The caller holds
// the store mutation lock: an admin change that wrote the store, or the
// watcher (reloadFromWatcher), which takes it itself.
func (ir *Runtime) Reload() (*signertemplates.ReloadReport, error) {
	return ir.reloadView(reloadMode{})
}

// Reconcile runs step, the store's reconcile, with the keyring in service,
// then builds and publishes what the store root selects and promotes
// recovery to unlocked. The caller holds the store mutation lock and has
// checked that the signer is unlocked or in recovery.
//
// explicit is the explicit reconcile, which may start unlocked: any failure
// there leaves the store in doubt, and it ends in recovery, with the recovery
// view of what the root selects, before the lock is released (RB2). The
// rescan after a restore passes false: it starts in recovery and stays there
// on a failure. A lock that overtakes the reconcile during its step, build, or
// promotion returns ErrReconcileStateChanged; the lock stands.
func (ir *Runtime) Reconcile(step func(*crypto.Keyring) error, explicit bool) (*signertemplates.ReloadReport, error) {
	// Under the store mutation lock the state can only move to locked.
	fromRecovery := ir.IsRecovery()
	if err := ir.WithKeyring(step); err != nil {
		if explicit {
			_, _ = ir.reloadView(reloadMode{inDoubt: true, cause: err})
		}
		if ir.GetState() == signerruntime.SignerStateLocked {
			return nil, ErrReconcileStateChanged
		}
		return nil, err
	}
	report, err := ir.reloadView(reloadMode{reconcile: true, fromRecovery: fromRecovery, failureInDoubt: explicit})
	if err != nil {
		if errors.Is(err, ErrReconcileStateChanged) || ir.GetState() == signerruntime.SignerStateLocked {
			return report, ErrReconcileStateChanged
		}
		return report, fmt.Errorf("current generation failed credential reload: %w", err)
	}
	return report, nil
}

// EnterRecovery enters recovery with the view in service: the keyring, the
// binding and the policy stay, and the keys and the source token index go.
// A locked signer stays locked. Once in recovery it calls the hook
// SetReloadRecoveryHook set, with cause. No production path calls it: every
// entry into recovery outside an unlock comes from a reload's failure rule.
// Tests use it to set up a signer in recovery; test/arch keeps it out of
// production code.
func (ir *Runtime) EnterRecovery(cause error) {
	ir.passphraseLock.RLock()
	var kr *crypto.Keyring
	var view recoveryView
	if ir.keyStore != nil {
		_ = ir.keyStore.WithKeyring(func(inService *crypto.Keyring) error {
			kr = inService
			return nil
		})
		if bound, err := ir.keyStore.ActivePaths(); err == nil {
			view.selection = &bound
		}
	}
	view.policy, view.asaSet = ir.PolicyState()
	view.alerts = ir.PolicyAlerts()
	end := reloadEnd{cause: cause}
	var detached keystore.DetachedKeyring
	end.recovery, detached = ir.enterRecoveryViewLocked(kr, view)
	end.detached = []keystore.DetachedKeyring{detached}
	ir.passphraseLock.RUnlock()
	ir.afterReload(end)
}

// reloadView builds the generation the store root selects with the keyring
// in service and publishes it, or the recovery view the failure rule picks.
// The caller holds the store mutation lock.
//
// The failure rule, decided by facts, for a build that failed or a store in
// doubt:
//
//  1. a role conflict fails the node closed and enters recovery;
//  2. a store in doubt enters recovery;
//  3. a root that selects another generation than the one bound, or that
//     does not authenticate, enters recovery bound to what it selects, or to
//     nothing: the view in service is the superseded generation's;
//  4. a content defect in the selected generation enters recovery;
//  5. anything else keeps the view in service and returns the error.
//
// The recovery view is bound to the build's selection, shows its policy
// when the build verified it and none otherwise, and holds no keys and no
// token index.
func (ir *Runtime) reloadView(mode reloadMode) (*signertemplates.ReloadReport, error) {
	ir.passphraseLock.RLock()
	end := ir.reloadViewLocked(mode)
	ir.passphraseLock.RUnlock()
	for _, detached := range end.detached {
		detached.ZeroWhenUnused()
	}
	end.detached = nil
	if end.recovery && end.err != nil {
		end.err = enteredRecovery{end.err}
	}
	if mode.reconcile && end.published {
		promoted := ir.IsUnlocked()
		if mode.fromRecovery {
			promoted = ir.PromoteRecoveryToUnlocked()
		}
		if !promoted {
			end.err = ErrReconcileStateChanged
		}
	}
	ir.afterReload(end)
	return end.report, end.err
}

// reloadViewLocked is reloadView's work under passphraseLock, held for
// reading from taking the keyring in service to the end of the install: a
// lock's cleanup, which takes it for writing, lands wholly before or after,
// and never finds a built token index left in memory.
func (ir *Runtime) reloadViewLocked(mode reloadMode) reloadEnd {
	if ir.keyStore == nil {
		return reloadEnd{err: errBuildNotConfigured}
	}
	// A runtime with no build fails every build, having established
	// nothing, so the failure rule fails it closed.
	build := ir.buildFn
	if build == nil {
		build = func(*crypto.Keyring) (*Loaded, error) { return nil, errBuildNotConfigured }
	}
	if mode.inDoubt {
		// The state and session end first: signing does not take the store
		// mutation lock, so no request may keep a key use, a pending approval,
		// or a live session against the generation being replaced while the
		// build runs. A locked signer stays locked, with nothing to build.
		if !ir.lockRuntime.SetRecovery() {
			return reloadEnd{err: ErrNeitherUnlockedNorRecovery}
		}
		ir.cancelKeyUses()
		ir.endSignRequests()
	}
	var kr *crypto.Keyring
	var loaded *Loaded
	var buildErr error
	if err := ir.keyStore.WithKeyring(func(inService *crypto.Keyring) error {
		kr = inService
		loaded, buildErr = build(inService)
		return nil
	}); err != nil {
		return reloadEnd{err: fmt.Errorf("signer is locked: %w", err)}
	}
	if loaded == nil {
		loaded = &Loaded{}
	}
	defer loaded.Discard()
	end := buildEnd(loaded, buildErr)
	prepared := loaded.Templates.Report()

	inRecovery := ir.IsRecovery()
	if buildErr == nil && !mode.inDoubt && (mode.reconcile || !inRecovery) {
		var detached keystore.DetachedKeyring
		end.report, detached = ir.publishLocked(kr, loaded)
		end.detached = append(end.detached, detached)
		end.published, end.keyCount = true, end.report.KeyCount
		end.notices, end.warnings = end.report.TemplateNotices, end.report.TemplateWarnings
		return end
	}
	view := recoveryView{selection: loaded.Selection}
	if loaded.PolicyVerified {
		view.policy, view.asaSet, view.alerts = loaded.Policy, loaded.ASASet, loaded.Alerts
	}
	if buildErr == nil && !mode.inDoubt {
		// A reload that succeeds in recovery (a restore or a rollback begun
		// there) shows recovery the new generation and publishes no keys:
		// the reconcile that follows publishes them as it promotes.
		end.detached = append(end.detached, ir.installRecoveryViewLocked(kr, view))
		end.report = &signertemplates.ReloadReport{RegistrationReport: prepared, TemplateNotices: end.notices, TemplateWarnings: end.warnings}
		return end
	}

	end.err, end.cause = buildErr, buildErr
	if buildErr == nil {
		end.cause = mode.cause
	}
	if mode.inDoubt {
		// Entered before the build.
		end.recovery = true
		end.detached = append(end.detached, ir.installRecoveryViewLocked(kr, view))
		return end
	}
	switch {
	case end.failClosed != nil, mode.failureInDoubt:
	case ir.rootMoved(loaded.Selection):
	case IsContentDefect(buildErr):
	default:
		return end
	}
	var detached keystore.DetachedKeyring
	end.recovery, detached = ir.enterRecoveryViewLocked(kr, view)
	end.detached = append(end.detached, detached)
	return end
}

// rootMoved reports whether the store root, as a build read it, no longer
// selects the generation the view in service is bound to: it selects
// another, or it did not authenticate (selection is nil).
func (ir *Runtime) rootMoved(selection *storepaths.GenPaths) bool {
	if selection == nil {
		return true
	}
	bound, err := ir.keyStore.ActivePaths()
	return err != nil || bound.GenerationID() != selection.GenerationID()
}

// publishLocked installs the whole of l, in the order a reader must see it:
// the stage tables holding the old inventory close first, then the
// providers are registered, the keystore takes the binding and the key cache,
// the runtime the policy, tokens and key maps, and the key session starts.
// kr is the keyring in service, which the install keeps. It returns the
// report and the keyring the install replaced, for zeroing once the caller
// has released its locks.
func (ir *Runtime) publishLocked(kr *crypto.Keyring, l *Loaded) (*signertemplates.ReloadReport, keystore.DetachedKeyring) {
	ir.stageTables.Invalidate()
	registration := l.Templates.Register(ir.providers)
	detached := ir.keyStore.Install(kr, l.Contents)
	ir.SetVerifiedPolicyState(l.Policy, l.ASASet, l.Alerts)
	ir.sourceTokens.Publish(l.Tokens)
	l.Tokens = nil
	keyCount := ir.publishKeys(l.Contents)
	if ir.keySession != nil {
		ir.keySession.InitializeSession()
	}
	return &signertemplates.ReloadReport{
		KeyCount:           keyCount,
		TemplateNotices:    registration.Notices(),
		TemplateWarnings:   registration.Warnings(),
		RegistrationReport: registration,
	}, detached
}

// recoveryView is what recovery serves: a binding, nil for none, and the
// policy, nil for none. It holds no keys and no token index.
type recoveryView struct {
	selection *storepaths.GenPaths
	policy    *policyruntime.NodePolicy
	asaSet    *asaset.Set
	alerts    []string
}

// enterRecoveryViewLocked enters recovery — moving the state and ending the
// session's key uses and approvals before installing view (which clears the
// source token index). Ending key uses before the token clear is defence in
// depth: context.AfterFunc delivers cancellation asynchronously, so the
// external-check consumer's session check decides the locked answer
// deterministically. A locked signer stays locked and the view is not
// installed. It reports whether it entered, and returns the keyring the
// install replaced.
func (ir *Runtime) enterRecoveryViewLocked(kr *crypto.Keyring, view recoveryView) (bool, keystore.DetachedKeyring) {
	if !ir.lockRuntime.SetRecovery() {
		return false, keystore.DetachedKeyring{}
	}
	ir.cancelKeyUses()
	ir.endSignRequests()
	return true, ir.installRecoveryViewLocked(kr, view)
}

// installRecoveryViewLocked installs view with kr, the keyring in service,
// which the install keeps. No provider is registered, and the key session
// stops and is replaced with a fresh inactive one (as performLockCleanup does),
// so a request holding the old session pointer stays permanently locked even
// after a later reconcile publishes unlocked, rather than seeing the old
// session re-initialized or finding no key on a passthrough check.
func (ir *Runtime) installRecoveryViewLocked(kr *crypto.Keyring, view recoveryView) keystore.DetachedKeyring {
	if ir.keySession != nil {
		ir.keySession.Destroy()
		if ir.keyStore != nil {
			ir.keySession = keystore.NewKeySession(ir.keyStore)
		} else {
			ir.keySession = nil
		}
	}
	ir.stageTables.Invalidate()
	var detached keystore.DetachedKeyring
	if ir.keyStore != nil {
		detached = ir.keyStore.Install(kr, keystore.Contents{Selection: view.selection})
	}
	ir.SetVerifiedPolicyState(view.policy, view.asaSet, view.alerts)
	ir.sourceTokens.Clear()
	ir.publishKeys(keystore.Contents{})
	return detached
}

// afterReload does what follows a reload once passphraseLock is released:
// the node fail-closed callback, the audit and the logs, then the
// keys-changed notification and the stage table wake, only while the signer
// is still unlocked (a lock that landed during the reload has told its
// sessions), and last the recovery hook. Key uses and approvals for an entry
// into recovery were already ended when SetRecovery moved the state.
func (ir *Runtime) afterReload(end reloadEnd) {
	for _, detached := range end.detached {
		detached.ZeroWhenUnused()
	}
	effects := ir.reloadEffectsSnapshot()
	if end.failClosed != nil && effects.NodeFailClosed != nil {
		effects.NodeFailClosed(fmt.Errorf("node role inventory conflict in product store: %w", end.failClosed))
	}
	if effects.Audit != nil {
		for _, warning := range end.rejected {
			effects.Audit.LogKeyRejected(warning.KeyFile, string(warning.Code)+": "+warning.Reason())
		}
	}
	for _, notice := range end.notices {
		logTo(effects.Info, "Info", notice)
	}
	for _, warning := range end.warnings {
		logTo(effects.Warn, "Warning", warning)
	}
	if end.published {
		if effects.Audit != nil {
			effects.Audit.LogKeyReload(end.keyCount)
		}
		fmt.Printf("🔄 Keys reloaded: %d key(s) available\n", end.keyCount)
		ir.notifyUnlockedReload(effects, end.keyCount)
	}
	if end.recovery {
		ir.watcherMu.Lock()
		hook := ir.onReloadRecovery
		ir.watcherMu.Unlock()
		if hook != nil && ir.IsRecovery() {
			hook(end.cause)
		}
	}
}

func (ir *Runtime) notifyUnlockedReload(effects ReloadEffects, keyCount int) {
	if !ir.IsUnlocked() {
		return
	}
	if effects.NotifyKeysChanged != nil {
		effects.NotifyKeysChanged(keyCount)
	}
	ir.WakeStageWork()
}

func (ir *Runtime) reloadEffectsSnapshot() ReloadEffects {
	ir.passphraseLock.RLock()
	defer ir.passphraseLock.RUnlock()
	return ir.reloadEffects
}

func logTo(fn func(string), prefix, msg string) {
	if fn != nil {
		fn(msg)
		return
	}
	fmt.Printf("%s: %s\n", prefix, msg)
}

// rejectedLogicSigKeys are the scan's LogicSig invariant violations, which
// the reload audits whether or not it publishes.
func rejectedLogicSigKeys(contents keystore.Contents) []apkeys.KeyScanWarning {
	var rejected []apkeys.KeyScanWarning
	for _, warning := range contents.Warnings {
		if warning.IsLogicSigInvariantViolation() {
			rejected = append(rejected, warning)
		}
	}
	return rejected
}

// buildEnd is what afterReload reports of a build before anything is
// published: the LogicSig keys its scan rejected and the template notices it
// prepared, audited and logged whether or not it publishes, and a role
// conflict, which fails the node closed.
func buildEnd(loaded *Loaded, err error) reloadEnd {
	prepared := loaded.Templates.Report()
	end := reloadEnd{rejected: rejectedLogicSigKeys(loaded.Contents), notices: prepared.Notices(), warnings: prepared.Warnings()}
	if errors.Is(err, keyclass.ErrNodeRoleConflict) {
		end.failClosed = err
	}
	return end
}

// buildOpened builds with kr, the keyring an unlock or a passphrase change
// opened from the store root, which is not the one in service. It holds no
// passphraseLock: it changes nothing live, and a lock that lands meanwhile
// wins at the attempt's fence. kr stays the caller's, for a publish to
// install or for the caller to zero.
func (ir *Runtime) buildOpened(kr *crypto.Keyring) (*Loaded, error) {
	ir.passphraseLock.RLock()
	build := ir.buildFn
	ir.passphraseLock.RUnlock()
	if build == nil {
		return &Loaded{}, errBuildNotConfigured
	}
	loaded, err := build(kr)
	if loaded == nil {
		loaded = &Loaded{}
	}
	return loaded, err
}

// publishUnlock installs l with kr, the keyring an unlock opened,
// which replaces the keyring in service (recovery's, in an unlock begun in
// recovery) under passphraseLock for writing, and zeroes the replaced one
// once the lock is released. The attempt's fence follows.
func (ir *Runtime) publishUnlock(kr *crypto.Keyring, l *Loaded) *signertemplates.ReloadReport {
	ir.passphraseLock.Lock()
	report, detached := ir.publishLocked(kr, l)
	ir.passphraseLock.Unlock()
	detached.ZeroWhenUnused()
	return report
}

// unlockBuildFailed decides how an unlock attempt whose build failed ends,
// by the failure rule for a signer not unlocked. A content defect enters
// recovery's view, as does, for an attempt begun in recovery, a root that
// moved off recovery's binding or did not authenticate. A role conflict,
// which the caller's afterReload fails the node closed for, installs nothing
// here, unlike a reload's: the node serves nothing more, so an attempt begun
// locked stays locked and one begun in recovery keeps recovery's view. (An
// attempt whose reconcile failed enters recovery for that failure before it
// gets here, role conflict or not.) Any
// other failure changes nothing and is the attempt's error. The keyring the
// attempt opened is installed only by an entry from locked; otherwise it is
// zeroed, and recovery keeps its own.
func (ir *Runtime) unlockBuildFailed(attempt signerruntime.Attempt, owned *crypto.Keyring, loaded *Loaded, err error) (UnlockOutcome, error) {
	enter := !errors.Is(err, keyclass.ErrNodeRoleConflict) &&
		(IsContentDefect(err) || (attempt.State() == signerruntime.SignerStateRecovery && ir.rootMoved(loaded.Selection)))
	if !enter {
		loaded.Discard()
		owned.Zero()
		return UnlockOutcome{}, err
	}
	return ir.unlockIntoRecovery(attempt, owned, loaded, err)
}

// unlockIntoRecovery ends an unlock attempt by entering recovery for cause,
// with recovery's view of what its build found: bound to the build's
// selection, showing the policy it verified or none, and holding no keys and
// no token index. The view is installed and then the attempt's fence decides
// (signerruntime.Runtime.EnterRecovery): a lock since the attempt began wins,
// and the attempt's cleanup clears the view. An attempt begun locked installs
// owned, the keyring it opened; one begun in recovery keeps recovery's, and
// zeroes owned.
func (ir *Runtime) unlockIntoRecovery(attempt signerruntime.Attempt, owned *crypto.Keyring, loaded *Loaded, cause error) (UnlockOutcome, error) {
	defer loaded.Discard()
	install := owned
	if attempt.State() == signerruntime.SignerStateRecovery {
		owned.Zero()
		install = nil
	}
	if ir.lockRuntime.LostToLock(attempt) {
		if install != nil {
			install.Zero()
		}
		return UnlockOutcome{}, signerruntime.ErrLockedDuringUnlock
	}
	view := recoveryView{selection: loaded.Selection}
	if loaded.PolicyVerified {
		view.policy, view.asaSet, view.alerts = loaded.Policy, loaded.ASASet, loaded.Alerts
	}
	var detached keystore.DetachedKeyring
	err := ir.lockRuntime.EnterRecovery(attempt, func() error {
		ir.passphraseLock.Lock()
		defer ir.passphraseLock.Unlock()
		kr := install
		if kr == nil {
			// Recovery's own, read under passphraseLock: a lock's cleanup
			// clears the keyring under it, so the one read here is still
			// usable when it is installed.
			_ = ir.keyStore.WithKeyring(func(inService *crypto.Keyring) error {
				kr = inService
				return nil
			})
		}
		if kr == nil {
			return fmt.Errorf("no keyring for recovery: %w", cause)
		}
		detached = ir.installRecoveryViewLocked(kr, view)
		return nil
	})
	detached.ZeroWhenUnused()
	switch {
	case errors.Is(err, signerruntime.ErrLockedDuringUnlock):
		// The attempt locked the runtime for its cleanup, which cleared the
		// view it installed.
		ir.notifyLocked()
		return UnlockOutcome{}, err
	case err != nil && ir.lockRuntime.LostToLock(attempt):
		// A lock that landed after the check above cleared recovery's
		// keyring before open read it: the attempt lost to that lock, which
		// told the admin session itself.
		return UnlockOutcome{}, signerruntime.ErrLockedDuringUnlock
	case err != nil:
		return UnlockOutcome{}, err
	}
	// The attempt began locked or in recovery (an unlocked one is answered
	// from the session), so no key use or approval of a session is in flight
	// for the entry to end.
	return UnlockOutcome{Recovery: true, Cause: cause}, nil
}
