// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/internal/signerapp/chainread"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/stagetable"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// RotatingChain reads an account's authorizer and the current round from the
// signer's own node.
type RotatingChain interface {
	ReadAccount(ctx context.Context, genesisHash []byte, account types.Address) (chainread.AccountView, error)
}

// RotatingDeps are the long-lived dependencies of the rotating flow. The
// signer keeps no durable state for rotating accounts: Tables is a derivable
// cache, Releases and Locks are process memory.
type RotatingDeps struct {
	Chain  RotatingChain
	Tables *stagetable.Store
	Locks  *RotatingLocks
	// Releases remembers the last release per account for status; nil
	// disables release memory.
	Releases *ReleaseMemory
	// Recovery holds the per-unlock recovery allowance and grants; nil
	// disables recovery, leaving an unknown authorizer unresolved.
	// LockGeneration reads the runtime's live lock generation, which
	// identifies the unlocked session; Recovery validates every entry
	// against it, so an allowance never outlives the unlock it was granted
	// in. nil means one unending session.
	Recovery       *RotatingRecovery
	LockGeneration func() uint64
	// KeyUse brackets every window in which prepare, sign, the stage table
	// fill or the release restore holds a loaded seed: its context is
	// cancelled the moment the signer locks, and a lock waits for release
	// before it reports the seed gone. Every seed load goes through keyUse,
	// which refuses to open a window without it, so with KeyUse unset no seed
	// is loaded; paths that load no seed (status, recovery) don't need it.
	// Besides reading the aplane key file, which is the load the window
	// covers, nothing that blocks on the disk or the network runs inside a
	// window, with one exception: for a stateless-hash family (SLH-DSA) the
	// sign's signing window reads the chain once more after signing, before
	// the seed is zeroed. That read runs under the window's context, so a
	// lock cancels it rather than waiting it out, and the request answers
	// locked.
	KeyUse func(context.Context) (context.Context, func())
	// DiscoveryTimeout bounds a request's scan for an unknown live stage.
	// Zero means DefaultDiscoveryTimeout.
	DiscoveryTimeout time.Duration
	Wake             func()
}

// rotatingNotConfiguredMessage is the text rotatingDeps refuses missing
// dependencies with, which errKeyUseNotConfigured shares.
const rotatingNotConfiguredMessage = "rotating signing is not configured"

// errKeyUseNotConfigured refuses a seed load on deps without KeyUse, with
// the message rotatingDeps uses for missing dependencies.
var errKeyUseNotConfigured = errors.New(rotatingNotConfiguredMessage)

// keyUse opens a window for holding a seed. The returned release is safe to
// call more than once. Without KeyUse it opens no window and returns
// errKeyUseNotConfigured with a cancelled context, so nothing loads a seed
// unregistered.
func (d *RotatingDeps) keyUse(ctx context.Context) (context.Context, func(), error) {
	if d.KeyUse == nil {
		refused, cancel := context.WithCancel(ctx)
		cancel()
		return refused, func() {}, errKeyUseNotConfigured
	}
	useCtx, release := d.KeyUse(ctx)
	return useCtx, sync.OnceFunc(release), nil
}

// RotatingLocks serializes prepare, sign and table maintenance for each
// rotating account. One instance lives for the life of the process.
type RotatingLocks struct {
	jobsMu sync.Mutex
	jobs   map[stageJobKey]*stageJob
	slots  chan struct{}
	mu     sync.Mutex
	locks  map[string]*sync.Mutex
}

// Lock locks account and returns its unlock.
func (l *RotatingLocks) Lock(account string) func() {
	l.mu.Lock()
	if l.locks == nil {
		l.locks = make(map[string]*sync.Mutex)
	}
	m, ok := l.locks[account]
	if !ok {
		m = &sync.Mutex{}
		l.locks[account] = m
	}
	l.mu.Unlock()
	m.Lock()
	return m.Unlock
}

// rotatingSession holds what every rotating operation loads for one account:
// the seed, the family's stage cryptography and the account's resource
// profile. Close zeroes the seed.
type rotatingSession struct {
	account types.Address
	keyType string
	profile *lsigresource.Profile
	key     *coresigning.KeyMaterial
	secret  *coresigning.RotatingKeyMaterial
	ops     coresigning.RotatingStageOps
}

func (rs *rotatingSession) close() {
	if rs != nil {
		zeroLoadedKeyMaterial(rs.key)
	}
}

// stageAddress derives stage i's address from the seed.
func (rs *rotatingSession) stageAddress(stage uint64) (types.Address, error) {
	return rs.ops.StageAddress(rs.secret, stage)
}

func (s *Service) rotatingDeps() (*RotatingDeps, *ServiceError) {
	if s.Planner == nil || s.Planner.Snapshot == nil || s.Rotating == nil ||
		s.Rotating.Chain == nil || s.Rotating.Tables == nil || s.Rotating.Locks == nil {
		return nil, internal(rotatingNotConfiguredMessage)
	}
	return s.Rotating, nil
}

// recoverySession returns the session an operation acts in: the one it
// captured with its context when it has one, otherwise the live one now.
// The memory itself validates it on every entry (see "Session ownership"
// in rotating_recovery.go); ok reports whether it is still admitted.
func (d *RotatingDeps) recoverySession(captured *uint64) (uint64, bool) {
	if d == nil || d.Recovery == nil {
		return 0, true
	}
	if d.LockGeneration != nil {
		d.Recovery.SetGenerationSource(d.LockGeneration)
	}
	if captured != nil {
		return *captured, d.Recovery.Admit(*captured)
	}
	gen := d.Recovery.Session()
	return gen, true
}

// rotatingAccounts lists the rotating accounts the planner knows, sorted.
func (s *Service) rotatingAccounts() []string {
	snapshot := s.Planner.Snapshot()
	accounts := make([]string, 0)
	for account, keyType := range snapshot.KeyTypes {
		if rotatingkey.IsRotatingKeyType(keyType) {
			accounts = append(accounts, account)
		}
	}
	sortStrings(accounts)
	return accounts
}

// indexedRotatingKey checks, from the key index alone, that accountText
// names a rotating aplane key this signer holds, and returns its session
// without the seed. It loads no key material.
func (s *Service) indexedRotatingKey(accountText string) (*rotatingSession, *ServiceError) {
	account, err := types.DecodeAddress(accountText)
	if err != nil {
		return nil, badRequest(fmt.Sprintf("invalid account: %v", err))
	}
	snapshot := s.Planner.Snapshot()
	keyType := snapshot.KeyTypes[accountText]
	if _, ok := snapshot.KeyFiles[accountText]; !ok {
		return nil, badRequest(fmt.Sprintf("no key found for account: %s", accountText))
	}
	if !rotatingkey.IsRotatingKeyType(keyType) {
		return nil, badRequest(fmt.Sprintf("account %s is not a rotating account", accountText))
	}
	profile := snapshot.KeyMetadata[accountText].LogicSigResources
	if profile == nil {
		return nil, internal("rotating account has no resource profile")
	}
	ops, opsErr := coresigning.GetRotatingStageOps(keyType)
	if opsErr != nil {
		return nil, internal(opsErr.Error())
	}
	return &rotatingSession{account: account, keyType: keyType, profile: profile, ops: ops}, nil
}

func (s *Service) openRotatingSession(ctx context.Context, accountText string, session *keystore.KeySession) (*rotatingSession, *ServiceError) {
	rs, svcErr := s.indexedRotatingKey(accountText)
	if svcErr != nil {
		return nil, svcErr
	}
	return loadRotatingKey(ctx, rs, session)
}

// loadRotatingKey loads the seed of an account indexedRotatingKey returned
// into rs.
func loadRotatingKey(ctx context.Context, rs *rotatingSession, session *keystore.KeySession) (*rotatingSession, *ServiceError) {
	if session == nil {
		return nil, lockedError()
	}
	accountText := rs.account.String()
	key, loadErr := session.GetKeyWithContext(ctx, accountText)
	if loadErr != nil {
		if errors.Is(loadErr, keystore.ErrStoreLocked) {
			return nil, lockedError()
		}
		return nil, internal(fmt.Sprintf("failed to load rotating key: %v", loadErr))
	}
	secret, ok := key.Value.(*coresigning.RotatingKeyMaterial)
	if !ok || secret == nil || key.Type != rs.keyType || len(secret.GenesisHash) != 32 {
		zeroLoadedKeyMaterial(key)
		return nil, internal("loaded rotating key has invalid material")
	}
	rs.key, rs.secret = key, secret
	return rs, nil
}
