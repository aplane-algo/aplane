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
	// DiscoveryTimeout bounds a request's scan for an unknown live stage.
	// Zero means DefaultDiscoveryTimeout.
	DiscoveryTimeout time.Duration
}

// discardTable drops a table whose contents disagree with the seed, so the
// background worker rebuilds it from scratch. The key is not touched.
func (d *RotatingDeps) discardTable(table *stagetable.Table) {
	if d == nil || d.Tables == nil || table == nil {
		return
	}
	_ = d.Tables.Discard(table)
}

// RotatingLocks serializes prepare, sign and table maintenance for each
// rotating account. One instance lives for the life of the process.
type RotatingLocks struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
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
	known   map[string]bool
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
		return nil, internal("rotating signing is not configured")
	}
	return s.Rotating, nil
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

func (s *Service) openRotatingSession(ctx context.Context, accountText string, session *keystore.KeySession) (*rotatingSession, *ServiceError) {
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
	if session == nil {
		return nil, lockedError()
	}
	key, loadErr := session.GetKeyWithContext(ctx, accountText)
	if loadErr != nil {
		if errors.Is(loadErr, keystore.ErrStoreLocked) {
			return nil, lockedError()
		}
		return nil, internal(fmt.Sprintf("failed to load rotating key: %v", loadErr))
	}
	secret, ok := key.Value.(*coresigning.RotatingKeyMaterial)
	if !ok || secret == nil || key.Type != keyType || len(secret.GenesisHash) != 32 {
		zeroLoadedKeyMaterial(key)
		return nil, internal("loaded rotating key has invalid material")
	}
	return &rotatingSession{
		account: account,
		keyType: keyType,
		profile: profile,
		key:     key,
		secret:  secret,
		ops:     ops,
		known:   knownAddressesFromSnapshot(snapshot),
	}, nil
}
