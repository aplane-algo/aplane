// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"fmt"
	"sync"

	"github.com/aplane-algo/aplane/internal/keystore"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// ReleaseRecord is what the signer remembers about the last signature it
// released from a rotating account's current stage. It lives in process
// memory only and is rebuilt from the audit log at unlock. StageAddr and
// NextAddr are verified addresses, derived from the seed and never read from
// the stage table, so alerts never depend on a file the design does not
// trust.
type ReleaseRecord struct {
	Account   string
	Stage     uint64
	StageAddr types.Address
	NextAddr  types.Address
	TxID      string
	LastValid uint64
	// Seq orders records against chain observations: a record with a Seq
	// above the Seq captured before a chain read was made after that read,
	// so the read says nothing about it.
	Seq uint64
}

// ReleaseMemory holds one ReleaseRecord per rotating account. It is
// observational: it changes what the signer reports, never what it signs.
type ReleaseMemory struct {
	mu        sync.Mutex
	seq       uint64
	byAccount map[string]ReleaseRecord
}

// Record replaces the account's entry with r and stamps it with the next
// sequence number.
func (m *ReleaseMemory) Record(r ReleaseRecord) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.byAccount == nil {
		m.byAccount = make(map[string]ReleaseRecord)
	}
	m.seq++
	r.Seq = m.seq
	m.byAccount[r.Account] = r
}

// Seq returns the sequence number of the most recent Record. A caller
// captures it before reading the chain so a later status evaluation can tell
// records made after the read from those the read can speak for.
func (m *ReleaseMemory) Seq() uint64 {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.seq
}

// clearIfUnchanged forgets the account's entry only if it is the one with
// seq, so an observation older than a newer release never erases it.
func (m *ReleaseMemory) clearIfUnchanged(account string, seq uint64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.byAccount[account]; ok && r.Seq == seq {
		delete(m.byAccount, account)
	}
}

// Get returns the account's entry, if any.
func (m *ReleaseMemory) Get(account string) (ReleaseRecord, bool) {
	if m == nil {
		return ReleaseRecord{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.byAccount[account]
	return r, ok
}

// Clear forgets the account's entry.
func (m *ReleaseMemory) Clear(account string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.byAccount, account)
}

// Reset forgets every entry, as at lock.
func (m *ReleaseMemory) Reset() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byAccount = nil
}

// AuditRotatingReleaseLogger is implemented by audit loggers that can record
// a rotating release durably, before the signature is returned.
type AuditRotatingReleaseLogger interface {
	LogRotatingRelease(account, txid string, stage, lastValid uint64) error
}

// AuditedRelease is a release read back from the audit log: enough to
// rebuild the ReleaseRecord once the stage addresses are derived.
type AuditedRelease struct {
	Account   string
	Stage     uint64
	TxID      string
	LastValid uint64
}

// RebuildReleaseMemory fills the release memory from audit entries, deriving
// the verified stage and successor addresses for each account inside a
// KeyUse window. Entries for accounts the signer no longer holds are
// skipped. It returns the number of records rebuilt and the first failure,
// if any; a failure for one account does not stop the others.
func (s *Service) RebuildReleaseMemory(ctx context.Context, session *keystore.KeySession, entries []AuditedRelease, opts StageFillOptions) (int, error) {
	deps, depErr := s.rotatingDeps()
	if depErr != nil || deps.Releases == nil {
		return 0, nil
	}
	snapshot := s.Planner.Snapshot()
	var firstErr error
	rebuilt := 0
	for _, e := range entries {
		if ctx.Err() != nil {
			break
		}
		if _, held := snapshot.KeyFiles[e.Account]; !held {
			continue
		}
		stageAddr, nextAddr, err := s.releaseAddresses(ctx, e.Account, e.Stage, session, opts)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("rotating account %s: %w", e.Account, err)
			}
			continue
		}
		deps.Releases.Record(ReleaseRecord{
			Account: e.Account, Stage: e.Stage, StageAddr: stageAddr, NextAddr: nextAddr,
			TxID: e.TxID, LastValid: e.LastValid,
		})
		rebuilt++
	}
	return rebuilt, firstErr
}

// releaseAddresses derives A_stage and A_{stage+1} for an account.
func (s *Service) releaseAddresses(ctx context.Context, account string, stage uint64, session *keystore.KeySession, opts StageFillOptions) (types.Address, types.Address, error) {
	derive := s.stageDeriver(account, session, StageFillOptions{Parallel: 2, KeyUse: opts.KeyUse})
	addrs, err := derive(ctx, stage, stage+2)
	if err != nil {
		return types.Address{}, types.Address{}, err
	}
	if len(addrs) != 2 {
		return types.Address{}, types.Address{}, context.Canceled
	}
	return addrs[0], addrs[1], nil
}

// RotatingStatus turns one fill pass into operator-facing status. Warnings
// are conditions that need action; notes are information. Both are derived
// from the pass's authorizer reads and the release memory, never from the
// stage table, which the design does not trust for any decision.
//
// Per account whose authorizer was read in this pass (a failed table write
// after a successful read does not silence the account's status):
//   - authorizer equals the remembered release's stage address and the round
//     is within its validity: in flight (note);
//   - the same, past the validity: expired, still live (warning), because the
//     revealed stage still controls the account and that transaction can
//     never confirm;
//   - authorizer anywhere else: the release landed or the account moved on;
//     the memory is cleared and nothing is said. A record made after the
//     pass's chain read is newer than the observation and is left alone;
//   - the stage is not yet found in the table: a note with the scan count,
//     never a claim that the authorizer is foreign.
func (s *Service) RotatingStatus(reports []StageTableReport) (warnings, notes []string) {
	deps, depErr := s.rotatingDeps()
	if depErr != nil {
		return nil, nil
	}
	for _, r := range reports {
		if !r.Observed {
			continue
		}
		if !r.Resolved && r.Err == nil {
			notes = append(notes, fmt.Sprintf("rotating account %s: stage not yet found, %d stages scanned", r.Account, r.Scanned))
		}
		rec, ok := deps.Releases.Get(r.Account)
		if !ok {
			continue
		}
		if rec.Seq > r.ObservedSeq {
			// Released after this pass read the chain: the read cannot say
			// whether it landed. The next pass will.
			continue
		}
		if r.Authorizer != rec.StageAddr {
			deps.Releases.clearIfUnchanged(r.Account, rec.Seq)
			continue
		}
		if r.Round > rec.LastValid {
			// The message omits the current round so it stays identical
			// across passes and is logged once, not on every pass.
			warnings = append(warnings, fmt.Sprintf("rotating account %s: stage %d revealed its keys in transaction %s, which expired at round %d without confirming; the revealed keys still control the account; send a rotate-only spend now", r.Account, rec.Stage, rec.TxID, rec.LastValid))
			continue
		}
		notes = append(notes, fmt.Sprintf("rotating account %s: release from stage %d in flight (transaction %s, valid through round %d)", r.Account, rec.Stage, rec.TxID, rec.LastValid))
	}
	return warnings, notes
}
