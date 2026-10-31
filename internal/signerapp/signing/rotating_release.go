// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"fmt"
	"sync"

	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/pkg/signerapi"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// ReleaseRecord is what the signer remembers about the last signature it
// released from a rotating account's current stage. It lives in process
// memory only and is rebuilt from the audit log at unlock. StageAddr and
// NextAddr are verified addresses, derived from the seed and never read from
// the stage table, so alerts never depend on a file the design does not
// trust.
type ReleaseRecord struct {
	// StatelessHash keeps release/window observations without one-time leaf history.
	StatelessHash bool
	Account       string
	Stage         uint64
	StageAddr     types.Address
	NextAddr      types.Address
	TxID          string
	LastValid     uint64
	// Leaves lists every distinct transaction the stage has released while
	// it stayed live, oldest first, with the one-time leaf each signed with.
	// The last entry is the latest release (TxID and LastValid above). A
	// family with one key per stage lists every release on leaf 0.
	Leaves []LeafRelease
	// Reused reports that two of the stage's releases signed with the same
	// one-time leaf: an expired release and its repair, or a client that
	// re-signed a rebuilt transaction, on a family with one key per stage;
	// or a stage that ran out of leaves. It is carried forward by Record
	// until the account moves past the stage. For a one-time stage scheme
	// (rotatingkey.Profile.OneTimeStage) this is the condition the status
	// reports; for the others it is informational.
	Reused bool
	// MessageBudget is the profile's StageMessageBudget (0 for a family
	// that has none). Distinct counts the different transactions a
	// stateless stage has released while it stayed live, from the live
	// signer and the audit log, saturating at MessageBudget+1: a retry of
	// one transaction is one release. It is reported, never enforced.
	MessageBudget int
	Distinct      int
	// Seq orders records against chain observations: a record with a Seq
	// above the Seq captured before a chain read was made after that read,
	// so the read says nothing about it.
	Seq uint64
}

// LeafRelease is one release of a stage: the one-time leaf (its tree and
// index) and the transaction it signed.
type LeafRelease struct {
	Tree      uint64
	Index     uint32
	TxID      string
	LastValid uint64
}

// latestLeaf is the record's own release as a leaf entry: its last listed
// leaf, or leaf 0 of tree 0 for a record that lists none.
func (r ReleaseRecord) latestLeaf() LeafRelease {
	if len(r.Leaves) > 0 {
		return r.Leaves[len(r.Leaves)-1]
	}
	return LeafRelease{TxID: r.TxID, LastValid: r.LastValid}
}

// LeafUsed reports whether the stage has released on the given leaf for a
// transaction other than txID.
func (r ReleaseRecord) LeafUsed(tree uint64, index uint32, txID string) bool {
	for _, l := range r.Leaves {
		if l.Tree == tree && l.Index == index && l.TxID != txID {
			return true
		}
	}
	return false
}

// LeafFor returns the leaf the stage already released txID on, if any.
func (r ReleaseRecord) LeafFor(txID string) (LeafRelease, bool) {
	for _, l := range r.Leaves {
		if l.TxID == txID {
			return l, true
		}
	}
	return LeafRelease{}, false
}

func leavesReused(leaves []LeafRelease) bool {
	seen := make(map[[2]uint64]bool, len(leaves))
	for _, l := range leaves {
		k := [2]uint64{l.Tree, uint64(l.Index)}
		if seen[k] {
			return true
		}
		seen[k] = true
	}
	return false
}

// ReleaseMemory holds one ReleaseRecord per rotating account. It is
// observational: it changes what the signer reports, never what it signs.
type ReleaseMemory struct {
	mu        sync.Mutex
	seq       uint64
	byAccount map[string]ReleaseRecord
	// armed holds every account until the audit log has been read after
	// an unlock; pending then names the accounts whose audited release is
	// still being restored. changed is closed and replaced when either
	// moves, waking AwaitRestored.
	armed   bool
	pending map[string]bool
	changed chan struct{}
	// messages holds, per account with a stateless stage budget, the
	// distinct transactions its newest stage released; it is the only
	// per-release state kept for such a stage and is bounded by the budget.
	messages map[string]*stageMessages
}

// stageMessages is the distinct transactions one stateless stage released,
// capped at limit entries (one past the budget, which is all the count is
// compared against).
type stageMessages struct {
	stage uint64
	limit int
	ids   map[string]struct{}
}

func (m *ReleaseMemory) messagesFor(account string, stage uint64, budget int) *stageMessages {
	if m.messages == nil {
		m.messages = make(map[string]*stageMessages)
	}
	set := m.messages[account]
	if set == nil || set.stage != stage {
		set = &stageMessages{stage: stage, ids: make(map[string]struct{})}
		m.messages[account] = set
	}
	set.limit = budget + 1
	return set
}

func (s *stageMessages) add(ids ...string) {
	for _, id := range ids {
		if id == "" || len(s.ids) >= s.limit {
			continue
		}
		s.ids[id] = struct{}{}
	}
}

// Record adds a live release to the account's entry and stamps the entry
// with the next sequence number. When the entry it replaces is from the
// same stage, r inherits that entry's released leaves and adds its own
// unless the same transaction is already listed (a retry is one release);
// r is marked Reused when two listed releases share a leaf.
func (m *ReleaseMemory) Record(r ReleaseRecord) {
	m.record(r, false)
}

// RecordAudited merges a release restored from the audit log, whose Leaves
// list every release the log holds for the stage, into the account's
// entry. The entry keeps every leaf either side knows, so a release signed
// while the log was being read is not forgotten and its leaf is not chosen
// again. When the entry lists a release the log does not, the entry is the
// newer of the two and keeps its latest release; when the entry is from a
// later stage, the audited release is stale and ignored.
func (m *ReleaseMemory) RecordAudited(r ReleaseRecord) {
	m.record(r, true)
}

func (m *ReleaseMemory) record(r ReleaseRecord, audited bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.byAccount == nil {
		m.byAccount = make(map[string]ReleaseRecord)
	}
	if r.StatelessHash {
		prev, held := m.byAccount[r.Account]
		if audited && held && prev.Stage > r.Stage {
			return
		}
		if r.MessageBudget > 0 {
			ids := []string{r.TxID}
			for _, l := range r.Leaves {
				ids = append(ids, l.TxID)
			}
			set := m.messagesFor(r.Account, r.Stage, r.MessageBudget)
			set.add(ids...)
			r.Distinct = len(set.ids)
		}
		// A live observation made while restore was running takes
		// precedence; the audited history still counts toward the stage.
		if audited && held && prev.Stage >= r.Stage {
			prev.MessageBudget, prev.Distinct = r.MessageBudget, r.Distinct
			m.byAccount[r.Account] = prev
			return
		}
		r.Leaves, r.Reused = nil, false
		m.seq++
		r.Seq = m.seq
		m.byAccount[r.Account] = r
		return
	}
	incoming := r.Leaves
	if len(incoming) == 0 {
		incoming = []LeafRelease{r.latestLeaf()}
	}
	var leaves []LeafRelease
	if prev, ok := m.byAccount[r.Account]; ok {
		if audited && prev.Stage > r.Stage {
			return
		}
		if prev.Stage == r.Stage {
			r.Reused = r.Reused || prev.Reused
			if audited {
				leaves = mergeLeaves(prev.Leaves, incoming)
				if leaves[len(leaves)-1].TxID != r.TxID {
					// Memory holds a release the log was read before:
					// it is the newer side and its latest stays latest.
					r.TxID, r.LastValid = prev.TxID, prev.LastValid
				}
			} else {
				// A live release: one scan of the history, no copy.
				leaves = prev.Leaves
				if !listsTxID(leaves, incoming[0].TxID) {
					leaves = append(leaves, incoming[0])
				}
			}
		}
	}
	if leaves == nil {
		leaves = mergeLeaves(nil, incoming)
	}
	r.Leaves = leaves
	r.Reused = r.Reused || leavesReused(leaves)
	m.seq++
	r.Seq = m.seq
	m.byAccount[r.Account] = r
}

// mergeLeaves merges the remembered leaves with the audited list in linear
// time, so the newer side's latest release ends the list: the audited
// order first, then any remembered release the log lacks.
func mergeLeaves(remembered, audited []LeafRelease) []LeafRelease {
	listed := make(map[string]bool, len(remembered)+len(audited))
	out := make([]LeafRelease, 0, len(remembered)+len(audited))
	for _, group := range [][]LeafRelease{audited, remembered} {
		for _, l := range group {
			if !listed[l.TxID] {
				listed[l.TxID] = true
				out = append(out, l)
			}
		}
	}
	return out
}

func listsTxID(leaves []LeafRelease, txID string) bool {
	for _, l := range leaves {
		if l.TxID == txID {
			return true
		}
	}
	return false
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
		delete(m.messages, account)
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
	delete(m.messages, account)
}

// Reset forgets every entry, as at lock.
// Reset forgets every record and holds every account until the next
// restore from the audit log begins (Restoring).
func (m *ReleaseMemory) Reset() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byAccount = nil
	m.messages = nil
	m.armed = true
	m.pending = nil
	m.signal()
}

// Restoring records that the audit log has been read and names the
// accounts whose audited release is still to be restored; every other
// account is released from the wait.
func (m *ReleaseMemory) Restoring(accounts []string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.armed = false
	m.pending = make(map[string]bool, len(accounts))
	for _, a := range accounts {
		m.pending[a] = true
	}
	m.signal()
}

// Restored releases the account from the wait: its audited release was
// recorded, skipped or failed.
func (m *ReleaseMemory) Restored(account string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.pending, account)
	m.signal()
}

// RestoredAll releases every account from the wait, whatever the restore
// achieved.
func (m *ReleaseMemory) RestoredAll() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.armed = false
	m.pending = nil
	m.signal()
}

// AwaitRestored returns once the account's audited release has been
// restored after an unlock, or there is nothing to restore, or with ctx's
// error. A memory that was never Reset holds nobody.
func (m *ReleaseMemory) AwaitRestored(ctx context.Context, account string) error {
	if m == nil {
		return nil
	}
	for {
		m.mu.Lock()
		if !m.armed && !m.pending[account] {
			m.mu.Unlock()
			return nil
		}
		if m.changed == nil {
			m.changed = make(chan struct{})
		}
		ch := m.changed
		m.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// signal wakes every AwaitRestored. The caller holds mu.
func (m *ReleaseMemory) signal() {
	if m.changed != nil {
		close(m.changed)
		m.changed = nil
	}
}

// AuditRotatingReleaseLogger is implemented by audit loggers that can record
// a rotating release durably, before the signature is returned.
type AuditRotatingReleaseLogger interface {
	LogRotatingRelease(account, txid string, stage, lastValid, tree uint64, index uint32) error
}

// AuditedRelease is a release read back from the audit log: enough to
// rebuild the ReleaseRecord once the stage addresses are derived.
type AuditedRelease struct {
	Account   string
	Stage     uint64
	TxID      string
	LastValid uint64
	// Reused reports that the log holds an earlier release from the same
	// stage on the same leaf. Entries the log rotated past are unknown, so
	// false means "none seen", not "none made".
	Reused bool
	// Leaves lists the stage's releases the log holds, oldest first.
	Leaves []LeafRelease
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
	accounts := make([]string, 0, len(entries))
	for _, e := range entries {
		accounts = append(accounts, e.Account)
	}
	deps.Releases.Restoring(accounts)
	for _, e := range entries {
		if ctx.Err() != nil {
			break
		}
		if _, held := snapshot.KeyFiles[e.Account]; !held {
			deps.Releases.Restored(e.Account)
			continue
		}
		stageAddr, nextAddr, err := s.releaseAddresses(ctx, e.Account, e.Stage, session, opts)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("rotating account %s: %w", e.Account, err)
			}
			deps.Releases.Restored(e.Account)
			continue
		}
		profile, _ := rotatingkey.Lookup(snapshot.KeyTypes[e.Account])
		deps.Releases.RecordAudited(ReleaseRecord{
			StatelessHash: profile.StatelessHash, MessageBudget: profile.StageMessageBudget,
			Account: e.Account, Stage: e.Stage, StageAddr: stageAddr, NextAddr: nextAddr,
			TxID: e.TxID, LastValid: e.LastValid, Reused: e.Reused, Leaves: e.Leaves,
		})
		deps.Releases.Restored(e.Account)
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
//   - the same, within the validity, but the stage has released over more
//     than one transaction and its scheme is one-time: reused (warning),
//     because the stage has lost its one-time scheme's protection until the
//     account moves; for other schemes the reuse is harmless and stays a note;
//   - authorizer anywhere else: the release landed or the account moved on;
//     the memory is cleared and nothing is said. A record made after the
//     pass's chain read is newer than the observation and is left alone;
//   - the authorizer is a credential this signer holds: a note that the
//     account was rekeyed to it; the rotating stages no longer control it;
//   - the authorizer is unknown and a recovery grant is searching: a note
//     with the scan count and the grant's progress;
//   - the authorizer is unknown and no grant is searching: a note that it
//     is not a stage within what was searched, with what stopped the
//     search and the two operator remedies. Like a non-rotating account
//     rekeyed to an address the signer does not hold, this is information,
//     not an alert, and never a claim that the account was exited.
func (s *Service) RotatingStatus(reports []StageTableReport) (warnings, notes []string) {
	deps, depErr := s.rotatingDeps()
	if depErr != nil {
		return nil, nil
	}
	snapshot := s.Planner.Snapshot()
	for _, r := range reports {
		if !r.Observed {
			continue
		}
		if !r.Resolved && r.Err == nil {
			notes = append(notes, unresolvedNote(r))
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
		// The messages omit the current round so they stay identical across
		// passes and are logged once, not on every pass.
		profile, _ := rotatingkey.Lookup(snapshot.KeyTypes[r.Account])
		reuse := ""
		if rec.Reused {
			reuse = " (the stage has signed more than one transaction)"
		} else if profile.LeavesPerStage > 1 && len(rec.Leaves) > 1 {
			reuse = fmt.Sprintf(" (attempt %d of %d from this stage)", len(rec.Leaves), profile.LeavesPerStage)
		}
		if profile.StageMessageBudget > 0 && rec.Distinct > profile.StageMessageBudget {
			warnings = append(warnings, fmt.Sprintf("rotating account %s: stage %d has released more than %d distinct transactions without the account moving, past the signing budget its key's security margin assumes; the latest release is %s (valid through round %d); land a spend or send a rotate-only spend now, and find the client that keeps requesting signatures", r.Account, rec.Stage, profile.StageMessageBudget, rec.TxID, rec.LastValid))
			continue
		}
		if r.Round > rec.LastValid {
			warnings = append(warnings, fmt.Sprintf("rotating account %s: stage %d revealed its keys in transaction %s, which expired at round %d without confirming; the revealed keys still control the account%s; send a rotate-only spend now", r.Account, rec.Stage, rec.TxID, rec.LastValid, reuse))
			continue
		}
		if rec.Reused && profile.OneTimeStage {
			warnings = append(warnings, fmt.Sprintf("rotating account %s: stage %d has signed more than one transaction; its one-time hash-based key is spent and the stage rests on %s until the account moves; latest release %s is in flight (valid through round %d), wait for it to land or send a rotate-only spend", r.Account, rec.Stage, profile.ReusedStageRestsOn, rec.TxID, rec.LastValid))
			continue
		}
		notes = append(notes, fmt.Sprintf("rotating account %s: release from stage %d in flight (transaction %s, valid through round %d)%s", r.Account, rec.Stage, rec.TxID, rec.LastValid, reuse))
	}
	return warnings, notes
}

// unresolvedNote words an unresolved account's status line.
func unresolvedNote(r StageTableReport) string {
	switch r.Class {
	case ClassHeldKey:
		return fmt.Sprintf("rotating account %s: rekeyed to %s, a key this signer holds; its rotating stages no longer control it", r.Account, r.Authorizer)
	}
	if g := r.Recovery.Grant; g != nil {
		progress := fmt.Sprintf("%s recovery running, %d of %d stages used", g.Kind, g.Charged, g.MaxStages)
		if g.Found != nil {
			progress += fmt.Sprintf(", stage %d found, filling the cache to it", *g.Found)
		} else if g.Hint != nil {
			progress += fmt.Sprintf(", probing around stage %d", *g.Hint)
		}
		return fmt.Sprintf("rotating account %s: stage not yet found, %d stages cached; %s", r.Account, r.Scanned, progress)
	}
	stopped := "automatic recovery is disabled"
	if r.Recovery.AllowanceMax > 0 {
		stopped = "automatic recovery for this authorizer is exhausted for this unlock"
	}
	if l := r.Recovery.Last; l != nil {
		stopped = fmt.Sprintf("the last %s search stopped: %s after %d stages", l.Kind, l.Reason, l.Charged)
	}
	return fmt.Sprintf("rotating account %s: authorizer %s is not a stage within the %d stages this signer has cached; %s; run `rotate recover` if the account was advanced elsewhere, or delete the key if it was exited", r.Account, r.Authorizer, r.Scanned, stopped)
}

// RotatingAccountStatuses projects a pass's reports into the structured
// per-account status the /status endpoint and `rotate status` show.
func (s *Service) RotatingAccountStatuses(reports []StageTableReport) []signerapi.RotatingAccountStatus {
	out := make([]signerapi.RotatingAccountStatus, 0, len(reports))
	for _, r := range reports {
		st := signerapi.RotatingAccountStatus{
			Account:        r.Account,
			Classification: signerapi.RotatingClassUnobserved,
			CachedStages:   r.Scanned,
			Recovery:       recoveryStatus(r.Recovery),
		}
		if r.Observed {
			st.Authorizer, st.Round = r.Authorizer.String(), r.Round
			switch {
			case r.Resolved:
				st.Classification = signerapi.RotatingClassStage
				stage := r.Stage
				st.Stage = &stage
			case r.Class == ClassHeldKey:
				st.Classification = signerapi.RotatingClassHeldKey
			case r.Class == ClassUnknown:
				st.Classification = signerapi.RotatingClassUnknown
			}
		}
		out = append(out, st)
	}
	return out
}
