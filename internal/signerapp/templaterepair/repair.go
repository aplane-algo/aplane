// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package templaterepair repairs the template record defects that fail a
// selected generation's validation, with the signer stopped: an externally
// edited record is re-pinned to its stored template or dropped, and an
// orphaned record is dropped. A repair commits a new generation through
// genstore.Mint whose parent, the damaged generation, is kept.
//
// The caller holds the exclusive store lock for the whole repair, so no
// signer runs and nothing can race it (docs/ARCH_STORE.md, "Offline bootstrap
// and rescue"). With no signer running, nothing else reconciles the
// generation store, so a repair reconciles it first, as every unlock does.
package templaterepair

import (
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/storevalidate"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatelibrary"
	"github.com/aplane-algo/aplane/internal/templatestore"
)

// Operation is the manifest operation of a template repair generation.
const Operation = "template-repair"

// Action is what a repair does to one defective record.
type Action string

const (
	// ActionRepin rewrites an externally edited record's fingerprint to the
	// one its stored template computes.
	ActionRepin Action = "repin"
	// ActionDrop deletes the record, archiving its template file when there
	// is one.
	ActionDrop Action = "drop"
)

var (
	// ErrNotDefective refuses a key type that is not one of the classified
	// template record defects, so a repair cannot touch a healthy template.
	ErrNotDefective = errors.New("key type is not a template record defect")
	// ErrRepinRefused refuses a re-pin of a record with no template file.
	ErrRepinRefused = errors.New("only an external edit can be re-pinned")
	// ErrUnnamedDefect refuses a repair that leaves a defect out: the
	// repaired generation must validate with no exclusions.
	ErrUnnamedDefect = errors.New("every template record defect must be repaired together")
	// ErrOtherDamage refuses a repair while anything it does not repair is
	// damaged.
	ErrOtherDamage = errors.New("the generation has damage a template repair does not cover")
	// ErrCommitBlocked refuses a repair that no generation commit could
	// complete over the current generation.
	ErrCommitBlocked = errors.New("no generation can be committed over the current one")
	// ErrGenerationTooLarge is the commit-blocking damage of a current
	// generation too large for any successor to fit the quarantine limits.
	ErrGenerationTooLarge = errors.New("the generation is too large for a successor")
	// ErrNothingNamed refuses a repair that names no key type. apstore
	// refuses such a command line first; this guard is what keeps Repair
	// from committing a generation that changes nothing.
	ErrNothingNamed = errors.New("template repair names no key type")
)

// Options is the stopped store a repair works on. Current is the generation
// the authenticated store root selects, resolved fresh by the caller with
// Keyring.
type Options struct {
	Paths   storepaths.Paths
	Current storepaths.GenPaths
	Keyring *crypto.Keyring
	Role    noderole.Role
	DataDir string
	Config  *serverconfig.ServerConfig
}

// Defect is one template record defect and the evidence the store holds
// about it. A repair offers no default for an external edit: the record is
// unauthenticated, and the stored template authenticates only as one sealed
// for its key type in the current term, which an earlier definition of the
// key type also is. The key files, which are authenticated, are the
// evidence of which definition the keys came from.
type Defect struct {
	KeyType string
	Kind    signertemplates.RecordDefectKind
	// TemplateType is the record's template type; it is empty for a
	// disabled record without template file.
	TemplateType templatestore.TemplateType
	// Keys counts the aplane keys of this key type.
	Keys int
	// For an external edit, KeysFromStoredTemplate counts the keys whose
	// recorded template fingerprint is the stored template's, and
	// ConflictAfterRepin those whose recorded one is another definition's:
	// they read conflict after a re-pin. Keys that record none are in
	// neither.
	KeysFromStoredTemplate int
	ConflictAfterRepin     int
	// RecordedFingerprint is the record's; TemplateFingerprint, for an
	// external edit, is the one its stored template computes.
	RecordedFingerprint string
	TemplateFingerprint string
}

// Allows reports whether action may repair the defect.
func (d Defect) Allows(action Action) bool {
	switch action {
	case ActionDrop:
		return true
	case ActionRepin:
		return d.Kind == signertemplates.RecordExternalEdit
	default:
		return false
	}
}

// Preview is the template record defects of the selected generation.
type Preview struct {
	GenerationID string
	Defects      []Defect
	// OtherDamage is the first damage outside the defects, which refuses
	// any repair; nil when there is none, or no defect to repair.
	OtherDamage error
	// CommitBlocked is what refuses every generation commit over the
	// current generation, which a repair cannot clear; nil when nothing
	// does, or there is no defect to repair.
	CommitBlocked error
	// Reconcile is what a repair's reconciliation would quarantine or
	// discard first: residue an earlier mint left.
	Reconcile genstore.ReconcileReport
	// Residue is the crash residue in the current generation, relative to
	// its directory (genstore.WriteResidue). The preview classifies the
	// generation as it stands, residue included, so its classification may
	// change once reconciliation discards the residue; Repair reclassifies
	// then.
	Residue []string
	// ResidueDamage is the damage the classification found that is crash
	// residue, by its path: a --confirm run discards it first, so it is
	// neither OtherDamage nor CommitBlocked.
	ResidueDamage []string
}

// ReconcilePending reports whether a repair would quarantine or discard
// anything before it mints.
func (preview Preview) ReconcilePending() bool {
	return len(preview.Reconcile.Quarantined) > 0 || len(preview.Reconcile.DiscardedStaging) > 0
}

// Inspect classifies every template record defect in the selected
// generation, with the classification reload uses. It reads the generation
// in place and writes nothing.
func Inspect(opts Options) (Preview, error) {
	preview := Preview{GenerationID: opts.Current.GenerationID()}
	// A namespace that cannot be listed is structural damage, which the gate
	// reports itself.
	preview.Residue, _ = genstore.WriteResidue(opts.Current)
	// Reconciliation refusing the store is damage unlock refuses too.
	report, reconcileErr := genstore.InspectStoreRoot(opts.Paths, opts.Keyring)
	preview.Reconcile = report
	if err := classify(opts, &preview, reconcileErr); err != nil {
		return Preview{}, err
	}
	preview.OtherDamage = preview.setAsideResidue(preview.OtherDamage, opts.Current)
	preview.CommitBlocked = preview.setAsideResidue(preview.CommitBlocked, opts.Current)
	return preview, nil
}

// setAsideResidue returns damage, or nil when it is about a file of the
// crash residue, which it records in ResidueDamage instead.
func (preview *Preview) setAsideResidue(damage error, current storepaths.GenPaths) error {
	if damage == nil {
		return nil
	}
	if path, ok := damagePath(damage, current); ok && slices.Contains(preview.Residue, path) {
		preview.ResidueDamage = append(preview.ResidueDamage, path)
		return nil
	}
	return damage
}

// damagePath is the path, relative to current's directory, of the file the
// first damage is about, when its error names one.
func damagePath(damage error, current storepaths.GenPaths) (string, bool) {
	var (
		template   *storevalidate.TemplateContentDefectError
		credential *storevalidate.CredentialDefectError
		policyFile *policy.UnsupportedEntryError
		stray      *storevalidate.DeletedArchiveStrayError
		path       string
	)
	switch {
	case errors.As(damage, &template) && template.Path != "":
		path = template.Path
	case errors.As(damage, &credential):
		path = credential.Warning.KeyFile
	case errors.As(damage, &policyFile):
		path = policyFile.Path
	case errors.As(damage, &stray):
		return stray.Path, true
	default:
		return "", false
	}
	relative, err := filepath.Rel(current.Dir(), path)
	if err != nil {
		return "", false
	}
	return filepath.ToSlash(relative), true
}

// classify fills preview with the record defects of opts.Current, the
// first damage a repair does not cover, and what refuses a commit over it.
// reconcileErr is reconciliation's refusal of the store, if any.
func classify(opts Options, preview *Preview, reconcileErr error) error {
	manager := signertemplates.NewManager(opts.Paths)
	manager.ActivePaths = opts.Current
	report, err := manager.ValidateKeystoreTemplates(opts.Keyring)
	if err != nil {
		return fmt.Errorf("classify template records: %w", err)
	}
	recordDefects := report.RecordDefects()
	if len(recordDefects) == 0 {
		return nil
	}
	defective := make(map[string]bool, len(recordDefects))
	for _, recordDefect := range recordDefects {
		defective[recordDefect.KeyType] = true
	}
	current := validateOptions(opts, opts.Current)
	// One scan, the gate's, serves the key counts too, so each damaged key
	// file is reported once.
	scan, damage := storevalidate.TemplateRepairDestination(current, defective)
	preview.OtherDamage = damage
	if scan == nil {
		if scan, err = keys.ScanKeysDirectory(opts.Current, opts.Keyring, nil); err != nil {
			return fmt.Errorf("count keys: %w", err)
		}
	}
	for _, recordDefect := range recordDefects {
		defect, err := describe(opts, recordDefect, scan)
		if err != nil {
			return err
		}
		preview.Defects = append(preview.Defects, defect)
	}
	if reconcileErr != nil {
		if preview.OtherDamage == nil {
			preview.OtherDamage = reconcileErr
		}
		return nil
	}
	preview.CommitBlocked = commitBlocked(current, preview.Reconcile, scan)
	return nil
}

// commitBlocked is what refuses a mint over the current generation and
// survives reconciliation: a parent that lost its seal, a generation too
// large for a successor, and what every commit's candidate check refuses
// though unlock never reads it.
func commitBlocked(current storevalidate.Options, reconcile genstore.ReconcileReport, scan *keys.KeyScanReport) error {
	if parent := reconcile.RetainedUnsealedParent; parent != "" {
		return &UnsealedParentError{Parent: parent}
	}
	if err := genstore.RequireSuccessorFits(current.Candidate); err != nil {
		return fmt.Errorf("%w: %w", ErrGenerationTooLarge, err)
	}
	return storevalidate.CommitOnlyDamage(current, scan)
}

// UnsealedParentError is a current generation whose parent has lost its
// seal: reconciliation keeps that parent as damage, and every mint refuses
// it.
type UnsealedParentError struct {
	Parent string
}

func (e *UnsealedParentError) Error() string {
	return fmt.Sprintf("the current generation's parent %s has lost its seal, which reconciliation keeps and every mint refuses", e.Parent)
}

func describe(opts Options, recordDefect signertemplates.RecordDefect, scan *keys.KeyScanReport) (Defect, error) {
	defect := Defect{
		KeyType:      recordDefect.KeyType,
		Kind:         recordDefect.Kind,
		TemplateType: recordDefect.TemplateType,
	}
	rec, ok, err := keytypestate.GetActive(opts.Current, defect.KeyType)
	if err != nil {
		return Defect{}, fmt.Errorf("read the record of %s: %w", defect.KeyType, err)
	}
	if !ok {
		return Defect{}, fmt.Errorf("the record of %s is gone", defect.KeyType)
	}
	defect.RecordedFingerprint = rec.Fingerprint
	if defect.Kind == signertemplates.RecordExternalEdit {
		defect.TemplateFingerprint, err = templatelibrary.StoredTemplateFingerprintActive(
			opts.Current, defect.KeyType, defect.TemplateType, opts.Keyring,
		)
		if err != nil {
			return Defect{}, fmt.Errorf("fingerprint the installed template of %s: %w", defect.KeyType, err)
		}
	}
	for _, info := range scan.Keys {
		if !strings.EqualFold(info.KeyType, defect.KeyType) {
			continue
		}
		defect.Keys++
		if defect.TemplateFingerprint == "" || info.TemplateFingerprint == "" {
			continue
		}
		// Key provenance reads conflict when it names a fingerprint other
		// than the registered template's (lsigprovider.CompareTemplateFingerprint).
		if info.TemplateFingerprint == defect.TemplateFingerprint {
			defect.KeysFromStoredTemplate++
		} else {
			defect.ConflictAfterRepin++
		}
	}
	return defect, nil
}

// Entry is one repaired record.
type Entry struct {
	Defect
	Action Action
	// Archived is where a drop moved the template file in the new
	// generation, or "" when there was none to move.
	Archived string
}

// Result is a template repair that committed, or whose commit is uncertain
// (genstore.RootCommitUncertain), in which case GenerationID is the
// generation the store root may select.
type Result struct {
	GenerationID string
	Parent       string
	Entries      []Entry
	// Reconciled is what the reconciliation before the repair quarantined
	// or discarded, reported whether or not the repair then ran.
	Reconciled genstore.ReconcileReport
}

// Repair reconciles the generation store, as unlock does, then applies
// actions, keyed by canonical key type, to the selected generation's
// template record defects and commits the result as a new generation. It
// refuses, changing nothing but what reconciliation moved, a key type that
// is not a defect, a re-pin of a record with no template file, a defect left
// out, a generation with any other damage, and one no commit can supersede.
func Repair(opts Options, actions map[string]Action) (Result, error) {
	var result Result
	reconciled, err := genstore.ReconcileStoreRoot(opts.Paths, opts.Keyring)
	result.Reconciled = reconciled
	if err != nil {
		return result, fmt.Errorf("template repair refused: %w: %w", ErrOtherDamage, err)
	}
	preview, err := Inspect(opts)
	if err != nil {
		return result, err
	}
	entries, err := preview.Plan(actions)
	if err != nil {
		return result, err
	}
	now := time.Now()
	generationID, err := genstore.NewGenerationID(now)
	if err != nil {
		return result, err
	}
	result.GenerationID, result.Parent = generationID, preview.GenerationID
	_, mintErr := genstore.Mint(opts.Paths, genstore.MintRequest{
		GenerationID: generationID,
		Parent:       preview.GenerationID,
		Operation:    Operation,
		OperationID:  Operation + "-" + generationID,
		CreatedAt:    now,
		Integrity:    opts.Keyring,
		Apply: func(staged storepaths.GenPaths) error {
			for i := range entries {
				if err := apply(staged, opts.Keyring, &entries[i]); err != nil {
					return err
				}
			}
			return nil
		},
		ValidateCandidate: func(staged storepaths.GenPaths) error {
			return storevalidate.Candidate(validateOptions(opts, staged))
		},
	})
	if mintErr != nil {
		if genstore.RootCommitUncertain(mintErr) {
			return result, fmt.Errorf("template repair may have committed as generation %s: %w", generationID, mintErr)
		}
		// The root still selects the damaged generation. A failure after
		// publication leaves the successor for the next repair's or
		// unlock's reconciliation to quarantine.
		result.GenerationID = ""
		return result, fmt.Errorf("template repair failed before the store root moved: %w", mintErr)
	}
	published := opts.Paths.GenerationPaths(generationID)
	for i := range entries {
		if entries[i].Archived != "" {
			entries[i].Archived = published.DeletedKeyTypeTemplate(entries[i].KeyType)
		}
	}
	result.Entries = entries
	return result, nil
}

// Plan matches actions, keyed by canonical key type, to the classified
// defects, in preview order, and refuses what Repair refuses.
func (preview Preview) Plan(actions map[string]Action) ([]Entry, error) {
	entries, err := preview.plan(actions)
	if err != nil {
		return nil, fmt.Errorf("template repair refused: %w", err)
	}
	return entries, nil
}

func (preview Preview) plan(actions map[string]Action) ([]Entry, error) {
	if len(actions) == 0 {
		return nil, ErrNothingNamed
	}
	defects := make(map[string]Defect, len(preview.Defects))
	for _, defect := range preview.Defects {
		defects[defect.KeyType] = defect
	}
	for _, keyType := range slices.Sorted(maps.Keys(actions)) {
		defect, ok := defects[keyType]
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrNotDefective, keyType)
		}
		if action := actions[keyType]; !defect.Allows(action) {
			if action == ActionRepin {
				return nil, fmt.Errorf("%w: %s has no template file to pin (%s)", ErrRepinRefused, keyType, defect.Kind)
			}
			return nil, fmt.Errorf("unknown template repair action %q for %s", action, keyType)
		}
	}
	entries := make([]Entry, 0, len(preview.Defects))
	for _, defect := range preview.Defects {
		action, ok := actions[defect.KeyType]
		if !ok {
			return nil, fmt.Errorf("%w: %s (%s) is not named", ErrUnnamedDefect, defect.KeyType, defect.Kind)
		}
		entries = append(entries, Entry{Defect: defect, Action: action})
	}
	if preview.OtherDamage != nil {
		return nil, fmt.Errorf("%w: %w", ErrOtherDamage, preview.OtherDamage)
	}
	if preview.CommitBlocked != nil {
		return nil, fmt.Errorf("%w: %w", ErrCommitBlocked, preview.CommitBlocked)
	}
	return entries, nil
}

func apply(staged storepaths.GenPaths, kr *crypto.Keyring, entry *Entry) error {
	switch entry.Action {
	case ActionRepin:
		if _, err := templatelibrary.RepinTemplateRecordActive(staged, entry.KeyType, kr); err != nil {
			return fmt.Errorf("re-pin %s: %w", entry.KeyType, err)
		}
	case ActionDrop:
		archived, err := templatelibrary.DropTemplateRecordActive(staged, entry.KeyType)
		if err != nil {
			return fmt.Errorf("drop %s: %w", entry.KeyType, err)
		}
		// The staged path; Repair names it in the published generation.
		entry.Archived = archived
	}
	return nil
}

func validateOptions(opts Options, candidate storepaths.GenPaths) storevalidate.Options {
	return storevalidate.Options{
		Paths: opts.Paths, Candidate: candidate, Keyring: opts.Keyring,
		ExpectedRole: opts.Role, DataDir: opts.DataDir, Config: opts.Config,
	}
}
