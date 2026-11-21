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
// and rescue").
package templaterepair

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/noderole"
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
	// ErrNothingNamed refuses a repair that names no key type.
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

// Defect is one template record defect and what a repair would do to it.
type Defect struct {
	KeyType string
	Kind    signertemplates.RecordDefectKind
	// TemplateType is the record's template type; it is empty for a
	// disabled record without template file.
	TemplateType  templatestore.TemplateType
	DefaultAction Action
	// Keys counts the aplane keys of this key type.
	Keys int
	// ConflictAfterRepin counts the keys whose recorded template fingerprint
	// would read conflict after a re-pin: an external edit's only.
	ConflictAfterRepin int
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
}

// Inspect classifies every template record defect in the selected
// generation, with the classification reload uses.
func Inspect(opts Options) (Preview, error) {
	preview := Preview{GenerationID: opts.Current.GenerationID()}
	manager := signertemplates.NewManager(opts.Paths)
	manager.ActivePaths = opts.Current
	report, err := manager.ValidateKeystoreTemplates(opts.Keyring)
	if err != nil {
		return Preview{}, fmt.Errorf("classify template records: %w", err)
	}
	recordDefects := report.RecordDefects()
	if len(recordDefects) == 0 {
		return preview, nil
	}
	scan, err := keys.ScanKeysDirectory(opts.Current, opts.Keyring, nil)
	if err != nil {
		return Preview{}, fmt.Errorf("count keys: %w", err)
	}
	defective := make(map[string]bool, len(recordDefects))
	for _, recordDefect := range recordDefects {
		defect, err := describe(opts, recordDefect, scan)
		if err != nil {
			return Preview{}, err
		}
		preview.Defects = append(preview.Defects, defect)
		defective[defect.KeyType] = true
	}
	preview.OtherDamage = storevalidate.TemplateRepairDestination(validateOptions(opts, opts.Current), defective)
	return preview, nil
}

func describe(opts Options, recordDefect signertemplates.RecordDefect, scan *keys.KeyScanReport) (Defect, error) {
	defect := Defect{
		KeyType:       recordDefect.KeyType,
		Kind:          recordDefect.Kind,
		TemplateType:  recordDefect.TemplateType,
		DefaultAction: ActionDrop,
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
		defect.DefaultAction = ActionRepin
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
		// Key provenance reads conflict when it names a fingerprint other
		// than the registered template's (lsigprovider.CompareTemplateFingerprint).
		if defect.TemplateFingerprint != "" && info.TemplateFingerprint != "" && info.TemplateFingerprint != defect.TemplateFingerprint {
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

// Result is a template repair that committed, or whose commit is uncertain.
type Result struct {
	GenerationID string
	Parent       string
	Entries      []Entry
	// CommitUncertain is set when the store root may select GenerationID
	// although Repair returned an error.
	CommitUncertain bool
}

// Repair applies actions, keyed by canonical key type, to the selected
// generation's template record defects and commits the result as a new
// generation. It refuses, changing nothing, a key type that is not a
// defect, a re-pin of a record with no template file, a defect left out,
// and a generation with any other damage.
func Repair(opts Options, actions map[string]Action) (Result, error) {
	preview, err := Inspect(opts)
	if err != nil {
		return Result{}, err
	}
	entries, err := preview.Plan(actions)
	if err != nil {
		return Result{}, err
	}
	now := time.Now()
	generationID, err := genstore.NewGenerationID(now)
	if err != nil {
		return Result{}, err
	}
	result := Result{GenerationID: generationID, Parent: preview.GenerationID}
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
			result.CommitUncertain = true
			return result, fmt.Errorf("template repair may have committed as generation %s: %w", generationID, mintErr)
		}
		return Result{}, fmt.Errorf("template repair failed; nothing was committed: %w", mintErr)
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
				return nil, fmt.Errorf("%w: %s is an %s", ErrRepinRefused, keyType, defect.Kind)
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
