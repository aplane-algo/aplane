// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package storevalidate owns side-effect-free semantic validation of a staged
// signer generation before it can become authoritative.
package storevalidate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aplane-algo/aplane/internal/asasetstore"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keyclass"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/storeinit"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// Options supplies the process context needed by the same gates used during
// runtime reload. Candidate is a staging capability and is never resolved from
// the committed store root.
type Options struct {
	Paths        storepaths.Paths
	Candidate    storepaths.GenPaths
	Keyring      *crypto.Keyring
	ExpectedRole noderole.Role
	DataDir      string
	Config       *serverconfig.ServerConfig
}

// FirstGeneration validates a store's staged first generation, for
// initialization and apstore rebuild.
func FirstGeneration(c storeinit.FirstGenerationCandidate) error {
	cfg, err := serverconfig.LoadServerConfig(c.DataDir)
	if err != nil {
		return fmt.Errorf("load signer config: %w", err)
	}
	return Candidate(Options{
		Paths: c.Paths, Candidate: c.Staged, Keyring: c.Keyring,
		ExpectedRole: c.Role, DataDir: c.DataDir, Config: &cfg,
	})
}

// Candidate verifies all destination authority and every managed credential
// without publishing runtime state or registering process-global providers.
func Candidate(opts Options) error {
	if err := requireKeyring(opts); err != nil {
		return err
	}
	if err := validateDeletedArchive(opts); err != nil {
		return err
	}
	if err := validateDestinationAuthority(opts, nil); err != nil {
		return err
	}

	scan, err := keys.ScanKeysDirectory(opts.Candidate, opts.Keyring, nil)
	if err != nil {
		return fmt.Errorf("credentials: %w", err)
	}
	return validateCredentialReport(opts.ExpectedRole, scan)
}

// DeletedArchiveMemberError is a deleted-archive member that does not
// verify. Unlock never opens archive members, but every generation commit
// does (Candidate), so it refuses a commit and not an unlock; `apadmin
// archive prune` removes it.
type DeletedArchiveMemberError struct {
	// Path is the member's canonical path in the generation, such as
	// deleted/keytypes/<key_type>.template.
	Path string
	// Prune is the selection archive prune takes to remove it: the member,
	// with the other half of an archived policy document and its sidecar.
	Prune []string
	Err   error
}

func (e *DeletedArchiveMemberError) Error() string {
	return fmt.Sprintf("verify %s: %v", e.Path, e.Err)
}

func (e *DeletedArchiveMemberError) Unwrap() error { return e.Err }

// TemplateContentDefectError is the first template or key-type content
// defect a generation holds. Path, for a defect about one entry of the
// keytypes namespace, is that entry's path.
type TemplateContentDefectError struct {
	Defect string
	Path   string
}

func (e *TemplateContentDefectError) Error() string {
	return "template/key-type content defect: " + e.Defect
}

// CredentialDefectError is the first entry of the keys namespace a
// credential scan could not load; its Warning names the file.
type CredentialDefectError struct {
	Warning keys.KeyScanWarning
}

func (e *CredentialDefectError) Error() string {
	return "credential content defect: " + e.Warning.Message()
}

// DeletedArchiveStrayError is a file in the deleted archive that is no
// member of it: its name is not one a member takes. Every commit refuses it,
// unlock never reads it, and archive prune, which takes members only, cannot
// remove it.
type DeletedArchiveStrayError struct {
	// Path is the file's path in the generation.
	Path   string
	Reason string
}

func (e *DeletedArchiveStrayError) Error() string { return fmt.Sprintf("%s %q", e.Reason, e.Path) }

// RecoveryDestination proves that destination authority and every
// unselected credential are healthy before a recovery-mode restore. Only the
// authenticated selectors being replaced may be skipped; the completed staged
// candidate is subsequently passed through Candidate with no exclusions.
func RecoveryDestination(opts Options, repairedSelectors map[string]bool) error {
	if len(repairedSelectors) == 0 {
		return fmt.Errorf("recovery restore has no authenticated credential selection")
	}
	if err := requireKeyring(opts); err != nil {
		return err
	}
	if err := genstore.ValidateCurrent(opts.Candidate); err != nil {
		return fmt.Errorf("destination generation structure: %w", err)
	}
	if err := validateDeletedArchive(opts); err != nil {
		return err
	}
	if err := validateDestinationAuthority(opts, nil); err != nil {
		return err
	}
	scan, err := keys.ScanKeysDirectory(opts.Candidate, opts.Keyring, repairedSelectors)
	if err != nil {
		return fmt.Errorf("unselected credentials: %w", err)
	}
	return validateCredentialReport(opts.ExpectedRole, scan)
}

// TemplateRepairDestination refuses what unlock would still refuse after a
// template repair: the generation's structure and archive limits, its node
// role, policy, ASA set and templates with only the template record defects
// of the repaired key types excluded, and every credential's content and the
// node role's key classes. It returns the credential scan it made, nil when
// the structure check stopped it first, so the caller need not scan again.
// What only a commit refuses is CommitOnlyDamage; the completed staged
// candidate is subsequently passed through Candidate with no exclusions.
func TemplateRepairDestination(opts Options, repairedKeyTypes map[string]bool) (*keys.KeyScanReport, error) {
	if len(repairedKeyTypes) == 0 {
		return nil, fmt.Errorf("template repair names no key type")
	}
	if err := requireKeyring(opts); err != nil {
		return nil, err
	}
	if err := genstore.ValidateCurrent(opts.Candidate); err != nil {
		return nil, fmt.Errorf("destination generation structure: %w", err)
	}
	scan, err := keys.ScanKeysDirectory(opts.Candidate, opts.Keyring, nil)
	if err != nil {
		return nil, fmt.Errorf("credentials: %w", err)
	}
	if err := validateDestinationAuthority(opts, repairedKeyTypes); err != nil {
		return scan, err
	}
	return scan, validateLoadableCredentials(opts.ExpectedRole, scan)
}

// CommitOnlyDamage is what every generation commit refuses (Candidate) and
// unlock never reads: a deleted-archive member that does not verify (a
// DeletedArchiveMemberError), and more cosigner credentials than a store
// holds. scan is the generation's credential scan.
func CommitOnlyDamage(opts Options, scan *keys.KeyScanReport) error {
	if err := requireKeyring(opts); err != nil {
		return err
	}
	if err := validateDeletedArchive(opts); err != nil {
		return err
	}
	return validateCosignerCredentialLimit(scan)
}

func requireKeyring(opts Options) error {
	if opts.Keyring == nil {
		return fmt.Errorf("candidate keyring is required")
	}
	return nil
}

// validateDeletedArchive checks the deleted archive's limits and opens every
// member.
func validateDeletedArchive(opts Options) error {
	if _, err := genstore.InspectDeletedArchive(opts.Candidate); err != nil {
		return fmt.Errorf("deleted archive: %w", err)
	}
	if err := validateDeletedArchiveEnvelopes(opts.Candidate, opts.Keyring); err != nil {
		return fmt.Errorf("deleted archive: %w", err)
	}
	return nil
}

// validateDestinationAuthority checks the node role, policy, ASA set and
// templates of a generation: what reload reads besides its credentials.
// repairedTemplates names the key types whose template record defects a
// template repair replaces; every other caller passes nil.
func validateDestinationAuthority(opts Options, repairedTemplates map[string]bool) error {
	role, err := noderole.LoadAndVerifyGenerationWithKeyring(
		opts.Paths, opts.Candidate, opts.Keyring,
	)
	if err != nil {
		return fmt.Errorf("node role: %w", err)
	}
	if role.Role != opts.ExpectedRole {
		return fmt.Errorf("node role %q does not match runtime role %q", role.Role, opts.ExpectedRole)
	}
	if _, err := policyruntime.Load(
		opts.ExpectedRole, opts.Config, opts.Candidate, opts.Keyring,
	); err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	// The ASA set is optional, but one that is present must authenticate.
	if _, err := asasetstore.Load(opts.Candidate, opts.Keyring); err != nil {
		return fmt.Errorf("asa set: %w", err)
	}

	manager := signertemplates.NewManager(opts.Paths)
	manager.ActivePaths = opts.Candidate
	report, err := manager.ValidateKeystoreTemplates(opts.Keyring)
	if err != nil {
		return fmt.Errorf("templates: %w", err)
	}
	if defects := report.ContentDefectsExcept(repairedTemplates); len(defects) > 0 {
		damaged := &TemplateContentDefectError{Defect: defects[0].Text}
		if defects[0].Entry != "" {
			damaged.Path = filepath.Join(opts.Candidate.KeyTypeRecordsDir(), defects[0].Entry)
		}
		return damaged
	}

	return nil
}

func validateDeletedArchiveEnvelopes(candidate storepaths.GenPaths, kr *crypto.Keyring) error {
	entries, _, err := genstore.ListDeletedArchive(candidate)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		base := filepath.Base(entry.Path)
		var ctx crypto.ObjectContext
		switch filepath.ToSlash(filepath.Dir(entry.Path)) {
		case "deleted/keys":
			selector, class, ok := keys.ParseManagedCredentialFilename(base)
			if !ok {
				return &DeletedArchiveStrayError{Path: entry.Path, Reason: "unsupported deleted credential"}
			}
			switch class {
			case keys.ManagedCredentialAccount:
				ctx = crypto.AccountKeyContext(selector)
			case keys.ManagedCredentialCosigner:
				ctx = crypto.CosignerCredentialContext(selector)
			default:
				return &DeletedArchiveStrayError{Path: entry.Path, Reason: "unsupported deleted credential class in"}
			}
		case "deleted/keytypes":
			if !strings.HasSuffix(base, ".template") {
				return &DeletedArchiveStrayError{Path: entry.Path, Reason: "unsupported deleted template"}
			}
			ctx = crypto.KeyTypeTemplateContext(strings.TrimSuffix(base, ".template"))
		case "deleted/policies":
			if err := verifyArchivedPolicy(candidate, entry.Path, kr); err != nil {
				return err
			}
			continue
		default:
			return &DeletedArchiveStrayError{Path: entry.Path, Reason: "deleted member is outside closed namespaces:"}
		}
		data, _, err := fsutil.ReadRegularFileLimited(
			filepath.Join(candidate.Dir(), filepath.FromSlash(entry.Path)),
			crypto.MaxStandaloneEnvelopeBytes,
		)
		if err != nil {
			return &DeletedArchiveMemberError{Path: entry.Path, Prune: []string{entry.Path}, Err: err}
		}
		plaintext, err := kr.Open(data, ctx)
		if err != nil {
			return &DeletedArchiveMemberError{Path: entry.Path, Prune: []string{entry.Path}, Err: err}
		}
		crypto.ZeroBytes(plaintext)
	}
	return nil
}

// verifyArchivedPolicy checks one member of the archived cosigner policies.
// Archived documents are plaintext, so each must still verify against its
// sidecar; a sidecar must sit beside its document.
func verifyArchivedPolicy(candidate storepaths.GenPaths, relative string, kr *crypto.Keyring) error {
	path := filepath.Join(candidate.Dir(), filepath.FromSlash(relative))
	if docPath, ok := strings.CutSuffix(path, ".hmac"); ok {
		if _, err := os.Lstat(docPath); err != nil {
			return &DeletedArchiveMemberError{Path: relative, Prune: []string{relative},
				Err: fmt.Errorf("archived policy sidecar has no document: %w", err)}
		}
		return nil
	}
	if !strings.HasSuffix(relative, ".json") {
		return &DeletedArchiveStrayError{Path: relative, Reason: "unsupported deleted policy"}
	}
	// A document and its sidecar are one record to archive prune.
	prune := []string{relative}
	sidecarPath := policy.PolicyIntegritySidecarPath(path)
	if _, err := os.Lstat(sidecarPath); err == nil {
		prune = append(prune, relative+".hmac")
	}
	data, _, err := fsutil.ReadRegularFileLimited(path, 1<<20)
	if err != nil {
		return &DeletedArchiveMemberError{Path: relative, Prune: prune, Err: err}
	}
	sidecar, err := policy.LoadPolicyIntegritySidecar(sidecarPath)
	if err != nil {
		return &DeletedArchiveMemberError{Path: relative, Prune: prune, Err: err}
	}
	if err := policy.VerifyPolicyIntegrity(data, sidecar, kr); err != nil {
		return &DeletedArchiveMemberError{Path: relative, Prune: prune, Err: err}
	}
	return nil
}

func validateCredentialReport(role noderole.Role, scan *keys.KeyScanReport) error {
	if err := validateLoadableCredentials(role, scan); err != nil {
		return err
	}
	return validateCosignerCredentialLimit(scan)
}

// validateLoadableCredentials refuses what a reload refuses in a credential
// scan: a credential it could not load, and a key class the node role
// forbids.
func validateLoadableCredentials(role noderole.Role, scan *keys.KeyScanReport) error {
	if len(scan.Warnings) > 0 {
		return &CredentialDefectError{Warning: scan.Warnings[0]}
	}
	keyTypes := make(map[string]string, len(scan.Keys))
	for selector, info := range scan.Keys {
		keyTypes[selector] = info.KeyType
	}
	if err := keyclass.ValidateKeyTypesAllowedForNodeRole(role, keyTypes); err != nil {
		return fmt.Errorf("credential inventory: %w", err)
	}
	return nil
}

// validateCosignerCredentialLimit is the commit-time cap on cosigner
// credentials; a reload does not apply it.
func validateCosignerCredentialLimit(scan *keys.KeyScanReport) error {
	cosignerKeys := 0
	for _, info := range scan.Keys {
		if info.Category == keys.CategoryWitness {
			cosignerKeys++
		}
	}
	if cosignerKeys > keys.MaxCosignerCredentials {
		return fmt.Errorf("credential inventory: %w: %d cosigner credentials, limit %d",
			keys.ErrCosignerCredentialLimit, cosignerKeys, keys.MaxCosignerCredentials)
	}
	return nil
}
