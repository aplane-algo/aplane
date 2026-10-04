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
	if opts.Keyring == nil {
		return fmt.Errorf("candidate keyring is required")
	}
	if err := validateDestinationAuthority(opts); err != nil {
		return err
	}

	scan, err := keys.ScanKeysDirectoryWithKeyringReportActive(opts.Candidate, opts.Keyring)
	if err != nil {
		return fmt.Errorf("credentials: %w", err)
	}
	return validateCredentialReport(opts.ExpectedRole, scan)
}

// RecoveryDestination proves that destination authority and every
// unselected credential are healthy before a recovery-mode restore. Only the
// authenticated selectors being replaced may be skipped; the completed staged
// candidate is subsequently passed through Candidate with no exclusions.
func RecoveryDestination(opts Options, repairedSelectors map[string]bool) error {
	if len(repairedSelectors) == 0 {
		return fmt.Errorf("recovery restore has no authenticated credential selection")
	}
	if err := genstore.ValidateCurrent(opts.Candidate); err != nil {
		return fmt.Errorf("destination generation structure: %w", err)
	}
	if err := validateDestinationAuthority(opts); err != nil {
		return err
	}
	scan, err := keys.ScanKeysDirectoryWithKeyringReportExcludingSelectorsActive(
		opts.Candidate, opts.Keyring, repairedSelectors,
	)
	if err != nil {
		return fmt.Errorf("unselected credentials: %w", err)
	}
	return validateCredentialReport(opts.ExpectedRole, scan)
}

func validateDestinationAuthority(opts Options) error {
	if opts.Keyring == nil {
		return fmt.Errorf("candidate keyring is required")
	}
	if _, err := genstore.InspectDeletedArchive(opts.Candidate); err != nil {
		return fmt.Errorf("deleted archive: %w", err)
	}
	if err := validateDeletedArchiveEnvelopes(opts.Candidate, opts.Keyring); err != nil {
		return fmt.Errorf("deleted archive: %w", err)
	}
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
		opts.ExpectedRole, opts.DataDir, opts.Config, opts.Candidate, opts.Keyring,
	); err != nil {
		return fmt.Errorf("policy: %w", err)
	}

	manager := signertemplates.NewManager(opts.Paths)
	manager.ActivePaths = opts.Candidate
	report, err := manager.ValidateKeystoreTemplates(opts.Keyring)
	if err != nil {
		return fmt.Errorf("templates: %w", err)
	}
	if defects := report.ContentDefectKeyTypes(); len(defects) > 0 {
		return fmt.Errorf("template/key-type content defect: %s", defects[0])
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
				return fmt.Errorf("unsupported deleted credential %q", entry.Path)
			}
			switch class {
			case keys.ManagedCredentialAccount:
				ctx = crypto.AccountKeyContext(selector)
			case keys.ManagedCredentialCosigner:
				ctx = crypto.CosignerCredentialContext(selector)
			default:
				return fmt.Errorf("unsupported deleted credential class in %q", entry.Path)
			}
		case "deleted/keytypes":
			if !strings.HasSuffix(base, ".template") {
				return fmt.Errorf("unsupported deleted template %q", entry.Path)
			}
			ctx = crypto.KeyTypeTemplateContext(strings.TrimSuffix(base, ".template"))
		case "deleted/policies":
			if err := verifyArchivedPolicy(candidate, entry.Path, kr); err != nil {
				return err
			}
			continue
		default:
			return fmt.Errorf("deleted member is outside closed namespaces: %q", entry.Path)
		}
		data, _, err := fsutil.ReadRegularFileLimited(
			filepath.Join(candidate.Dir(), filepath.FromSlash(entry.Path)),
			crypto.MaxStandaloneEnvelopeBytes,
		)
		if err != nil {
			return err
		}
		plaintext, err := kr.Open(data, ctx)
		if err != nil {
			return fmt.Errorf("verify %s: %w", entry.Path, err)
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
			return fmt.Errorf("archived policy sidecar %q has no document: %w", relative, err)
		}
		return nil
	}
	data, _, err := fsutil.ReadRegularFileLimited(path, 1<<20)
	if err != nil {
		return err
	}
	sidecar, err := policy.LoadPolicyIntegritySidecar(policy.PolicyIntegritySidecarPath(path))
	if err != nil {
		return fmt.Errorf("verify %s: %w", relative, err)
	}
	if err := policy.VerifyPolicyIntegrity(data, sidecar, kr); err != nil {
		return fmt.Errorf("verify %s: %w", relative, err)
	}
	return nil
}

func validateCredentialReport(role noderole.Role, scan *keys.KeyScanReport) error {
	if len(scan.Warnings) > 0 {
		return fmt.Errorf("credential content defect: %s", scan.Warnings[0].Message())
	}
	keyTypes := make(map[string]string, len(scan.Keys))
	cosignerKeys := 0
	for selector, info := range scan.Keys {
		keyTypes[selector] = info.KeyType
		if info.Category == keys.CategoryWitness {
			cosignerKeys++
		}
	}
	if cosignerKeys > keys.MaxCosignerCredentials {
		return fmt.Errorf("credential inventory: %w: %d cosigner credentials, limit %d",
			keys.ErrCosignerCredentialLimit, cosignerKeys, keys.MaxCosignerCredentials)
	}
	if err := keyclass.ValidateKeyTypesAllowedForNodeRole(role, keyTypes); err != nil {
		return fmt.Errorf("credential inventory: %w", err)
	}
	return nil
}
