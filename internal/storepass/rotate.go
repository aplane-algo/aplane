// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storepass

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatestore"
	"github.com/aplane-algo/aplane/internal/testcheckpoint"
)

type Logger func(format string, args ...any)

type RotateOptions struct {
	Logf Logger

	// AfterRootCommit updates passphrase helpers after the new cryptographic
	// root becomes authoritative. Its failure is a warning, never a rollback
	// request.
	AfterRootCommit func() error
}

type RotateResult struct {
	KeysMigrated             int
	TemplatesMigrated        int
	PolicySidecarsMigrated   int
	NodeRoleSidecarsMigrated int
	PriorGenerations         int
	HelperWarning            string
	RootCommitted            bool
}

func VerifyCurrentPassphrase(paths storepaths.Paths, passphrase []byte) error {
	_, kr, err := genstore.ResolveStoreRoot(paths, passphrase)
	if err != nil {
		return fmt.Errorf("current passphrase verification failed: %w", err)
	}
	kr.Zero()
	return nil
}

// Rotate freezes and seals the selected generation under the old term,
// constructs a complete successor under a fresh settled term, then replaces
// store-root.enc once so the new passphrase, term, and generation become
// authoritative together. There is no resumable or partially published
// rotation state.
//
// The caller holds the store mutation lock and maintenance fence.
func Rotate(
	paths storepaths.Paths,
	oldPassphrase, newPassphrase []byte,
	opts RotateOptions,
) (RotateResult, error) {
	var result RotateResult
	if !crypto.StoreRootExistsIn(paths.KeystoreMetadataDir()) {
		return result, fmt.Errorf("no store root found in %s - store not initialized", paths.KeystoreMetadataDir())
	}
	if len(oldPassphrase) == 0 || len(newPassphrase) == 0 {
		return result, fmt.Errorf("current and new passphrases are required")
	}

	selected, oldKeyring, err := genstore.OpenStoreRootSelection(paths, oldPassphrase)
	if err != nil {
		return result, fmt.Errorf("current passphrase verification failed: %w", err)
	}
	defer oldKeyring.Zero()
	active, err := genstore.ResolveStoreRootWithKeyring(paths, oldKeyring)
	if err != nil {
		return result, err
	}
	if active.GenerationID() != selected.GenerationID() {
		return result, fmt.Errorf("store root selection changed during changepass preflight")
	}
	preview, err := genstore.InspectStoreRoot(paths, oldKeyring, nil)
	if err != nil {
		return result, err
	}
	if len(preview.DiscardedStaging) != 0 || len(preview.Quarantined) != 0 || preview.RetainedUnsealedParent != "" {
		return result, fmt.Errorf("passphrase change requires a reconciled generation store")
	}

	now := time.Now()
	logf(opts.Logf, "freezing selected generation %s", active.GenerationID())
	if err := genstore.WriteSeal(active, now.Unix(), oldKeyring); err != nil {
		return result, fmt.Errorf("seal outgoing generation: %w", err)
	}
	outgoingSeal, err := genstore.ReadSeal(active, oldKeyring)
	if err != nil {
		return result, fmt.Errorf("read outgoing generation seal: %w", err)
	}
	outgoingManifest, err := genstore.ReadManifest(active)
	if err != nil {
		return result, fmt.Errorf("read outgoing generation manifest: %w", err)
	}
	rollbackCapability, cleanRollback, err := genstore.CarryRollbackCapability(
		outgoingManifest,
		outgoingSeal.Inventory,
	)
	if err != nil {
		return result, fmt.Errorf("evaluate restore rollback capability: %w", err)
	}
	if outgoingManifest.RollbackCapability != nil && !cleanRollback {
		logf(opts.Logf, "dropping diverged restore rollback capability")
	}
	anchors, err := collectHistoricalAnchors(paths, active, oldKeyring)
	if err != nil {
		return result, err
	}
	result.PriorGenerations = len(anchors)

	successorKeyring, err := crypto.NewSuccessorKeyring(oldKeyring, anchors)
	if err != nil {
		return result, fmt.Errorf("create successor keyring: %w", err)
	}
	defer successorKeyring.Zero()
	generationID, err := genstore.NewGenerationID(now)
	if err != nil {
		return result, err
	}

	logf(opts.Logf, "staging fresh-term successor %s", generationID)
	_, mintErr := genstore.Mint(paths, genstore.MintRequest{
		GenerationID:               generationID,
		Parent:                     active.GenerationID(),
		Integrity:                  oldKeyring,
		OutgoingSealAlreadyWritten: true,
		ReplacementKeyring:         successorKeyring,
		ReplacementPassphrase:      newPassphrase,
		Operation:                  "store-passphrase-change",
		OperationID:                "changepass-" + generationID,
		RollbackCapability:         rollbackCapability,
		CreatedAt:                  now,
		AfterPublication: func() error {
			return testcheckpoint.Reach("changepass.successor_published")
		},
		AfterRootCommit: func() error {
			return testcheckpoint.Reach("changepass.store_root_replaced")
		},
		Apply: func(staged storepaths.GenPaths) error {
			counts, err := reencryptSealedGeneration(paths, active, staged, oldKeyring, successorKeyring, now)
			if err != nil {
				return err
			}
			result.KeysMigrated = counts.keys
			result.TemplatesMigrated = counts.templates
			result.PolicySidecarsMigrated = 1
			result.NodeRoleSidecarsMigrated = 1
			return nil
		},
	})
	if mintErr != nil {
		// A classified durability error can accompany a visible committed root.
		// Only the new root itself may establish that point of no return.
		if committedGeneration, opened, openErr := openCommittedGeneration(paths, newPassphrase); openErr == nil && committedGeneration == generationID {
			opened.Zero()
			result.RootCommitted = true
			updatePassphraseHelper(&result, opts)
			return result, fmt.Errorf("new passphrase and generation committed but root durability requires recovery confirmation: %w", mintErr)
		}
		return result, mintErr
	}

	result.RootCommitted = true
	updatePassphraseHelper(&result, opts)
	return result, nil
}

func openCommittedGeneration(paths storepaths.Paths, passphrase []byte) (string, *crypto.Keyring, error) {
	active, kr, err := genstore.ResolveStoreRoot(paths, passphrase)
	if err != nil {
		return "", nil, err
	}
	return active.GenerationID(), kr, nil
}

func collectHistoricalAnchors(
	paths storepaths.Paths,
	active storepaths.GenPaths,
	kr *crypto.Keyring,
) ([]crypto.HistoricalGenerationAnchor, error) {
	entries, err := os.ReadDir(paths.GenerationsDir())
	if err != nil {
		return nil, err
	}
	anchors := make([]crypto.HistoricalGenerationAnchor, 0, len(entries))
	for _, entry := range entries {
		id := entry.Name()
		if id == active.GenerationID() {
			continue
		}
		if err := storepaths.ValidateGenerationID(id); err != nil || !entry.IsDir() {
			return nil, fmt.Errorf("unexpected retained generation entry %q", id)
		}
		gen := paths.GenerationPaths(id)
		if anchor, ok := kr.HistoricalGenerationAnchor(id); ok {
			if err := genstore.ValidateAnchoredSealed(gen, anchor, kr); err != nil {
				return nil, fmt.Errorf("validate anchored generation %s: %w", id, err)
			}
			anchors = append(anchors, anchor)
			continue
		}
		anchor, err := genstore.BuildHistoricalAnchor(gen, kr)
		if err != nil {
			return nil, fmt.Errorf("anchor retained generation %s: %w", id, err)
		}
		anchors = append(anchors, anchor)
	}
	activeAnchor, err := genstore.BuildHistoricalAnchor(active, kr)
	if err != nil {
		return nil, fmt.Errorf("anchor outgoing generation: %w", err)
	}
	anchors = append(anchors, activeAnchor)
	slices.SortFunc(anchors, func(a, b crypto.HistoricalGenerationAnchor) int {
		return strings.Compare(a.GenerationID, b.GenerationID)
	})
	return anchors, nil
}

type migrationCounts struct {
	keys      int
	templates int
}

func reencryptSealedGeneration(
	paths storepaths.Paths,
	from, staged storepaths.GenPaths,
	oldKeyring, successorKeyring *crypto.Keyring,
	now time.Time,
) (migrationCounts, error) {
	var counts migrationCounts
	seal, err := genstore.ReadSeal(from, oldKeyring)
	if err != nil {
		return counts, err
	}
	members := make(map[string][]byte, len(seal.Inventory))
	for _, entry := range seal.Inventory {
		data, _, err := fsutil.ReadRegularFileLimited(
			filepath.Join(from.Dir(), filepath.FromSlash(entry.Path)),
			entry.Size,
		)
		if err != nil {
			return counts, fmt.Errorf("read sealed member %s: %w", entry.Path, err)
		}
		if err := genstore.VerifyBytesAgainstSeal(seal, entry.Path, data); err != nil {
			return counts, fmt.Errorf("verify sealed member %s: %w", entry.Path, err)
		}
		members[entry.Path] = data

		ctx, envelope, kind, err := generationMemberContext(entry.Path)
		if err != nil {
			return counts, err
		}
		output := data
		if envelope {
			if entry.Term != oldKeyring.CurrentTerm() {
				return counts, fmt.Errorf("sealed current member %s has term %d, want %d", entry.Path, entry.Term, oldKeyring.CurrentTerm())
			}
			plaintext, err := oldKeyring.Open(data, ctx)
			if err != nil {
				return counts, fmt.Errorf("open sealed member %s: %w", entry.Path, err)
			}
			sealed, sealErr := successorKeyring.Seal(plaintext, ctx)
			crypto.ZeroBytes(plaintext)
			if sealErr != nil {
				return counts, fmt.Errorf("seal successor member %s: %w", entry.Path, sealErr)
			}
			output = sealed
			switch kind {
			case "key":
				counts.keys++
			case "template":
				counts.templates++
			}
		} else if entry.Term != 0 {
			return counts, fmt.Errorf("plaintext member %s carries term %d", entry.Path, entry.Term)
		}
		if entry.Path == "policy.yaml.hmac" || entry.Path == "node.yaml.hmac" {
			continue
		}
		if err := os.WriteFile(filepath.Join(staged.Dir(), filepath.FromSlash(entry.Path)), output, 0o600); err != nil {
			return counts, err
		}
	}

	nodeBytes, _, err := fsutil.ReadRegularFile(paths.NodeRolePath())
	if err != nil {
		return counts, err
	}
	nodeDocument, err := noderole.ParseDocument(nodeBytes)
	if err != nil {
		return counts, err
	}

	policyBytes := members["policy.yaml"]
	switch nodeDocument.Role {
	case noderole.RoleSigner:
		if _, err := policy.ParseStoredConfig(policyBytes); err != nil {
			return counts, fmt.Errorf("parse outgoing signer policy: %w", err)
		}
	case noderole.RoleSentry:
		if _, err := policy.ParseStoredSentryConfig(policyBytes); err != nil {
			return counts, fmt.Errorf("parse outgoing sentry policy: %w", err)
		}
	default:
		return counts, fmt.Errorf("unsupported node role %q", nodeDocument.Role)
	}
	policySidecar, err := policy.ParsePolicyIntegritySidecar(members["policy.yaml.hmac"])
	if err != nil {
		return counts, err
	}
	if err := policy.VerifyPolicyIntegrity(policyBytes, policySidecar, oldKeyring); err != nil {
		return counts, fmt.Errorf("verify outgoing policy sidecar: %w", err)
	}
	newPolicySidecar, err := policy.SignPolicyIntegrity(policyBytes, successorKeyring, now)
	if err != nil {
		return counts, err
	}
	newPolicyBytes, err := policy.MarshalPolicyIntegritySidecar(newPolicySidecar)
	if err != nil {
		return counts, err
	}
	if err := os.WriteFile(staged.PolicyIntegritySidecar(), newPolicyBytes, 0o600); err != nil {
		return counts, err
	}

	nodeSidecar, err := noderole.ParseSidecar(members["node.yaml.hmac"])
	if err != nil {
		return counts, err
	}
	if err := noderole.Verify(nodeBytes, nodeSidecar, oldKeyring); err != nil {
		return counts, fmt.Errorf("verify outgoing node role sidecar: %w", err)
	}
	newNodeSidecar, err := noderole.Sign(nodeBytes, successorKeyring, now, nodeSidecar.NodeMTimeNS)
	if err != nil {
		return counts, err
	}
	newNodeBytes, err := noderole.MarshalSidecar(newNodeSidecar)
	if err != nil {
		return counts, err
	}
	if err := os.WriteFile(staged.NodeRoleIntegritySidecar(), newNodeBytes, 0o600); err != nil {
		return counts, err
	}
	return counts, nil
}

func generationMemberContext(relative string) (crypto.ObjectContext, bool, string, error) {
	base := filepath.Base(relative)
	switch {
	case relative == "policy.yaml", relative == "policy.yaml.hmac", relative == "node.yaml.hmac":
		return crypto.ObjectContext{}, false, "", nil
	case strings.HasPrefix(relative, "keys/"), strings.HasPrefix(relative, "deleted/keys/"):
		if strings.HasSuffix(base, keys.WitnessPublicMetadataSuffix) {
			return crypto.ObjectContext{}, false, "", nil
		}
		selector, class, ok := keys.ParseManagedCredentialFilename(base)
		if !ok {
			return crypto.ObjectContext{}, false, "", fmt.Errorf("unsupported credential member %q", relative)
		}
		switch class {
		case keys.ManagedCredentialAccount:
			return crypto.AccountKeyContext(selector), true, "key", nil
		case keys.ManagedCredentialSentry:
			return crypto.SentryCredentialContext(selector), true, "key", nil
		default:
			return crypto.ObjectContext{}, false, "", fmt.Errorf("unsupported credential class %q", class)
		}
	case strings.HasPrefix(relative, "keytypes/"), strings.HasPrefix(relative, "deleted/keytypes/"):
		if strings.HasSuffix(base, templatestore.TemplateFileExtension) {
			ctx, err := templatestore.TemplateContextForFile(base)
			return ctx, true, "template", err
		}
		if strings.HasSuffix(base, ".json") && strings.HasPrefix(relative, "keytypes/") {
			return crypto.ObjectContext{}, false, "", nil
		}
	}
	return crypto.ObjectContext{}, false, "", fmt.Errorf("unsupported generation member %q", relative)
}

func updatePassphraseHelper(result *RotateResult, opts RotateOptions) {
	if opts.AfterRootCommit == nil {
		return
	}
	if err := opts.AfterRootCommit(); err != nil {
		result.HelperWarning = fmt.Sprintf(
			"passphrase changed, but helper update failed; unlock manually with the new passphrase: %v",
			err,
		)
		logf(opts.Logf, "%s", result.HelperWarning)
	}
}

func logf(log Logger, format string, args ...any) {
	if log != nil {
		log(format, args...)
	}
}
