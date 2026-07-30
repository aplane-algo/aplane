// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storepass

import (
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/rotationinventory"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

type Logger func(format string, args ...any)

type RotateOptions struct {
	Logf Logger

	// AfterRootCommit updates passphrase helpers after the new cryptographic
	// root becomes authoritative. Its failure is a warning, never a rollback
	// request or a barrier to completing the already-committed rotation.
	AfterRootCommit func() error
}

type RotateResult struct {
	KeysMigrated             int
	TemplatesMigrated        int
	RecoveredFilesMigrated   int
	PolicySidecarsMigrated   int
	NodeRoleSidecarsMigrated int
	PriorGenerations         int
	HelperWarning            string
	RootCommitted            bool
	RotationPending          bool
}

func VerifyCurrentPassphrase(paths storepaths.Paths, identityID string, passphrase []byte) error {
	kr, err := loadAndVerifyCurrentKeyring(paths, identityID, passphrase)
	if err != nil {
		return err
	}
	kr.Zero()
	return nil
}

// Rotate appends a fresh key term, commits that root under newPassphrase, and
// synchronously completes the snapshot-pinned migration. Once StartRotation
// commits, the new passphrase is authoritative. Later failures deliberately
// leave a resumable pending root instead of attempting cryptographic rollback.
//
// The caller holds the identity mutation lock.
func Rotate(
	paths storepaths.Paths,
	identityID string,
	oldPassphrase, newPassphrase []byte,
	opts RotateOptions,
) (RotateResult, error) {
	var result RotateResult
	metaDir := paths.KeystoreMetadataDir(identityID)
	if !crypto.KeyringExistsIn(metaDir) {
		return result, fmt.Errorf("no keyring found in %s - store not initialized", metaDir)
	}
	if len(oldPassphrase) == 0 || len(newPassphrase) == 0 {
		return result, fmt.Errorf("current and new passphrases are required")
	}

	kr, err := loadAndVerifyCurrentKeyring(paths, identityID, oldPassphrase)
	if err != nil {
		return result, err
	}
	defer kr.Zero()
	if state, pending := kr.PendingRotation(); pending {
		return result, fmt.Errorf(
			"passphrase change blocked: %w (%d -> %d); unlock with the committed passphrase to resume",
			crypto.ErrRotationAlreadyPending,
			state.FromTerm,
			state.ToTerm,
		)
	}

	logf(opts.Logf, "starting durable key-term rotation")
	snapshot, startErr := rotationinventory.StartRotation(
		paths,
		identityID,
		kr,
		newPassphrase,
	)
	_, rootCommitted := kr.PendingRotation()
	if rootCommitted {
		result.RootCommitted = true
		result.RotationPending = true
		result.PriorGenerations = len(kr.HistoricalGenerationAnchors())
	}
	if startErr != nil {
		if result.RootCommitted {
			updatePassphraseHelper(&result, opts)
			return result, fmt.Errorf(
				"new passphrase committed but rotation requires recovery: %w",
				startErr,
			)
		}
		if errors.Is(startErr, crypto.ErrRotationCommitStateUnknown) {
			return result, fmt.Errorf(
				"rotation root commit state is unknown; stop and reopen the store with the new passphrase first, then try the old passphrase only if the new one is rejected: %w",
				startErr,
			)
		}
		return result, startErr
	}
	if snapshot == nil {
		return result, fmt.Errorf("rotation root committed without a snapshot")
	}
	if !rootCommitted {
		return result, fmt.Errorf("rotation returned without committing a pending root")
	}
	updatePassphraseHelper(&result, opts)

	logf(
		opts.Logf,
		"completing key-term rotation %d -> %d over %d pinned artifacts",
		snapshot.FromTerm,
		snapshot.ToTerm,
		len(snapshot.Inventory),
	)
	completion, err := rotationinventory.CompleteRotation(
		paths,
		identityID,
		kr,
		newPassphrase,
	)
	applyCompletionReport(&result, completion)
	if err != nil {
		if !result.RotationPending {
			return result, fmt.Errorf(
				"new passphrase committed and rotation closed, but final cleanup requires recovery: %w",
				err,
			)
		}
		return result, fmt.Errorf(
			"new passphrase committed but rotation remains resumable: %w",
			err,
		)
	}
	result.RotationPending = false
	return result, nil
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

func applyCompletionReport(result *RotateResult, completion *rotationinventory.CompletionReport) {
	if completion == nil || completion.Resume == nil {
		return
	}
	resume := completion.Resume
	result.KeysMigrated = resume.KeysMigrated
	result.TemplatesMigrated = resume.TemplatesMigrated
	result.RecoveredFilesMigrated = resume.RecoveredFilesMigrated
	result.PolicySidecarsMigrated = resume.PolicySidecarsMigrated
	result.NodeRoleSidecarsMigrated = resume.NodeRoleSidecarsMigrated
	if completion.RootClosed {
		result.RotationPending = false
	}
}

func logf(log Logger, format string, args ...any) {
	if log != nil {
		log(format, args...)
	}
}

// loadAndVerifyCurrentKeyring opens the store's keyring with the current
// passphrase. The unwrap is the verification: there is no separate verifier.
//
// The caller owns the returned keyring and must Zero it.
func loadAndVerifyCurrentKeyring(
	paths storepaths.Paths,
	identityID string,
	passphrase []byte,
) (*crypto.Keyring, error) {
	kr, err := crypto.OpenKeyringStore(
		paths.KeystoreMetadataDir(identityID),
		passphrase,
	)
	if err != nil {
		if errors.Is(err, crypto.ErrRotationPending) {
			return nil, err
		}
		return nil, fmt.Errorf("current passphrase verification failed: %w", err)
	}
	return kr, nil
}
