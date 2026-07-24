// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package recovered

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const (
	// ActivationJournalSchema identifies the decrypted activation journal.
	ActivationJournalSchema = "aplane.recovered-activation-journal.v1"
	// RollbackSnapshotSchema identifies the decrypted pre-activation snapshot.
	RollbackSnapshotSchema = "aplane.recovered-rollback-snapshot.v1"
	// ActivationStagingPrefix identifies unpublished activation preparation.
	ActivationStagingPrefix = ".activation-preparing-"
)

// ActivationState is the durable reconciliation direction.
type ActivationState string

const (
	// ActivationApplying means activation may have partially changed active
	// state and must be explicitly resumed or rolled back.
	ActivationApplying ActivationState = "applying"
	// ActivationRollingBack means only rollback may continue.
	ActivationRollingBack ActivationState = "rolling_back"
)

// ActivationJournal pins the operator-reviewed activation intent.
type ActivationJournal struct {
	Schema                       string          `json:"schema"`
	RestoreID                    string          `json:"restore_id"`
	CreatedAt                    time.Time       `json:"created_at"`
	State                        ActivationState `json:"state"`
	ReviewToken                  string          `json:"review_token"`
	DestinationPolicySHA256      string          `json:"destination_policy_sha256"`
	DestinationApprovalMode      string          `json:"destination_approval_mode"`
	AcknowledgePolicyTransition  bool            `json:"acknowledge_policy_transition"`
	AcknowledgeUnattendedSigning bool            `json:"acknowledge_unattended_signing"`
	ReplaceExisting              bool            `json:"replace_existing"`
}

// RollbackSnapshot is the exact pre-activation state of active namespaces.
// Call Zero when it is no longer needed.
type RollbackSnapshot struct {
	Schema      string              `json:"schema"`
	RestoreID   string              `json:"restore_id"`
	Directories []RollbackDirectory `json:"directories"`
}

// RollbackDirectory records one identity-relative active directory.
type RollbackDirectory struct {
	RelativePath string         `json:"relative_path"`
	Existed      bool           `json:"existed"`
	Files        []RollbackFile `json:"files"`
}

// RollbackFile records one exact regular file.
type RollbackFile struct {
	Name   string `json:"name"`
	Mode   uint32 `json:"mode"`
	SHA256 string `json:"sha256"`
	Data   []byte `json:"data"`
}

// Zero clears file bytes owned by the snapshot.
func (s *RollbackSnapshot) Zero() {
	if s == nil {
		return
	}
	for i := range s.Directories {
		for j := range s.Directories[i].Files {
			crypto.ZeroBytes(s.Directories[i].Files[j].Data)
		}
	}
}

// CreateActivation atomically publishes durable intent and rollback material
// before any active-store write.
func CreateActivation(
	paths storepaths.Paths,
	identityID string,
	journal ActivationJournal,
	snapshot RollbackSnapshot,
	masterKey []byte,
) error {
	if journal.Schema == "" {
		journal.Schema = ActivationJournalSchema
	}
	if journal.CreatedAt.IsZero() {
		journal.CreatedAt = time.Now().UTC()
	}
	if snapshot.Schema == "" {
		snapshot.Schema = RollbackSnapshotSchema
	}
	if err := validateActivationJournal(&journal); err != nil {
		return err
	}
	if err := validateRollbackSnapshot(&snapshot, journal.RestoreID); err != nil {
		return err
	}

	batchDir := paths.RecoveredBatchDir(identityID, journal.RestoreID)
	if err := requireRegularDirectory(batchDir); err != nil {
		return err
	}
	finalDir := paths.RecoveredActivationDir(identityID, journal.RestoreID)
	if _, err := os.Lstat(finalDir); err == nil {
		return fmt.Errorf("activation already exists for recovered batch %s", journal.RestoreID)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect activation destination: %w", err)
	}
	stageDir, err := os.MkdirTemp(batchDir, ActivationStagingPrefix+"*")
	if err != nil {
		return fmt.Errorf("create activation staging directory: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(stageDir)
		}
	}()
	if err := os.Chmod(stageDir, fsutil.StoreDirPerm); err != nil {
		return fmt.Errorf("set activation staging permissions: %w", err)
	}
	if err := writeEncryptedJSON(filepath.Join(stageDir, "rollback.enc"), &snapshot, masterKey); err != nil {
		return fmt.Errorf("write activation rollback snapshot: %w", err)
	}
	if err := writeEncryptedJSON(filepath.Join(stageDir, "journal.enc"), &journal, masterKey); err != nil {
		return fmt.Errorf("write activation journal: %w", err)
	}
	if err := syncDirectory(stageDir); err != nil {
		return fmt.Errorf("sync activation staging directory: %w", err)
	}
	if err := os.Rename(stageDir, finalDir); err != nil {
		return fmt.Errorf("publish activation intent: %w", err)
	}
	cleanup = false
	if err := syncDirectory(batchDir); err != nil {
		return fmt.Errorf("sync recovered batch after activation publish: %w", err)
	}
	return nil
}

// LoadActivation decrypts and validates durable activation state.
func LoadActivation(
	paths storepaths.Paths,
	identityID, restoreID string,
	masterKey []byte,
) (*ActivationJournal, *RollbackSnapshot, error) {
	if err := ValidateRestoreID(restoreID); err != nil {
		return nil, nil, err
	}
	dir := paths.RecoveredActivationDir(identityID, restoreID)
	if err := requireRegularDirectory(dir); err != nil {
		return nil, nil, err
	}
	var journal ActivationJournal
	if err := readEncryptedJSON(paths.RecoveredActivationJournalPath(identityID, restoreID), masterKey, &journal); err != nil {
		return nil, nil, fmt.Errorf("load activation journal: %w", err)
	}
	if err := validateActivationJournal(&journal); err != nil {
		return nil, nil, err
	}
	if journal.RestoreID != restoreID {
		return nil, nil, fmt.Errorf("activation journal restore ID mismatch")
	}
	var snapshot RollbackSnapshot
	if err := readEncryptedJSON(paths.RecoveredActivationRollbackPath(identityID, restoreID), masterKey, &snapshot); err != nil {
		snapshot.Zero()
		return nil, nil, fmt.Errorf("load activation rollback snapshot: %w", err)
	}
	if err := validateRollbackSnapshot(&snapshot, restoreID); err != nil {
		snapshot.Zero()
		return nil, nil, err
	}
	return &journal, &snapshot, nil
}

// UpdateActivationState durably changes the reconciliation direction.
func UpdateActivationState(
	paths storepaths.Paths,
	identityID, restoreID string,
	state ActivationState,
	masterKey []byte,
) error {
	journal, snapshot, err := LoadActivation(paths, identityID, restoreID, masterKey)
	if snapshot != nil {
		snapshot.Zero()
	}
	if err != nil {
		return err
	}
	journal.State = state
	if err := validateActivationJournal(journal); err != nil {
		return err
	}
	path := paths.RecoveredActivationJournalPath(identityID, restoreID)
	if err := writeEncryptedJSON(path, journal, masterKey); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

// RemoveActivation removes only the durable activation state for a recovered
// batch after successful activation or rollback.
func RemoveActivation(paths storepaths.Paths, identityID, restoreID string) error {
	if err := ValidateRestoreID(restoreID); err != nil {
		return err
	}
	dir := paths.RecoveredActivationDir(identityID, restoreID)
	if err := requireRegularDirectory(dir); err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("remove activation state: %w", err)
	}
	return syncDirectory(paths.RecoveredBatchDir(identityID, restoreID))
}

func validateActivationJournal(journal *ActivationJournal) error {
	if journal == nil || journal.Schema != ActivationJournalSchema {
		return fmt.Errorf("unsupported activation journal schema")
	}
	if err := ValidateRestoreID(journal.RestoreID); err != nil {
		return err
	}
	if journal.CreatedAt.IsZero() || !sha256Shape.MatchString(journal.ReviewToken) ||
		!sha256Shape.MatchString(journal.DestinationPolicySHA256) {
		return fmt.Errorf("activation journal metadata is incomplete")
	}
	switch journal.State {
	case ActivationApplying, ActivationRollingBack:
	default:
		return fmt.Errorf("invalid activation state %q", journal.State)
	}
	return nil
}

func validateRollbackSnapshot(snapshot *RollbackSnapshot, restoreID string) error {
	if snapshot == nil || snapshot.Schema != RollbackSnapshotSchema || snapshot.RestoreID != restoreID {
		return fmt.Errorf("invalid activation rollback snapshot")
	}
	seenDirs := make(map[string]struct{}, len(snapshot.Directories))
	for _, dir := range snapshot.Directories {
		if dir.RelativePath == "" || filepath.IsAbs(dir.RelativePath) ||
			filepath.Clean(dir.RelativePath) != dir.RelativePath ||
			strings.Contains(dir.RelativePath, "..") {
			return fmt.Errorf("invalid rollback directory %q", dir.RelativePath)
		}
		if _, ok := seenDirs[dir.RelativePath]; ok {
			return fmt.Errorf("duplicate rollback directory %q", dir.RelativePath)
		}
		seenDirs[dir.RelativePath] = struct{}{}
		if !dir.Existed && len(dir.Files) != 0 {
			return fmt.Errorf("absent rollback directory %q contains files", dir.RelativePath)
		}
		seenFiles := make(map[string]struct{}, len(dir.Files))
		for _, file := range dir.Files {
			if file.Name == "" || filepath.Base(file.Name) != file.Name ||
				strings.ContainsAny(file.Name, `/\`+"\x00") {
				return fmt.Errorf("invalid rollback filename %q", file.Name)
			}
			if _, ok := seenFiles[file.Name]; ok {
				return fmt.Errorf("duplicate rollback file %q", file.Name)
			}
			seenFiles[file.Name] = struct{}{}
			if !sha256Shape.MatchString(file.SHA256) {
				return fmt.Errorf("invalid rollback file digest")
			}
			sum := sha256.Sum256(file.Data)
			if hex.EncodeToString(sum[:]) != file.SHA256 {
				return fmt.Errorf("rollback file digest mismatch for %q", file.Name)
			}
		}
		if !slices.IsSortedFunc(dir.Files, func(a, b RollbackFile) int {
			return strings.Compare(a.Name, b.Name)
		}) {
			return fmt.Errorf("rollback files are not sorted")
		}
	}
	if !slices.IsSortedFunc(snapshot.Directories, func(a, b RollbackDirectory) int {
		return strings.Compare(a.RelativePath, b.RelativePath)
	}) {
		return fmt.Errorf("rollback directories are not sorted")
	}
	return nil
}

func writeEncryptedJSON(path string, value any, masterKey []byte) error {
	plaintext, err := json.Marshal(value)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(plaintext)
	encrypted, err := crypto.EncryptWithMasterKey(plaintext, masterKey)
	if err != nil {
		return err
	}
	if err := fsutil.WriteFile(path, encrypted); err != nil {
		return err
	}
	return syncRegularFile(path)
}

func readEncryptedJSON(path string, masterKey []byte, out any) error {
	encrypted, err := readRegularFile(path)
	if err != nil {
		return err
	}
	plaintext, err := crypto.DecryptWithMasterKey(encrypted, masterKey)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(plaintext)
	return json.Unmarshal(plaintext, out)
}
