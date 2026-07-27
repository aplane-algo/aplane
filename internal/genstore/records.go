// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package genstore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const (
	// ManifestSchema identifies the immutable at-mint operation record.
	ManifestSchema = "aplane.generation-manifest.v1"
	// SealSchema identifies the final content record written before a
	// generation stops being current.
	SealSchema = "aplane.generation-seal.v1"
	// schemaVersion is shared by both records.
	schemaVersion = 1
)

// generationNamespaces are the directories a generation carries. Order is
// load-bearing for inventory comparison.
var generationNamespaces = []string{"keys", "keytypes"}

// InventoryEntry pins one regular file by namespace-relative path.
type InventoryEntry struct {
	Path   string `json:"path"` // e.g. "keys/ADDR.key"
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Manifest is the immutable at-mint operation record. It describes the
// minting transaction, not the live directory: single-file mutations to the
// current generation do not falsify it. CURRENT answers which state
// committed; the manifest answers which operation produced it.
type Manifest struct {
	Schema        string `json:"schema"`
	SchemaVersion int    `json:"schema_version"`
	GenerationID  string `json:"generation_id"`
	// ParentID is empty for a store's first generation.
	ParentID      string `json:"parent_id,omitempty"`
	CreatedAtUnix int64  `json:"created_at"`
	// Operation is the minting operation type (e.g. "layout-migration",
	// "restore-activation"); OperationID is its stable identifier for
	// post-crash idempotency and audit correlation.
	Operation   string `json:"operation"`
	OperationID string `json:"operation_id"`
	// SourceRestoreID and ReviewTokenSHA256 tie a restore activation to its
	// reviewed batch.
	SourceRestoreID   string `json:"source_restore_id,omitempty"`
	ReviewTokenSHA256 string `json:"review_token_sha256,omitempty"`
	// Inventory is the at-mint content record.
	Inventory []InventoryEntry `json:"inventory"`
	// Complete is written true before publication; a manifest without it is
	// an aborted mint.
	Complete bool `json:"complete"`
}

// Seal is the final content record of a generation, written durably while
// it is still current, immediately before every pointer flip away from it.
// Prior-generation and rollback-target validation use the seal, never the
// at-mint manifest. A non-current generation without a seal is by
// construction an uncommitted attempt.
type Seal struct {
	Schema        string           `json:"schema"`
	SchemaVersion int              `json:"schema_version"`
	GenerationID  string           `json:"generation_id"`
	SealedAtUnix  int64            `json:"sealed_at"`
	Inventory     []InventoryEntry `json:"inventory"`
}

// BuildInventory walks the generation's namespaces and pins every regular
// file. Strict: symlinks, subdirectories, and irregular files are errors,
// never skipped. A missing namespace directory contributes no entries.
func BuildInventory(gen storepaths.GenPaths) ([]InventoryEntry, error) {
	var inventory []InventoryEntry
	for _, namespace := range generationNamespaces {
		dir := filepath.Join(gen.Dir(), namespace)
		info, err := os.Lstat(dir)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, fmt.Errorf("generation namespace is not a regular directory: %s", dir)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			path := filepath.Join(dir, entry.Name())
			data, _, err := fsutil.ReadRegularFile(path)
			if err != nil {
				return nil, fmt.Errorf("inventory %s/%s: %w", namespace, entry.Name(), err)
			}
			sum := sha256.Sum256(data)
			inventory = append(inventory, InventoryEntry{
				Path:   namespace + "/" + entry.Name(),
				SHA256: hex.EncodeToString(sum[:]),
				Size:   int64(len(data)),
			})
		}
	}
	slices.SortFunc(inventory, func(a, b InventoryEntry) int {
		return strings.Compare(a.Path, b.Path)
	})
	return inventory, nil
}

// WriteManifest durably writes the generation's manifest. Called once, in
// staging, before publication.
func WriteManifest(gen storepaths.GenPaths, manifest Manifest) error {
	if manifest.Schema == "" {
		manifest.Schema = ManifestSchema
	}
	if manifest.SchemaVersion == 0 {
		manifest.SchemaVersion = schemaVersion
	}
	if err := validateManifest(&manifest, gen.GenerationID()); err != nil {
		return err
	}
	return writeJSONDurable(gen.ManifestPath(), manifest)
}

// ReadManifest loads and validates the generation's manifest.
func ReadManifest(gen storepaths.GenPaths) (*Manifest, error) {
	var manifest Manifest
	if err := readJSONStrict(gen.ManifestPath(), &manifest); err != nil {
		return nil, fmt.Errorf("read generation manifest: %w", err)
	}
	if err := validateManifest(&manifest, gen.GenerationID()); err != nil {
		return nil, err
	}
	return &manifest, nil
}

// WriteSeal durably records the generation's final inventory. Must be
// called while the generation is still current, before the pointer flip
// away from it; sealing is the last write a generation ever receives.
func WriteSeal(gen storepaths.GenPaths, sealedAtUnix int64) error {
	inventory, err := BuildInventory(gen)
	if err != nil {
		return fmt.Errorf("seal generation %s: %w", gen.GenerationID(), err)
	}
	seal := Seal{
		Schema:        SealSchema,
		SchemaVersion: schemaVersion,
		GenerationID:  gen.GenerationID(),
		SealedAtUnix:  sealedAtUnix,
		Inventory:     inventory,
	}
	if err := writeJSONDurable(gen.SealPath(), seal); err != nil {
		return err
	}
	return fsutil.SyncDir(gen.Dir())
}

// ReadSeal loads and validates the generation's seal. os.IsNotExist errors
// pass through so reconciliation can classify unsealed generations.
func ReadSeal(gen storepaths.GenPaths) (*Seal, error) {
	var seal Seal
	if err := readJSONStrict(gen.SealPath(), &seal); err != nil {
		return nil, err
	}
	if seal.Schema != SealSchema || seal.SchemaVersion != schemaVersion {
		return nil, fmt.Errorf("unsupported generation seal schema")
	}
	if seal.GenerationID != gen.GenerationID() {
		return nil, fmt.Errorf("generation seal names %s, want %s", seal.GenerationID, gen.GenerationID())
	}
	if err := validateInventory(seal.Inventory); err != nil {
		return nil, fmt.Errorf("generation seal: %w", err)
	}
	return &seal, nil
}

// HasSeal reports whether the generation carries a seal file. Every
// generation that was ever current is sealed before it stops being current,
// so unsealed + non-current identifies an uncommitted attempt.
func HasSeal(gen storepaths.GenPaths) (bool, error) {
	_, err := os.Lstat(gen.SealPath())
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func validateManifest(manifest *Manifest, generationID string) error {
	if manifest.Schema != ManifestSchema || manifest.SchemaVersion != schemaVersion {
		return fmt.Errorf("unsupported generation manifest schema")
	}
	if manifest.GenerationID != generationID {
		return fmt.Errorf("generation manifest names %q, want %q", manifest.GenerationID, generationID)
	}
	if manifest.ParentID != "" {
		if err := storepaths.ValidateGenerationID(manifest.ParentID); err != nil {
			return fmt.Errorf("generation manifest parent: %w", err)
		}
		if manifest.ParentID == manifest.GenerationID {
			// A self-parent manifest would make rollback resolve to the
			// current generation itself — reporting a rollback that never
			// moved CURRENT.
			return fmt.Errorf("generation manifest names itself as its parent")
		}
	}
	if manifest.CreatedAtUnix <= 0 || manifest.Operation == "" || manifest.OperationID == "" {
		return fmt.Errorf("generation manifest metadata is incomplete")
	}
	return validateInventory(manifest.Inventory)
}

func validateInventory(inventory []InventoryEntry) error {
	seen := make(map[string]struct{}, len(inventory))
	for _, entry := range inventory {
		namespace, name, ok := strings.Cut(entry.Path, "/")
		if !ok || !slices.Contains(generationNamespaces, namespace) ||
			name == "" || name != filepath.Base(name) ||
			strings.ContainsAny(name, `/\`+"\x00") {
			return fmt.Errorf("invalid inventory path %q", entry.Path)
		}
		if _, dup := seen[entry.Path]; dup {
			return fmt.Errorf("duplicate inventory path %q", entry.Path)
		}
		seen[entry.Path] = struct{}{}
		if len(entry.SHA256) != 64 || entry.Size < 0 {
			return fmt.Errorf("invalid inventory record for %q", entry.Path)
		}
	}
	if !slices.IsSortedFunc(inventory, func(a, b InventoryEntry) int {
		return strings.Compare(a.Path, b.Path)
	}) {
		return fmt.Errorf("inventory is not sorted")
	}
	return nil
}

func writeJSONDurable(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileDurable(path, append(data, '\n'))
}

func readJSONStrict(path string, out any) error {
	data, _, err := fsutil.ReadRegularFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	return decoder.Decode(out)
}
