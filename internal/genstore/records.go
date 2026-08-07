// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package genstore

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const (
	// ManifestSchema identifies the immutable at-mint operation record.
	ManifestSchema = "aplane.generation-manifest.v1"
	// SealSchema identifies the final content record written before a
	// generation stops being current.
	SealSchema = "aplane.generation-seal.v2"

	manifestSchemaVersion = 1
	sealSchemaVersion     = 2

	generationSealMACDomain = "aplane.generation-seal-mac.v1"
	inventoryDigestDomain   = "aplane.generation-inventory-digest.v1"

	// OperationCredentialRestore identifies a generation produced by a
	// direct credential restore. Only this exact operation may be the source
	// of an explicit restore rollback; rollback mints deliberately use a
	// distinct operation name.
	OperationCredentialRestore         = "credential-restore"
	OperationCredentialRestoreRollback = "credential-restore-rollback"
)

// generationNamespaces are the directories a generation carries. Order is
// load-bearing for inventory comparison.
var generationNamespaces = []string{"keys", "keytypes"}

// InventoryEntry pins one regular file by namespace-relative path.
type InventoryEntry struct {
	Path   string `json:"path"` // e.g. "keys/ADDR.key"
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	// Term is zero for plaintext generation members and positive for a term
	// envelope. In a seal it is security-bearing and MAC-authenticated.
	Term int64 `json:"term,omitempty"`
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
	// "credential-restore"); OperationID is its stable identifier for
	// post-crash idempotency and audit correlation.
	Operation   string `json:"operation"`
	OperationID string `json:"operation_id"`
	// RestoreArchiveSHA256 authenticates the portable archive that supplied
	// a direct credential restore. RestoreRollbackEligible is false for a
	// repair begun from recovery mode, whose damaged parent must not later be
	// promoted back into service by an explicit rollback.
	RestoreArchiveSHA256    string `json:"restore_archive_sha256,omitempty"`
	RestoreRollbackEligible bool   `json:"restore_rollback_eligible,omitempty"`
	// RollbackSourceGenerationID names the sealed generation whose content
	// was reconstructed into this mint. ParentID remains the outgoing
	// current generation, preserving commit lineage; the rollback source is
	// separate because rollback mints content instead of rewinding CURRENT.
	RollbackSourceGenerationID string `json:"rollback_source_generation_id,omitempty"`
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
	Schema         string           `json:"schema"`
	SchemaVersion  int              `json:"schema_version"`
	GenerationID   string           `json:"generation_id"`
	SealedAtUnix   int64            `json:"sealed_at"`
	ManifestSHA256 string           `json:"manifest_sha256"`
	IntegrityTerm  int64            `json:"integrity_term"`
	Inventory      []InventoryEntry `json:"inventory"`
	IntegrityMAC   string           `json:"integrity_mac"`
}

// CanonicalInventoryDigest returns the domain-separated digest used when a
// rotation snapshot or baseline names an effective generation inventory
// authority. It is independent of JSON formatting.
func CanonicalInventoryDigest(inventory []InventoryEntry) (string, error) {
	if err := validateInventory(inventory); err != nil {
		return "", err
	}
	var encoded []byte
	encoded = appendSealField(encoded, []byte(inventoryDigestDomain))
	encoded = appendSealUint64(encoded, uint64(len(inventory)))
	for _, entry := range inventory {
		digest, err := decodeCanonicalSHA256(entry.SHA256)
		if err != nil {
			return "", fmt.Errorf("inventory %s: %w", entry.Path, err)
		}
		encoded = appendSealField(encoded, []byte(entry.Path))
		encoded = appendSealField(encoded, digest)
		encoded = appendSealUint64(encoded, uint64(entry.Size))
		encoded = appendSealUint64(encoded, uint64(entry.Term))
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
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
			term, present, err := crypto.InspectTermEnvelope(data)
			if err != nil {
				return nil, fmt.Errorf("inventory %s/%s term: %w", namespace, entry.Name(), err)
			}
			if !present {
				term = 0
			}
			inventory = append(inventory, InventoryEntry{
				Path:   namespace + "/" + entry.Name(),
				SHA256: hex.EncodeToString(sum[:]),
				Size:   int64(len(data)),
				Term:   term,
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
		manifest.SchemaVersion = manifestSchemaVersion
	}
	if err := validateManifest(&manifest, gen.GenerationID()); err != nil {
		return err
	}
	return writeJSONDurable(gen.ManifestPath(), manifest)
}

// ReadManifest loads and validates the generation's manifest.
func ReadManifest(gen storepaths.GenPaths) (*Manifest, error) {
	data, _, err := fsutil.ReadRegularFile(gen.ManifestPath())
	if err != nil {
		return nil, fmt.Errorf("read generation manifest: %w", err)
	}
	return ParseManifestBytes(gen, data)
}

// ParseManifestBytes parses and validates the exact immutable manifest buffer
// a caller intends to hash or otherwise consume.
func ParseManifestBytes(gen storepaths.GenPaths, data []byte) (*Manifest, error) {
	var manifest Manifest
	if err := decodeJSONStrict(data, &manifest); err != nil {
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
func WriteSeal(gen storepaths.GenPaths, sealedAtUnix int64, kr *crypto.Keyring) error {
	if kr == nil {
		return fmt.Errorf("seal generation %s: keyring is required", gen.GenerationID())
	}
	if sealedAtUnix <= 0 {
		return fmt.Errorf("seal generation %s: sealed_at must be positive", gen.GenerationID())
	}
	manifestBytes, manifest, err := readManifestBytes(gen)
	if err != nil {
		return fmt.Errorf("seal generation %s: %w", gen.GenerationID(), err)
	}
	if !manifest.Complete {
		return fmt.Errorf("seal generation %s: manifest is not complete", gen.GenerationID())
	}
	inventory, err := BuildInventory(gen)
	if err != nil {
		return fmt.Errorf("seal generation %s: %w", gen.GenerationID(), err)
	}
	manifestSum := sha256.Sum256(manifestBytes)
	seal := Seal{
		Schema:         SealSchema,
		SchemaVersion:  sealSchemaVersion,
		GenerationID:   gen.GenerationID(),
		SealedAtUnix:   sealedAtUnix,
		ManifestSHA256: hex.EncodeToString(manifestSum[:]),
		IntegrityTerm:  kr.CurrentTerm(),
		Inventory:      inventory,
	}
	macInput, err := canonicalSealMACInput(&seal)
	if err != nil {
		return fmt.Errorf("seal generation %s: %w", gen.GenerationID(), err)
	}
	term, mac, err := kr.SignIntegrity(crypto.IntegrityDomainGenerationSeal, macInput)
	if err != nil {
		return fmt.Errorf("seal generation %s: %w", gen.GenerationID(), err)
	}
	if term != seal.IntegrityTerm {
		return fmt.Errorf("seal generation %s: integrity term changed during signing", gen.GenerationID())
	}
	seal.IntegrityMAC = mac
	if err := writeJSONDurable(gen.SealPath(), seal); err != nil {
		return err
	}
	return fsutil.SyncDir(gen.Dir())
}

// ReadSeal loads and validates the generation's seal. os.IsNotExist errors
// pass through so reconciliation can classify unsealed generations.
func ReadSeal(gen storepaths.GenPaths, kr *crypto.Keyring) (*Seal, error) {
	if kr == nil {
		return nil, fmt.Errorf("read generation seal: keyring is required")
	}
	sealBytes, _, err := fsutil.ReadRegularFile(gen.SealPath())
	if err != nil {
		return nil, err
	}
	manifestBytes, _, err := fsutil.ReadRegularFile(gen.ManifestPath())
	if err != nil {
		return nil, fmt.Errorf("generation seal manifest: %w", err)
	}
	return ParseSealBytes(gen, sealBytes, manifestBytes, kr)
}

// BuildHistoricalAnchor validates an unanchored seal under current authority
// and returns the exact complete-seal reference to commit into the root before
// that authority retires.
func BuildHistoricalAnchor(
	gen storepaths.GenPaths,
	kr *crypto.Keyring,
) (crypto.HistoricalGenerationAnchor, error) {
	if kr == nil {
		return crypto.HistoricalGenerationAnchor{}, fmt.Errorf(
			"build historical anchor: keyring is required",
		)
	}
	sealBytes, _, err := fsutil.ReadRegularFile(gen.SealPath())
	if err != nil {
		return crypto.HistoricalGenerationAnchor{}, err
	}
	manifestBytes, _, err := fsutil.ReadRegularFile(gen.ManifestPath())
	if err != nil {
		return crypto.HistoricalGenerationAnchor{}, fmt.Errorf(
			"historical anchor manifest: %w",
			err,
		)
	}
	if _, err := ParseSealBytes(gen, sealBytes, manifestBytes, kr); err != nil {
		return crypto.HistoricalGenerationAnchor{}, fmt.Errorf(
			"historical anchor generation %s: %w",
			gen.GenerationID(),
			err,
		)
	}
	return crypto.NewHistoricalGenerationAnchor(gen.GenerationID(), sealBytes)
}

// ReadAnchoredSeal loads exact seal and manifest buffers and validates them
// through the root's historical anchor.
func ReadAnchoredSeal(
	gen storepaths.GenPaths,
	anchor crypto.HistoricalGenerationAnchor,
	kr *crypto.Keyring,
) (*Seal, error) {
	sealBytes, _, err := fsutil.ReadRegularFile(gen.SealPath())
	if err != nil {
		return nil, err
	}
	manifestBytes, _, err := fsutil.ReadRegularFile(gen.ManifestPath())
	if err != nil {
		return nil, fmt.Errorf("anchored generation seal manifest: %w", err)
	}
	return ParseAnchoredSealBytes(gen, anchor, sealBytes, manifestBytes, kr)
}

// ParseSealBytes validates exact seal and manifest buffers together. This is
// the historical-open primitive: callers can hash, authenticate, and consume
// the same bytes without a path-validation/read-again TOCTOU gap.
func ParseSealBytes(
	gen storepaths.GenPaths,
	sealBytes, manifestBytes []byte,
	kr *crypto.Keyring,
) (*Seal, error) {
	if kr == nil {
		return nil, fmt.Errorf("read generation seal: keyring is required")
	}
	seal, macInput, err := parseSealRecord(gen, sealBytes, manifestBytes)
	if err != nil {
		return nil, err
	}
	if err := kr.VerifyIntegrity(
		crypto.IntegrityDomainGenerationSeal,
		macInput,
		seal.IntegrityTerm,
		seal.IntegrityMAC,
	); err != nil {
		return nil, fmt.Errorf("generation seal integrity verification failed: %w", err)
	}
	if err := requireCurrentInventoryTerms(seal, kr.CurrentTerm()); err != nil {
		return nil, err
	}
	return seal, nil
}

// ParseAnchoredSealBytes validates exact seal and manifest buffers after the
// complete seal bytes match a root historical anchor. The anchor authorizes
// verification under a resident retired term; the retired-term MAC alone
// never grants historical authority.
func ParseAnchoredSealBytes(
	gen storepaths.GenPaths,
	anchor crypto.HistoricalGenerationAnchor,
	sealBytes, manifestBytes []byte,
	kr *crypto.Keyring,
) (*Seal, error) {
	if kr == nil {
		return nil, fmt.Errorf("read anchored generation seal: keyring is required")
	}
	if err := anchor.VerifyExact(gen.GenerationID(), sealBytes); err != nil {
		return nil, fmt.Errorf("generation %s historical anchor: %w", gen.GenerationID(), err)
	}
	seal, macInput, err := parseSealRecord(gen, sealBytes, manifestBytes)
	if err != nil {
		return nil, err
	}
	if err := kr.VerifyHistoricalGenerationSealIntegrity(
		macInput,
		seal.IntegrityTerm,
		seal.IntegrityMAC,
	); err != nil {
		return nil, fmt.Errorf("anchored generation seal integrity verification failed: %w", err)
	}
	return seal, nil
}

func parseSealRecord(
	gen storepaths.GenPaths,
	sealBytes, manifestBytes []byte,
) (*Seal, []byte, error) {
	var seal Seal
	if err := decodeJSONStrict(sealBytes, &seal); err != nil {
		return nil, nil, err
	}
	if seal.Schema != SealSchema || seal.SchemaVersion != sealSchemaVersion {
		return nil, nil, fmt.Errorf("unsupported generation seal schema")
	}
	if seal.GenerationID != gen.GenerationID() {
		return nil, nil, fmt.Errorf("generation seal names %s, want %s", seal.GenerationID, gen.GenerationID())
	}
	if err := validateInventory(seal.Inventory); err != nil {
		return nil, nil, fmt.Errorf("generation seal: %w", err)
	}
	if seal.SealedAtUnix <= 0 || seal.IntegrityTerm <= 0 {
		return nil, nil, fmt.Errorf("generation seal metadata is incomplete")
	}
	if err := validateCanonicalSHA256(seal.ManifestSHA256); err != nil {
		return nil, nil, fmt.Errorf("generation seal manifest_sha256: %w", err)
	}
	if err := validateCanonicalSHA256(seal.IntegrityMAC); err != nil {
		return nil, nil, fmt.Errorf("generation seal integrity_mac: %w", err)
	}
	manifest, err := ParseManifestBytes(gen, manifestBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("generation seal manifest: %w", err)
	}
	if !manifest.Complete {
		return nil, nil, fmt.Errorf("generation seal manifest is not complete")
	}
	manifestSum := sha256.Sum256(manifestBytes)
	if hex.EncodeToString(manifestSum[:]) != seal.ManifestSHA256 {
		return nil, nil, fmt.Errorf("generation seal manifest digest mismatch")
	}
	macInput, err := canonicalSealMACInput(&seal)
	if err != nil {
		return nil, nil, fmt.Errorf("generation seal: %w", err)
	}
	return &seal, macInput, nil
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
	if manifest.Schema != ManifestSchema || manifest.SchemaVersion != manifestSchemaVersion {
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
	if manifest.RollbackSourceGenerationID != "" {
		if manifest.ParentID == "" {
			return fmt.Errorf("generation manifest rollback source requires a parent")
		}
		if err := storepaths.ValidateGenerationID(manifest.RollbackSourceGenerationID); err != nil {
			return fmt.Errorf("generation manifest rollback source: %w", err)
		}
		if manifest.RollbackSourceGenerationID == manifest.GenerationID {
			return fmt.Errorf("generation manifest names itself as its rollback source")
		}
		if manifest.RollbackSourceGenerationID == manifest.ParentID {
			return fmt.Errorf("generation manifest rollback source is its outgoing parent")
		}
	}
	if manifest.CreatedAtUnix <= 0 || manifest.Operation == "" || manifest.OperationID == "" {
		return fmt.Errorf("generation manifest metadata is incomplete")
	}
	if manifest.RestoreArchiveSHA256 != "" {
		if err := validateCanonicalSHA256(manifest.RestoreArchiveSHA256); err != nil {
			return fmt.Errorf("generation manifest restore_archive_sha256: %w", err)
		}
	}
	if manifest.RestoreRollbackEligible &&
		(manifest.Operation != OperationCredentialRestore || manifest.ParentID == "" || manifest.RestoreArchiveSHA256 == "") {
		return fmt.Errorf("generation manifest has invalid restore rollback eligibility")
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
		if err := validateCanonicalSHA256(entry.SHA256); err != nil ||
			entry.Size < 0 ||
			entry.Term < 0 {
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

func decodeJSONStrict(data []byte, out any) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var trailing any
	switch err := decoder.Decode(&trailing); err {
	case io.EOF:
		return nil
	case nil:
		return fmt.Errorf("trailing data after JSON document")
	default:
		return fmt.Errorf("trailing data after JSON document: %w", err)
	}
}

func readManifestBytes(gen storepaths.GenPaths) ([]byte, *Manifest, error) {
	data, _, err := fsutil.ReadRegularFile(gen.ManifestPath())
	if err != nil {
		return nil, nil, fmt.Errorf("read generation manifest: %w", err)
	}
	manifest, err := ParseManifestBytes(gen, data)
	if err != nil {
		return nil, nil, err
	}
	return data, manifest, nil
}

func canonicalSealMACInput(seal *Seal) ([]byte, error) {
	if seal == nil {
		return nil, fmt.Errorf("missing generation seal")
	}
	if seal.SealedAtUnix <= 0 || seal.IntegrityTerm <= 0 {
		return nil, fmt.Errorf("generation seal metadata is incomplete")
	}
	if err := validateInventory(seal.Inventory); err != nil {
		return nil, err
	}
	manifestDigest, err := decodeCanonicalSHA256(seal.ManifestSHA256)
	if err != nil {
		return nil, fmt.Errorf("manifest_sha256: %w", err)
	}
	var out []byte
	out = appendSealField(out, []byte(generationSealMACDomain))
	out = appendSealField(out, []byte(seal.Schema))
	out = appendSealUint64(out, uint64(seal.SchemaVersion))
	out = appendSealField(out, []byte(seal.GenerationID))
	out = appendSealUint64(out, uint64(seal.SealedAtUnix))
	out = appendSealField(out, manifestDigest)
	out = appendSealUint64(out, uint64(seal.IntegrityTerm))
	out = appendSealUint64(out, uint64(len(seal.Inventory)))
	for _, entry := range seal.Inventory {
		digest, err := decodeCanonicalSHA256(entry.SHA256)
		if err != nil {
			return nil, fmt.Errorf("inventory %s: %w", entry.Path, err)
		}
		out = appendSealField(out, []byte(entry.Path))
		out = appendSealField(out, digest)
		out = appendSealUint64(out, uint64(entry.Size))
		out = appendSealUint64(out, uint64(entry.Term))
	}
	return out, nil
}

func requireCurrentInventoryTerms(seal *Seal, currentTerm int64) error {
	for _, entry := range seal.Inventory {
		if entry.Term != 0 && entry.Term != currentTerm {
			return fmt.Errorf(
				"unanchored generation seal entry %q names term %d, want current term %d",
				entry.Path,
				entry.Term,
				currentTerm,
			)
		}
	}
	return nil
}

func appendSealUint64(out []byte, value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return appendSealField(out, encoded[:])
}

func appendSealField(out, field []byte) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(field)))
	out = append(out, length[:]...)
	return append(out, field...)
}

func validateCanonicalSHA256(value string) error {
	_, err := decodeCanonicalSHA256(value)
	return err
}

func decodeCanonicalSHA256(value string) ([]byte, error) {
	if len(value) != sha256.Size*2 {
		return nil, fmt.Errorf("must be %d lowercase hexadecimal characters", sha256.Size*2)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("must be %d lowercase hexadecimal characters", sha256.Size*2)
	}
	return decoded, nil
}
