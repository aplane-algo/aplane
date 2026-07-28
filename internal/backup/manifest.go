// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/backup/sourcecontext"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/noderole"
)

const (
	// ManifestFileName is the sealed archive manifest: the single record
	// covering every other archive member, encrypted under the export
	// passphrase with the standalone envelope the .apb payloads use.
	ManifestFileName = "manifest.sealed"
	// ManifestSchema identifies the sealed manifest inside its envelope.
	// The schema lives in the sealed plaintext, so it also separates this
	// record from any other standalone-encrypted payload.
	ManifestSchema        = "aplane.backup.manifest.v2"
	ManifestSchemaVersion = 1

	maxSealedManifestBytes = 1 << 20

	// maxSourcePolicyBytes bounds the archive policy snapshot that recovery
	// embeds verbatim into the encrypted batch metadata.
	maxSourcePolicyBytes = 256 * 1024
)

// ManifestMember is one archive member's authenticated identity.
type ManifestMember struct {
	Path   string `json:"path"` // archive-relative, forward slashes
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Manifest is the authenticated description of a managed backup archive.
// Decrypting it proves the archive was created, or endorsed, by a party that
// knew the export passphrase (docs/PROPOSAL_ARCHIVE_MANIFEST.md); the member
// inventory then makes every other archive member tamper-evident.
//
// Source context is carried inline: it is review material describing the
// source store and never changes destination behavior. Authentication makes
// it trustworthy as a report, not as an instruction.
type Manifest struct {
	Schema         string `json:"schema"`
	SchemaVersion  int    `json:"schema_version"`
	SourceNodeRole string `json:"source_node_role"`
	CreatedAtUnix  int64  `json:"created_at_unix,omitempty"`

	// Members covers every archive member except the manifest itself.
	Members []ManifestMember `json:"members"`

	// UserAutoApprove is recorded for signer sources only.
	UserAutoApprove *bool `json:"user_auto_approve,omitempty"`
	// GenesisHashMappings carries custom network mappings only.
	GenesisHashMappings []sourcecontext.GenesisHashMapping `json:"genesis_hash_mappings,omitempty"`
}

// SourceProjection returns the manifest's source context.
func (m Manifest) SourceProjection() sourcecontext.Projection {
	return sourcecontext.CloneProjection(sourcecontext.Projection{
		UserAutoApprove:     m.UserAutoApprove,
		GenesisHashMappings: m.GenesisHashMappings,
	})
}

// SourceSnapshot returns the manifest's source context in the shape
// WriteSealedManifest consumes, so an archive can be re-sealed after its
// members are legitimately rewritten.
func (m Manifest) SourceSnapshot() SourceSettingsSnapshot {
	snapshot := SourceSettingsSnapshot{}
	if m.UserAutoApprove != nil {
		value := *m.UserAutoApprove
		snapshot.UserAutoApprove = &value
	}
	if len(m.GenesisHashMappings) > 0 {
		snapshot.GenesisHashMappings = make(map[string]string, len(m.GenesisHashMappings))
		for _, mapping := range m.GenesisHashMappings {
			snapshot.GenesisHashMappings[mapping.GenesisHash] = mapping.Network
		}
	}
	return snapshot
}

// WriteSealedManifest inventories every file already staged under destDir,
// seals the manifest under exportPassphrase, and writes it into the archive.
// It must run after every other member is final: the inventory is what makes
// them tamper-evident.
func WriteSealedManifest(
	destDir string,
	role noderole.Role,
	createdAt time.Time,
	snapshot SourceSettingsSnapshot,
	exportPassphrase []byte,
) error {
	if _, err := noderole.ParseRole(string(role)); err != nil {
		return err
	}
	if len(exportPassphrase) == 0 {
		return fmt.Errorf("sealing the backup manifest requires the export passphrase")
	}
	if createdAt.IsZero() {
		createdAt = time.Now()
	}
	projection, err := sourcecontext.NormalizeProjection(
		role,
		snapshot.UserAutoApprove,
		snapshot.GenesisHashMappings,
	)
	if err != nil {
		return fmt.Errorf("validate backup source settings: %w", err)
	}
	members, err := inventoryArchiveMembers(destDir)
	if err != nil {
		return err
	}
	manifest := Manifest{
		Schema:              ManifestSchema,
		SchemaVersion:       ManifestSchemaVersion,
		SourceNodeRole:      string(role),
		CreatedAtUnix:       createdAt.UTC().Unix(),
		Members:             members,
		UserAutoApprove:     projection.UserAutoApprove,
		GenesisHashMappings: projection.GenesisHashMappings,
	}
	plaintext, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("marshal backup manifest: %w", err)
	}
	if len(plaintext) > maxSealedManifestBytes {
		return fmt.Errorf("backup manifest exceeds size limit %d", maxSealedManifestBytes)
	}
	sealed, err := crypto.EncryptStandalone(plaintext, exportPassphrase)
	if err != nil {
		return fmt.Errorf("seal backup manifest: %w", err)
	}
	if err := fsutil.WriteFile(filepath.Join(destDir, ManifestFileName), sealed); err != nil {
		return fmt.Errorf("write backup manifest: %w", err)
	}
	return nil
}

// OpenSealedManifest decrypts the archive's manifest with exportPassphrase and
// verifies the archive against it: every listed member must be present with a
// matching digest and size, and no unlisted member may exist. A wrong
// passphrase and a tampered manifest are indistinguishable by construction
// (GCM), exactly as for payload content.
func OpenSealedManifest(sourceRoot string, exportPassphrase []byte) (Manifest, error) {
	if len(exportPassphrase) == 0 {
		return Manifest{}, fmt.Errorf("reading the backup manifest requires the export passphrase")
	}
	sealed, err := readSealedManifestFile(filepath.Join(sourceRoot, ManifestFileName))
	if err != nil {
		if os.IsNotExist(err) {
			return Manifest{}, fmt.Errorf(
				"unsupported backup archive format: no sealed manifest (%s); archives written by other releases cannot be read",
				ManifestFileName,
			)
		}
		return Manifest{}, fmt.Errorf("read backup manifest: %w", err)
	}
	plaintext, err := crypto.DecryptStandalone(sealed, exportPassphrase)
	if err != nil {
		return Manifest{}, fmt.Errorf("decrypt backup manifest: %w", err)
	}
	defer crypto.ZeroBytes(plaintext)

	var manifest Manifest
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("parse backup manifest: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return Manifest{}, fmt.Errorf("parse backup manifest: %w", err)
	}
	if manifest.Schema != ManifestSchema {
		return Manifest{}, fmt.Errorf("unsupported backup manifest schema: %q", manifest.Schema)
	}
	if manifest.SchemaVersion != ManifestSchemaVersion {
		return Manifest{}, fmt.Errorf("unsupported backup manifest schema_version: %d", manifest.SchemaVersion)
	}
	role, err := noderole.ParseRole(manifest.SourceNodeRole)
	if err != nil {
		return Manifest{}, fmt.Errorf("invalid backup manifest source_node_role: %w", err)
	}
	if err := sourcecontext.ValidateProjection(role, manifest.SourceProjection()); err != nil {
		return Manifest{}, fmt.Errorf("invalid backup manifest source settings: %w", err)
	}
	if err := verifyArchiveMembers(sourceRoot, manifest.Members); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// inventoryArchiveMembers hashes every regular file under root except the
// manifest itself, returning entries sorted by path.
func inventoryArchiveMembers(root string) ([]ManifestMember, error) {
	var members []ManifestMember
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("archive member is not a regular file: %s", path)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == ManifestFileName {
			return nil
		}
		sum, size, err := fsutil.RegularFileSHA256(path)
		if err != nil {
			return fmt.Errorf("hash archive member %s: %w", rel, err)
		}
		members = append(members, ManifestMember{Path: rel, SHA256: sum, Size: size})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("inventory archive members: %w", err)
	}
	slices.SortFunc(members, func(a, b ManifestMember) int {
		return strings.Compare(a.Path, b.Path)
	})
	return members, nil
}

// verifyArchiveMembers proves the archive on disk is exactly what the
// manifest describes: every listed member present and byte-identical, and no
// member outside the list. Both directions matter — checking only the listed
// members would let an attacker add files, and checking only presence would
// let them substitute content.
func verifyArchiveMembers(root string, members []ManifestMember) error {
	listed := make(map[string]ManifestMember, len(members))
	for _, member := range members {
		if member.Path == "" || member.Path == ManifestFileName {
			return fmt.Errorf("backup manifest lists an invalid member path %q", member.Path)
		}
		if filepath.IsAbs(member.Path) || strings.Contains(member.Path, "\\") {
			return fmt.Errorf("backup manifest lists a non-relative member path %q", member.Path)
		}
		clean := filepath.ToSlash(filepath.Clean(member.Path))
		if clean != member.Path || clean == ".." || strings.HasPrefix(clean, "../") {
			return fmt.Errorf("backup manifest lists a non-canonical member path %q", member.Path)
		}
		if _, duplicate := listed[member.Path]; duplicate {
			return fmt.Errorf("backup manifest lists member %q twice", member.Path)
		}
		listed[member.Path] = member
	}

	present, err := inventoryArchiveMembers(root)
	if err != nil {
		return err
	}
	for _, actual := range present {
		expected, ok := listed[actual.Path]
		if !ok {
			return fmt.Errorf("backup archive contains unlisted member %q", actual.Path)
		}
		if expected.SHA256 != actual.SHA256 || expected.Size != actual.Size {
			return fmt.Errorf("backup archive member %q does not match the sealed manifest", actual.Path)
		}
		delete(listed, actual.Path)
	}
	if len(listed) > 0 {
		missing := make([]string, 0, len(listed))
		for path := range listed {
			missing = append(missing, path)
		}
		slices.Sort(missing)
		return fmt.Errorf("backup archive is missing member(s) named by the sealed manifest: %s",
			strings.Join(missing, ", "))
	}
	return nil
}

func readSealedManifestFile(path string) ([]byte, error) {
	file, err := openManagedBackupArchive(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxSealedManifestBytes {
		return nil, fmt.Errorf("backup manifest exceeds size limit %d", maxSealedManifestBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxSealedManifestBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSealedManifestBytes {
		return nil, fmt.Errorf("backup manifest exceeds size limit %d", maxSealedManifestBytes)
	}
	return data, nil
}
