// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storepaths

import (
	"fmt"
	"path/filepath"
	"regexp"
)

// Generation-based active storage (docs/ARCH_GENERATIONS.md): the active
// keys/ and keytypes/ namespaces live inside immutable-after-flip generation
// directories selected by the CURRENT pointer. Everything here is pure path
// construction; reading and validating CURRENT lives in internal/genstore.
const (
	// StoreRootName is the sole generation-selection and key-authority commit
	// record in the atomic store-root layout.
	StoreRootName = "store-root.enc"
	// CurrentPointerName is the file naming the active generation.
	CurrentPointerName = "CURRENT"
	// GenerationsDirName holds one directory per generation.
	GenerationsDirName = "generations"
	// QuarantineDirName holds non-authoritative state preserved for explicit
	// operator disposition.
	QuarantineDirName = "quarantine"
	// QuarantinedGenerationsDirName holds complete abandoned generation
	// publications. Ordinary generation resolution never searches it.
	QuarantinedGenerationsDirName = "generations"
	// GenerationStagingPrefix marks an unpublished generation being minted.
	GenerationStagingPrefix = ".staging-"
	// GenerationManifestName is the immutable at-mint operation record.
	GenerationManifestName = "manifest.json"
	// GenerationSealName is the final content record written before a
	// generation stops being current.
	GenerationSealName = "seal.json"
)

// generationIDShape: sortable mint time plus collision suffix.
var generationIDShape = regexp.MustCompile(`^gen-[0-9]{1,19}-[0-9a-f]{8}$`)

// ValidateGenerationID reports whether id is a well-formed generation ID.
func ValidateGenerationID(id string) error {
	if !generationIDShape.MatchString(id) {
		return fmt.Errorf("invalid generation ID %q", id)
	}
	return nil
}

func validateGenerationComponent(id string) string {
	if err := ValidateGenerationID(id); err != nil {
		panic(err)
	}
	return id
}

// StoreRootPath is identities/default/store-root.enc.
func (p Paths) StoreRootPath() string {
	return filepath.Join(p.ProductDir(), StoreRootName)
}

// CurrentPointerPath is identities/default/CURRENT.
func (p Paths) CurrentPointerPath() string {
	return filepath.Join(p.ProductDir(), CurrentPointerName)
}

// GenerationsDir is identities/default/generations.
func (p Paths) GenerationsDir() string {
	return filepath.Join(p.ProductDir(), GenerationsDirName)
}

// GenerationDir is identities/default/generations/<generation-id>.
func (p Paths) GenerationDir(generationID string) string {
	return filepath.Join(p.GenerationsDir(), validateGenerationComponent(generationID))
}

// QuarantineDir is identities/default/quarantine. Nothing below this path is
// generation authority.
func (p Paths) QuarantineDir() string {
	return filepath.Join(p.ProductDir(), QuarantineDirName)
}

// QuarantinedGenerationsDir is the reserved namespace for complete abandoned
// generation publications.
func (p Paths) QuarantinedGenerationsDir() string {
	return filepath.Join(p.QuarantineDir(), QuarantinedGenerationsDirName)
}

// QuarantinedGenerationDir returns the non-authoritative destination for one
// complete abandoned generation publication. It deliberately returns only a
// directory path, not GenPaths, so normal generation consumers cannot receive
// a quarantined generation handle.
func (p Paths) QuarantinedGenerationDir(generationID string) string {
	return filepath.Join(p.QuarantinedGenerationsDir(), validateGenerationComponent(generationID))
}

// GenerationPaths binds generation-qualified active-store paths. Pure
// constructor: it does not consult CURRENT. Operations resolve CURRENT once
// (internal/genstore.Resolve) under the store mutation lock and pass the
// result down; re-resolving mid-operation is a correctness bug.
func (p Paths) GenerationPaths(generationID string) GenPaths {
	return GenPaths{
		root:         p.GenerationDir(generationID),
		generationID: generationID,
	}
}

// StagedGenerationPaths binds GenPaths to an unpublished staging directory.
// Only the genstore commit protocol should use this: staging and published
// generation directories share one internal layout, and the commit rename
// is what turns one into the other.
func StagedGenerationPaths(generationID, stagingDir string) GenPaths {
	return GenPaths{
		root:         stagingDir,
		generationID: validateGenerationComponent(generationID),
	}
}

// GenPaths carries the active-store paths of one resolved generation.
type GenPaths struct {
	root         string
	generationID string
}

// GenerationID names the bound generation.
func (g GenPaths) GenerationID() string { return g.generationID }

// Dir is the generation directory itself.
func (g GenPaths) Dir() string { return g.root }

// ManifestPath is the generation's immutable at-mint operation record.
func (g GenPaths) ManifestPath() string {
	return filepath.Join(g.root, GenerationManifestName)
}

// SealPath is the generation's final content record.
func (g GenPaths) SealPath() string {
	return filepath.Join(g.root, GenerationSealName)
}

// KeysDir is the generation's active credential namespace.
func (g GenPaths) KeysDir() string {
	return filepath.Join(g.root, "keys")
}

// DeletedDir is the generation-owned deleted credential and template archive.
func (g GenPaths) DeletedDir() string {
	return filepath.Join(g.root, "deleted")
}

// DeletedKeysDir is the generation-owned deleted credential namespace.
func (g GenPaths) DeletedKeysDir() string {
	return filepath.Join(g.DeletedDir(), "keys")
}

// DeletedKeyTypeRecordsDir is the generation-owned deleted template namespace.
func (g GenPaths) DeletedKeyTypeRecordsDir() string {
	return filepath.Join(g.DeletedDir(), "keytypes")
}

// DeletedKeyTypeTemplate is the archived template document for one key type.
func (g GenPaths) DeletedKeyTypeTemplate(keyType string) string {
	validateKeyTypeComponent(keyType)
	return filepath.Join(g.DeletedKeyTypeRecordsDir(), keyType+".template")
}

// KeyTypeRecordsDir is the generation's key-type state namespace.
func (g GenPaths) KeyTypeRecordsDir() string {
	return filepath.Join(g.root, "keytypes")
}

// KeyTypeRecord is the generation's state record for one key type.
func (g GenPaths) KeyTypeRecord(keyType string) string {
	validateKeyTypeComponent(keyType)
	return filepath.Join(g.KeyTypeRecordsDir(), keyType+".json")
}

// KeyTypeTemplate is the generation's template document for one key type.
func (g GenPaths) KeyTypeTemplate(keyType string) string {
	validateKeyTypeComponent(keyType)
	return filepath.Join(g.KeyTypeRecordsDir(), keyType+".template")
}

// PolicyPath is the generation-owned signer policy document.
func (g GenPaths) PolicyPath() string {
	return filepath.Join(g.root, "policy.yaml")
}

// PolicyIntegritySidecar is the generation-owned signer policy integrity
// record.
func (g GenPaths) PolicyIntegritySidecar() string {
	return filepath.Join(g.root, "policy.yaml.hmac")
}

// NodeRoleIntegritySidecar is the generation-owned integrity record for the
// immutable data-root node role document.
func (g GenPaths) NodeRoleIntegritySidecar() string {
	return filepath.Join(g.root, "node.yaml.hmac")
}
