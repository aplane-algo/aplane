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
	// CurrentPointerName is the file naming the active generation.
	CurrentPointerName = "CURRENT"
	// GenerationsDirName holds one directory per generation.
	GenerationsDirName = "generations"
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
