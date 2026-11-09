// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package plainhost

import (
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
)

// ShapeFromMetadata reads a stored bounded account's shape, as StoredFingerprint does.
func ShapeFromMetadata(metadata *boundedmeta.Metadata) (Shape, error) {
	return shapeFromMetadata(metadata)
}

// CheckResources runs the generation resource backstop on its own.
func CheckResources(metadata *boundedmeta.Metadata, opcodes lsigresource.OpcodeProfile, programBytes int) error {
	return checkResources(metadata, opcodes, programBytes)
}

// ShapeComposerForTest returns the composer a shape selects, or nil when the
// grammar has no such shape.
func (p *Provider) ShapeComposerForTest(shape Shape) *composeddsa.ComposedDSA {
	p.mustLoadShapes()
	selected, ok := p.byShape[shape.Descriptor()]
	if !ok {
		return nil
	}
	return selected.composer
}

// ShapeFingerprintForTest returns a shape's provenance, or "" when the grammar
// has no such shape.
func (p *Provider) ShapeFingerprintForTest(shape Shape) string {
	p.mustLoadShapes()
	selected, ok := p.byShape[shape.Descriptor()]
	if !ok {
		return ""
	}
	return selected.fingerprint
}

// ComposerValuesForTest is what a shape's composer sees of a request's values.
func (p *Provider) ComposerValuesForTest(shape Shape, values map[string]string) map[string]string {
	p.mustLoadShapes()
	return composerValues(p.byShape[shape.Descriptor()], values)
}

// ProgramsForTest lists every program the grammar offers, in grammar order: the
// plain1 arrangements, then the bounded2 shapes.
func (p *Provider) ProgramsForTest() (descriptors, fingerprints []string) {
	p.mustLoadShapes()
	for _, selected := range p.ordered {
		descriptors = append(descriptors, selected.descriptor)
		fingerprints = append(fingerprints, selected.fingerprint)
	}
	return descriptors, fingerprints
}

// GrammarFingerprintOverForTest recomputes the grammar fingerprint over the
// programs at the given indexes, in that order.
func (p *Provider) GrammarFingerprintOverForTest(indexes []int) string {
	p.mustLoadShapes()
	programs := make([]*program, len(indexes))
	for i, index := range indexes {
		programs[i] = p.ordered[index]
	}
	return grammarFingerprint(p.KeyType(), programs)
}

// mustLoadShapes builds the shapes for a test, which then reads them directly.
func (p *Provider) mustLoadShapes() {
	if err := p.loadShapes(); err != nil {
		panic(err)
	}
}

// ShapesBuiltForTest reports whether the shapes have been built yet.
func (p *Provider) ShapesBuiltForTest() bool { return p.byShape != nil }
