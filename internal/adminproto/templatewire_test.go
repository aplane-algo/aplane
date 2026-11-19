// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminproto

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/keytypestate"
)

func TestWireTemplateTypeProjection(t *testing.T) {
	tests := []struct {
		source keytypestate.Source
		wire   string
	}{
		{keytypestate.SourceYAMLGeneric, "generic"},
		{keytypestate.SourceYAMLComposed, "composed"},
		{keytypestate.SourceCompiled, "compiled_provider"},
	}

	for _, tt := range tests {
		wire, ok := WireTemplateTypeFromSource(tt.source)
		if !ok || wire != tt.wire {
			t.Fatalf("WireTemplateTypeFromSource(%q) = %q, %v; want %q, true", tt.source, wire, ok, tt.wire)
		}
	}
}
