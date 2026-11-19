// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminproto

import (
	"github.com/aplane-algo/aplane/internal/keytypestate"
)

const (
	WireTemplateTypeGeneric          = "generic"
	WireTemplateTypeComposed         = "composed"
	WireTemplateTypeCompiledProvider = "compiled_provider"
)

func WireTemplateTypeFromSource(source keytypestate.Source) (string, bool) {
	switch source {
	case keytypestate.SourceYAMLGeneric:
		return WireTemplateTypeGeneric, true
	case keytypestate.SourceYAMLComposed:
		return WireTemplateTypeComposed, true
	case keytypestate.SourceCompiled:
		return WireTemplateTypeCompiledProvider, true
	default:
		return "", false
	}
}
