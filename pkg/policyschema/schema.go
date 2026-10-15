// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package policyschema publishes the JSON Schema for APlane policy documents.
// The schema is the producer-facing contract; the node's semantic validation
// is authoritative and stricter (see docs/ARCH_POLICY.md).
package policyschema

import _ "embed"

// FormatV1 is the one policy document format. A document's "role" field says
// which node role it is for.
const FormatV1 = "aplane.policy.v1"

// SchemaV1 is the JSON Schema 2020-12 document for policy format v1.
//
//go:embed policy.v1.schema.json
var SchemaV1 []byte
