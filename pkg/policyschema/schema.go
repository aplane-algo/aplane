// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package policyschema publishes the JSON Schema for APlane policy documents.
// The schema is the producer-facing contract; the node's semantic validation
// is authoritative and stricter (see docs/ARCH_POLICY_FORMAT.md).
package policyschema

import _ "embed"

const (
	SignerFormatV1   = "aplane.signer-policy.v1"
	CosignerFormatV1 = "aplane.cosigner-policy.v1"
)

// SchemaV1 is the JSON Schema 2020-12 document for policy format v1.
//
//go:embed policy.v1.schema.json
var SchemaV1 []byte
