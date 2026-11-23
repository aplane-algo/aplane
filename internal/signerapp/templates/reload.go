// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package templates

import "errors"

// AuditLogger is what a reload records: the key count it published, and each
// key the scan rejected for a LogicSig invariant.
type AuditLogger interface {
	LogKeyReload(keyCount int)
	LogKeyRejected(keyFile, reason string)
}

// ReloadReport is a request-scoped projection of one runtime reload. It
// describes what the reload accepted or rejected for callers such as template
// administration; it is not persisted and is not template/key-type state.
// Durable authority remains in encrypted template files and keytypestate
// records.
type ReloadReport struct {
	KeyCount         int
	TemplateNotices  []string
	TemplateWarnings []string
	RegistrationReport
}

// ErrGenerationValidation marks a reload failure caused by content defects
// in the selected generation; the unlock paths map it to recovery mode
// instead of an ordinary unlock failure.
var ErrGenerationValidation = errors.New("generation validation failed")

// IsGenerationValidationErr reports whether err wraps ErrGenerationValidation.
func IsGenerationValidationErr(err error) bool {
	return errors.Is(err, ErrGenerationValidation)
}
