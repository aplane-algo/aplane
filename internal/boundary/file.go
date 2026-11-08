// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package boundary

import (
	"errors"
	"fmt"
	"strings"
	"syscall"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
)

// MaxFileBytes bounds the file size before parsing. It leaves room for
// a full list of 58-character addresses in block style.
const MaxFileBytes = 8 << 20

// File is a parsed boundary file. It holds only what the file says: a
// cosigner stays a name for the signer to resolve.
type File struct {
	Schema     string   `yaml:"schema"`
	Spend      []string `yaml:"spend"`
	Recipients []string `yaml:"recipients"`
	// RecipientScope "any" asks for no recipient list. It is a separate field so
	// that a missing list is still an error rather than an open account.
	RecipientScope *string `yaml:"recipient_scope"`
	Encoding       *string `yaml:"encoding"`
	Rekey          *struct {
		Authority string `yaml:"authority"`
	} `yaml:"rekey"`
	Cosigner *string `yaml:"cosigner"`
	// UnlockRound is text so that a uint64 survives, and may be written as a number.
	UnlockRound *string `yaml:"unlock_round"`
}

// ParseFile strictly parses a boundary file. This grammar is closed: it
// has no field for TEAL, a template, a base key type, a fee, or runtime arguments.
// Parsing is not the security gate: the provider applies the semantic rules to
// every request, however it arrived.
func ParseFile(data []byte) (*File, error) {
	if len(data) > MaxFileBytes {
		return nil, fmt.Errorf("boundary file exceeds %d bytes", MaxFileBytes)
	}
	var file File
	if err := generictemplate.DecodeStrictYAML(data, &file, generictemplate.RequireStringScalars(ParameterUnlockRound)); err != nil {
		return nil, fmt.Errorf("boundary file: %w", err)
	}
	if file.Schema != SchemaV1 {
		return nil, fmt.Errorf("boundary file: schema must be %s", SchemaV1)
	}
	if len(file.Spend) == 0 {
		return nil, fmt.Errorf("boundary file: spend is required")
	}
	if file.UnlockRound != nil && strings.TrimSpace(*file.UnlockRound) == "" {
		return nil, fmt.Errorf("boundary file: unlock_round is empty")
	}
	anyRecipient := false
	if file.RecipientScope != nil {
		switch *file.RecipientScope {
		case RecipientScopeAny:
			anyRecipient = true
		case RecipientScopeListed:
		default:
			return nil, fmt.Errorf("boundary file: recipient_scope must be %s or %s", RecipientScopeListed, RecipientScopeAny)
		}
	}
	if anyRecipient && file.Recipients != nil {
		return nil, fmt.Errorf("boundary file: recipient_scope %s takes no recipients", RecipientScopeAny)
	}
	if anyRecipient && file.UnlockRound != nil {
		return nil, fmt.Errorf("boundary file: recipient_scope %s does not combine with unlock_round", RecipientScopeAny)
	}
	if !anyRecipient && len(file.Recipients) == 0 && (file.Recipients != nil || file.UnlockRound == nil) {
		return nil, fmt.Errorf("boundary file: recipients is required unless the file sets unlock_round or recipient_scope: %s", RecipientScopeAny)
	}
	if file.Recipients == nil && file.Encoding != nil {
		return nil, fmt.Errorf("boundary file: encoding needs a recipient list")
	}
	if file.Rekey == nil {
		return nil, fmt.Errorf("boundary file: rekey is required")
	}
	if file.Rekey.Authority != RekeySpendingKey && file.Rekey.Authority != RekeyRefused {
		return nil, fmt.Errorf("boundary file: rekey.authority must be %s or %s", RekeySpendingKey, RekeyRefused)
	}
	if file.Cosigner != nil && strings.TrimSpace(*file.Cosigner) == "" {
		return nil, fmt.Errorf("boundary file: cosigner is empty")
	}
	if file.Encoding != nil && *file.Encoding == "" {
		return nil, fmt.Errorf("boundary file: encoding is empty")
	}
	return &file, nil
}

// CreationParameters converts the file to flat creation parameters. It sends
// public values, never the original YAML, and leaves a cosigner name for the
// signer's reference catalog to resolve.
func (f *File) CreationParameters() map[string]string {
	params := map[string]string{
		ParameterSpendEffects:   strings.Join(f.Spend, ","),
		ParameterRekeyAuthority: f.Rekey.Authority,
	}
	if f.Recipients != nil {
		params[ParameterRecipients] = strings.Join(f.Recipients, ",")
	}
	if f.UnlockRound != nil {
		params[ParameterUnlockRound] = *f.UnlockRound
	}
	if f.RecipientScope != nil {
		params[ParameterRecipientScope] = *f.RecipientScope
	}
	if f.Encoding != nil {
		params[ParameterListEncoding] = *f.Encoding
	}
	if f.Cosigner != nil {
		params[ParameterCosigner] = *f.Cosigner
	}
	return params
}

// LoadFile reads a boundary file and returns its creation parameters.
func LoadFile(path string) (map[string]string, error) {
	// Only a regular file is read: a FIFO or device could block or feed the
	// caller, which runs on apadmin's UI path.
	data, _, err := fsutil.ReadRegularFileLimited(path, MaxFileBytes)
	if errors.Is(err, syscall.ELOOP) {
		err = errors.New("a symbolic link is not accepted")
	}
	if err != nil {
		return nil, fmt.Errorf("read boundary file %s: %w", path, err)
	}
	file, err := ParseFile(data)
	if err != nil {
		return nil, err
	}
	return file.CreationParameters(), nil
}
