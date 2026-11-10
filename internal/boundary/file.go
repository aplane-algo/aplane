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
		// To is the rekey-to list, with authority only_these or plus_cosigned.
		To []string `yaml:"to"`
	} `yaml:"rekey"`
	Cosigner *string `yaml:"cosigner"`
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
	if err := generictemplate.DecodeStrictYAML(data, &file, generictemplate.RequireStringScalars()); err != nil {
		return nil, fmt.Errorf("boundary file: %w", err)
	}
	if file.Schema != SchemaV1 {
		return nil, fmt.Errorf("boundary file: schema must be %s", SchemaV1)
	}
	// Without spend the file has no bounds: it describes the overlays alone, a
	// plain1 account, so it can't name what only bounds take.
	if len(file.Spend) == 0 {
		if file.Spend != nil {
			return nil, fmt.Errorf("boundary file: spend is empty; leave it out for an account without bounds")
		}
		for _, field := range []struct {
			name string
			set  bool
		}{
			{"recipients", file.Recipients != nil},
			{"recipient_scope", file.RecipientScope != nil},
			{"encoding", file.Encoding != nil},
		} {
			if field.set {
				return nil, fmt.Errorf("boundary file: %s needs spend, the transfer kinds the account may make", field.name)
			}
		}
	}
	anyRecipient, listed := false, false
	if file.RecipientScope != nil {
		switch *file.RecipientScope {
		case RecipientScopeAny:
			anyRecipient = true
		case RecipientScopeListed:
			listed = true
		default:
			return nil, fmt.Errorf("boundary file: recipient_scope must be %s or %s", RecipientScopeListed, RecipientScopeAny)
		}
	}
	if anyRecipient && file.Recipients != nil {
		return nil, fmt.Errorf("boundary file: recipient_scope %s takes no recipients", RecipientScopeAny)
	}
	// An explicit listed scope asks for a list, as the provider reads it.
	if listed && len(file.Recipients) == 0 {
		return nil, fmt.Errorf("boundary file: recipient_scope %s needs recipients", RecipientScopeListed)
	}
	if len(file.Spend) != 0 && !anyRecipient && len(file.Recipients) == 0 {
		return nil, fmt.Errorf("boundary file: recipients is required unless the file sets recipient_scope: %s", RecipientScopeAny)
	}
	if file.Recipients == nil && file.Encoding != nil {
		return nil, fmt.Errorf("boundary file: encoding needs a recipient list")
	}
	if file.Rekey == nil {
		return nil, fmt.Errorf("boundary file: rekey is required")
	}
	switch file.Rekey.Authority {
	case RekeyOnlyThese, RekeyPlusCosigned:
		if len(file.Rekey.To) == 0 {
			return nil, fmt.Errorf("boundary file: rekey.authority %s needs the addresses in rekey.to", file.Rekey.Authority)
		}
	case RekeyRefused, RekeySpendingKey:
		if file.Rekey.To != nil {
			return nil, fmt.Errorf("boundary file: rekey.to needs rekey.authority %s or %s", RekeyOnlyThese, RekeyPlusCosigned)
		}
	default:
		return nil, fmt.Errorf("boundary file: rekey.authority must be %s, %s, %s or %s", RekeyRefused, RekeySpendingKey, RekeyOnlyThese, RekeyPlusCosigned)
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
	params := map[string]string{ParameterRekeyAuthority: f.Rekey.Authority}
	if len(f.Spend) != 0 {
		params[ParameterSpendEffects] = strings.Join(f.Spend, ",")
	}
	if f.Rekey.To != nil {
		params[ParameterRekeyTo] = strings.Join(f.Rekey.To, ",")
	}
	if f.Recipients != nil {
		params[ParameterRecipients] = strings.Join(f.Recipients, ",")
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
