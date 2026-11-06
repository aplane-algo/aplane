// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package boundary

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
)

// MaxFileBytes bounds the file size before parsing. It leaves room for
// a full list of 58-character addresses in block style.
const MaxFileBytes = 8 << 20

// File is a parsed boundary file. It holds only what the file says: a
// cosigner stays a name for the signer to resolve, and the admin key stays a path.
type File struct {
	Schema     string   `yaml:"schema"`
	Spend      []string `yaml:"spend"`
	Recipients []string `yaml:"recipients"`
	Encoding   *string  `yaml:"encoding"`
	Rekey      *struct {
		Authority string  `yaml:"authority"`
		AdminKey  *string `yaml:"admin_key"`
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
	if len(file.Recipients) == 0 && (file.Recipients != nil || file.UnlockRound == nil) {
		return nil, fmt.Errorf("boundary file: recipients is required unless the file sets unlock_round")
	}
	if file.Recipients == nil && file.Encoding != nil {
		return nil, fmt.Errorf("boundary file: encoding needs a recipient list")
	}
	if file.Rekey == nil {
		return nil, fmt.Errorf("boundary file: rekey is required")
	}
	switch file.Rekey.Authority {
	case RekeySpendingKey:
		if file.Rekey.AdminKey != nil {
			return nil, fmt.Errorf("boundary file: rekey.admin_key is not used with authority %s", RekeySpendingKey)
		}
	case RekeyAdminKey:
		if file.Rekey.AdminKey == nil || strings.TrimSpace(*file.Rekey.AdminKey) == "" {
			return nil, fmt.Errorf("boundary file: authority %s requires rekey.admin_key", RekeyAdminKey)
		}
	default:
		return nil, fmt.Errorf("boundary file: rekey.authority must be %s or %s", RekeySpendingKey, RekeyAdminKey)
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
// public values, never a path or the original YAML, and leaves a cosigner name
// for the signer's reference catalog to resolve.
func (f *File) CreationParameters(directory string) (map[string]string, error) {
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
	if f.Encoding != nil {
		params[ParameterListEncoding] = *f.Encoding
	}
	if f.Cosigner != nil {
		params[ParameterCosigner] = *f.Cosigner
	}
	if f.Rekey.AdminKey != nil {
		publicKey, err := readAdminPublicKey(directory, *f.Rekey.AdminKey)
		if err != nil {
			return nil, err
		}
		params[boundedmeta.AdminPublicKeyParameter] = publicKey
	}
	return params, nil
}

// AdminKeyID identifies the contract admin key in creation parameters, for a summary
// made before the signer has seen them. The grammar accepts only a Falcon-1024
// witness here, so this is not a guess at the key's type. It returns "" when the
// parameters name no admin key.
func AdminKeyID(params map[string]string) (string, error) {
	value := params[boundedmeta.AdminPublicKeyParameter]
	if value == "" {
		return "", nil
	}
	publicKey, err := boundedmeta.ParseAdminPublicKey(value)
	if err != nil {
		return "", err
	}
	return witness.ID(witness.Falcon1024V1, publicKey)
}

// LoadFile reads a boundary file and returns its creation parameters.
func LoadFile(path string) (map[string]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read boundary file: %w", err)
	}
	if info.Size() > MaxFileBytes {
		return nil, fmt.Errorf("boundary file exceeds %d bytes", MaxFileBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read boundary file: %w", err)
	}
	file, err := ParseFile(data)
	if err != nil {
		return nil, err
	}
	return file.CreationParameters(filepath.Dir(path))
}

// readAdminPublicKey reads the public .cos.json envelope. A relative path is
// resolved against the boundary file, so a file works from any directory.
func readAdminPublicKey(directory, path string) (string, error) {
	if !filepath.IsAbs(path) {
		path = filepath.Join(directory, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read admin cosigner: %w", err)
	}
	reference, err := witness.ParsePublicReference(data)
	if err != nil {
		return "", fmt.Errorf("admin cosigner %s: %w", path, err)
	}
	if reference.KeyType != witness.Falcon1024V1 {
		return "", fmt.Errorf("admin cosigner %s has key type %s, need %s", path, reference.KeyType, witness.Falcon1024V1)
	}
	return reference.PublicKeyHex, nil
}
