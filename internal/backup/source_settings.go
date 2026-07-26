// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aplane-algo/aplane/internal/backup/sourcecontext"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/noderole"
)

const (
	// SourceSettingsFileName is the optional, independently versioned source
	// context member in a managed backup archive.
	SourceSettingsFileName = "source_settings.json"
	// SourceSettingsSchema identifies the source-settings sidecar schema.
	SourceSettingsSchema = "aplane.backup.source-settings.v1"
	// SourceSettingsSchemaVersion is the current sidecar schema version.
	SourceSettingsSchemaVersion = 1

	maxSourceSettingsBytes        = 256 * 1024
	maxSourceSettingsWarningBytes = 512
)

// SourceSettingsSnapshot is the non-secret runtime context captured by a new
// managed backup. UserAutoApprove is required for signer sources and omitted
// for sentry sources. GenesisHashMappings contains custom mappings only.
type SourceSettingsSnapshot struct {
	UserAutoApprove     *bool
	GenesisHashMappings map[string]string
}

type sourceSettingsDocument struct {
	Schema              string                             `json:"schema"`
	SchemaVersion       int                                `json:"schema_version"`
	UserAutoApprove     *bool                              `json:"user_auto_approve,omitempty"`
	GenesisHashMappings []sourcecontext.GenesisHashMapping `json:"genesis_hash_mappings,omitempty"`
}

type sourceSettingsInspection struct {
	Status     sourcecontext.Status
	SHA256     string
	Projection sourcecontext.Projection
	Warning    string
}

func writeSourceSettings(
	destDir string,
	role noderole.Role,
	snapshot SourceSettingsSnapshot,
) error {
	projection, err := sourcecontext.NormalizeProjection(
		role,
		snapshot.UserAutoApprove,
		snapshot.GenesisHashMappings,
	)
	if err != nil {
		return fmt.Errorf("validate backup source settings: %w", err)
	}
	document := sourceSettingsDocument{
		Schema:              SourceSettingsSchema,
		SchemaVersion:       SourceSettingsSchemaVersion,
		UserAutoApprove:     projection.UserAutoApprove,
		GenesisHashMappings: projection.GenesisHashMappings,
	}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal backup source settings: %w", err)
	}
	data = append(data, '\n')
	if len(data) > maxSourceSettingsBytes {
		return fmt.Errorf("backup source settings exceed size limit %d", maxSourceSettingsBytes)
	}
	if err := fsutil.WriteFile(filepath.Join(destDir, SourceSettingsFileName), data); err != nil {
		return fmt.Errorf("write backup source settings: %w", err)
	}
	return nil
}

func inspectSourceSettings(sourceRoot, sourceNodeRole string) sourceSettingsInspection {
	path := filepath.Join(sourceRoot, SourceSettingsFileName)
	data, err := readSourceSettingsFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return sourceSettingsInspection{Status: sourcecontext.StatusMissing}
		}
		return invalidSourceSettings(fmt.Errorf("read source settings: %w", err))
	}

	var document sourceSettingsDocument
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return invalidSourceSettings(fmt.Errorf("parse source settings: %w", err))
	}
	if err := requireJSONEOF(decoder); err != nil {
		return invalidSourceSettings(err)
	}
	if document.Schema != SourceSettingsSchema {
		return invalidSourceSettings(fmt.Errorf(
			"unsupported source settings schema %q",
			document.Schema,
		))
	}
	if document.SchemaVersion != SourceSettingsSchemaVersion {
		return invalidSourceSettings(fmt.Errorf(
			"unsupported source settings schema_version %d",
			document.SchemaVersion,
		))
	}
	role, err := noderole.ParseRole(sourceNodeRole)
	if err != nil {
		return invalidSourceSettings(fmt.Errorf("source settings require known source node role: %w", err))
	}
	projection := sourcecontext.Projection{
		UserAutoApprove:     document.UserAutoApprove,
		GenesisHashMappings: document.GenesisHashMappings,
	}
	if err := sourcecontext.ValidateProjection(role, projection); err != nil {
		return invalidSourceSettings(fmt.Errorf("validate source settings: %w", err))
	}
	sum := sha256.Sum256(data)
	return sourceSettingsInspection{
		Status:     sourcecontext.StatusUnverified,
		SHA256:     hex.EncodeToString(sum[:]),
		Projection: sourcecontext.CloneProjection(projection),
	}
}

func readSourceSettingsFile(path string) ([]byte, error) {
	file, err := openManagedBackupArchive(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxSourceSettingsBytes {
		return nil, fmt.Errorf("source settings exceed size limit %d", maxSourceSettingsBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxSourceSettingsBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSourceSettingsBytes {
		return nil, fmt.Errorf("source settings exceed size limit %d", maxSourceSettingsBytes)
	}
	return data, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return fmt.Errorf("parse trailing source settings data: %w", err)
	}
	return fmt.Errorf("source settings contain trailing JSON value")
}

func invalidSourceSettings(err error) sourceSettingsInspection {
	warning := "source settings metadata is invalid"
	if err != nil {
		warning += ": " + err.Error()
	}
	if len(warning) > maxSourceSettingsWarningBytes {
		warning = strings.TrimSpace(warning[:maxSourceSettingsWarningBytes])
	}
	return sourceSettingsInspection{
		Status:  sourcecontext.StatusInvalid,
		Warning: warning,
	}
}
