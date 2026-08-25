// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package noderole owns the durable single-purpose role for an apsigner data
// root. The role is stored in root node.yaml and integrity-bound to the product store.
package noderole

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	SchemaVersion = 1
)

type Role string

const (
	RoleSigner Role = "signer"
	RoleSentry Role = "sentry"
)

var (
	ErrInvalidRole     = errors.New("invalid node role")
	ErrInvalidDocument = errors.New("invalid node role document")
	ErrRoleFileExists  = errors.New("node role already initialized")
	ErrRoleFileMissing = errors.New("node role file missing")
	ErrRoleFileUnread  = errors.New("node role file unreadable")
	ErrRoleIntegrity   = errors.New("node role integrity check failed")
	ErrRoleSidecarBad  = errors.New("node role integrity sidecar invalid")
	ErrRoleSidecarMiss = errors.New("node role integrity sidecar missing")
	ErrRoleUnsupported = errors.New("node role integrity sidecar unsupported")
	ErrRoleMismatch    = errors.New("node role integrity mismatch")
)

type Document struct {
	SchemaVersion int    `yaml:"schema_version"`
	Role          Role   `yaml:"role"`
	CreatedAt     string `yaml:"created_at,omitempty"`
}

func DefaultRole() Role {
	return RoleSigner
}

func ParseRole(raw string) (Role, error) {
	switch role := Role(strings.ToLower(strings.TrimSpace(raw))); role {
	case RoleSigner, RoleSentry:
		return role, nil
	default:
		return "", fmt.Errorf("%w: %q must be one of: %s, %s", ErrInvalidRole, raw, RoleSigner, RoleSentry)
	}
}

func NewDocument(role Role, createdAt time.Time) (Document, error) {
	if _, err := ParseRole(string(role)); err != nil {
		return Document{}, err
	}
	if createdAt.IsZero() {
		createdAt = time.Now()
	}
	return Document{
		SchemaVersion: SchemaVersion,
		Role:          role,
		CreatedAt:     createdAt.UTC().Format(time.RFC3339),
	}, nil
}

func ParseDocument(data []byte) (Document, error) {
	var doc Document
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&doc); err != nil {
		return Document{}, fmt.Errorf("%w: failed to parse node.yaml: %w", ErrInvalidDocument, err)
	}
	if doc.SchemaVersion != SchemaVersion {
		return Document{}, fmt.Errorf("%w: schema_version %d", ErrInvalidDocument, doc.SchemaVersion)
	}
	role, err := ParseRole(string(doc.Role))
	if err != nil {
		return Document{}, err
	}
	doc.Role = role
	if strings.TrimSpace(doc.CreatedAt) != "" {
		if _, err := time.Parse(time.RFC3339, doc.CreatedAt); err != nil {
			return Document{}, fmt.Errorf("%w: created_at must be RFC3339: %w", ErrInvalidDocument, err)
		}
	}
	return doc, nil
}

func MarshalDocument(doc Document) ([]byte, error) {
	if doc.SchemaVersion == 0 {
		doc.SchemaVersion = SchemaVersion
	}
	if doc.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: schema_version %d", ErrInvalidDocument, doc.SchemaVersion)
	}
	role, err := ParseRole(string(doc.Role))
	if err != nil {
		return nil, err
	}
	doc.Role = role
	doc.CreatedAt = strings.TrimSpace(doc.CreatedAt)
	if doc.CreatedAt != "" {
		if _, err := time.Parse(time.RFC3339, doc.CreatedAt); err != nil {
			return nil, fmt.Errorf("%w: created_at must be RFC3339: %w", ErrInvalidDocument, err)
		}
	}
	data, err := yaml.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal node role document: %w", err)
	}
	return data, nil
}
