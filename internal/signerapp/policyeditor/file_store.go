// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyeditor

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/serverconfig"
)

// FileStore edits one standalone policy draft. It has no keystore, integrity
// sidecar, signer-store lock, or ownership-normalization authority.
type FileStore struct {
	Path    string
	Target  Target
	DataDir string
	Config  *serverconfig.ServerConfig
}

// Persistence reports that Save replaces only this standalone draft.
func (s *FileStore) Persistence() Persistence {
	if s == nil {
		return Persistence{Kind: PersistenceDraft}
	}
	return Persistence{Kind: PersistenceDraft, Path: s.Path}
}

// ModeLabel identifies this backend in policytui headers.
func (s *FileStore) ModeLabel() string {
	return "standalone draft"
}

func (s *FileStore) Load(ctx context.Context) (*policy.StoredConfig, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy YAML file: %w", err)
	}
	if strings.TrimSpace(string(data)) == "" {
		return nil, fmt.Errorf("policy YAML file is empty")
	}
	stored, err := s.target().Parse(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", s.target().DocumentName(), err)
	}
	if err := s.Validate(ctx, stored); err != nil {
		return nil, err
	}
	return stored, nil
}

func (s *FileStore) Save(ctx context.Context, stored *policy.StoredConfig) error {
	if err := s.Validate(ctx, stored); err != nil {
		return err
	}
	data, err := s.target().Marshal(stored)
	if err != nil {
		return fmt.Errorf("failed to marshal %s: %w", s.target().DocumentName(), err)
	}
	if err := fsutil.WriteFileDurable(s.Path, data); err != nil {
		return fmt.Errorf("failed to save policy draft: %w", err)
	}
	return nil
}

func (s *FileStore) Validate(ctx context.Context, stored *policy.StoredConfig) error {
	validator := OfflineStore{DataDir: s.DataDir, Target: s.target(), Config: s.Config}
	return validator.Validate(ctx, stored)
}

func (s *FileStore) target() Target {
	if s.Target == "" || s.Target == TargetAuto {
		return TargetSigner
	}
	return s.Target
}
