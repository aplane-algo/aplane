// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apboundedadminapp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"

	boundedprotocol "github.com/aplane-algo/aplane/internal/boundedadmin/protocol"
)

type processSigner struct {
	executable func() (string, error)
	stderr     io.Writer
}

func newProcessSigner(stderr io.Writer) *processSigner {
	return &processSigner{executable: os.Executable, stderr: stderr}
}

func (s *processSigner) Sign(ctx context.Context, artifactPath string, request boundedprotocol.Request) (boundedprotocol.Response, error) {
	if artifactPath == "" {
		return boundedprotocol.Response{}, fmt.Errorf("bounded-admin key path is required")
	}
	executable, err := s.executable()
	if err != nil {
		return boundedprotocol.Response{}, fmt.Errorf("locate apbounded-admin executable: %w", err)
	}
	info, err := os.Lstat(executable)
	if err != nil {
		return boundedprotocol.Response{}, fmt.Errorf("inspect apbounded-admin executable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
		return boundedprotocol.Response{}, fmt.Errorf("apbounded-admin executable is not a regular executable file: %s", executable)
	}
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return boundedprotocol.Response{}, fmt.Errorf("encode bounded-admin request: %w", err)
	}
	requestJSON = append(requestJSON, '\n')

	cmd := exec.CommandContext(ctx, executable, "sign", "--key", artifactPath)
	cmd.Stdin = bytes.NewReader(requestJSON)
	cmd.Stderr = s.stderr
	cmd.Env = helperEnvironment()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return boundedprotocol.Response{}, fmt.Errorf("open apbounded-admin response pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return boundedprotocol.Response{}, fmt.Errorf("start apbounded-admin signing child: %w", err)
	}
	response, decodeErr := boundedprotocol.DecodeResponse(io.LimitReader(stdout, boundedprotocol.MaxResponseBytes+1))
	waitErr := cmd.Wait()
	if waitErr != nil {
		return boundedprotocol.Response{}, fmt.Errorf("apbounded-admin signing child failed: %w", waitErr)
	}
	if decodeErr != nil {
		return boundedprotocol.Response{}, decodeErr
	}
	return response, nil
}

func helperEnvironment() []string {
	allowed := []string{"HOME", "LANG", "LC_ALL", "TERM", "TMPDIR", "LD_LIBRARY_PATH"}
	env := make([]string, 0, len(allowed))
	for _, name := range allowed {
		if value, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+value)
		}
	}
	return env
}
