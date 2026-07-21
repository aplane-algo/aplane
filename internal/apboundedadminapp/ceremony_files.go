// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apboundedadminapp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	boundedauthorization "github.com/aplane-algo/aplane/internal/boundedadmin/authorization"
	boundedprotocol "github.com/aplane-algo/aplane/internal/boundedadmin/protocol"
)

const (
	RequestExtension  = ".apbounded-admin-request"
	ResponseExtension = ".apbounded-admin-signature"
)

// ReadRequest reads a strict ceremony request from a regular file, or stdin for "-".
func ReadRequest(path string, stdin io.Reader) (boundedprotocol.Request, error) {
	reader, closeFile, err := ceremonyReader(path, RequestExtension, stdin, boundedprotocol.MaxRequestBytes)
	if err != nil {
		return boundedprotocol.Request{}, err
	}
	defer closeFile()
	return boundedprotocol.DecodeRequest(reader)
}

// ReadResponse reads a strict ceremony response from a regular file, or stdin for "-".
func ReadResponse(path string, stdin io.Reader) (boundedprotocol.Response, error) {
	reader, closeFile, err := ceremonyReader(path, ResponseExtension, stdin, boundedprotocol.MaxResponseBytes)
	if err != nil {
		return boundedprotocol.Response{}, err
	}
	defer closeFile()
	return boundedprotocol.DecodeResponse(reader)
}

// WriteRequest writes a validated request atomically without overwriting a file.
func WriteRequest(path string, request boundedprotocol.Request, stdout io.Writer) error {
	if _, err := boundedauthorization.ValidateRequest(request); err != nil {
		return err
	}
	return writeCeremony(path, RequestExtension, request, stdout)
}

// WriteResponse writes a response atomically without overwriting a file.
func WriteResponse(path string, response boundedprotocol.Response, stdout io.Writer) error {
	if response.Schema != boundedprotocol.ResponseSchemaV1 {
		return fmt.Errorf("unsupported bounded-admin response schema %q", response.Schema)
	}
	return writeCeremony(path, ResponseExtension, response, stdout)
}

func ceremonyReader(path, extension string, stdin io.Reader, maxBytes int64) (io.Reader, func(), error) {
	if path == "-" {
		if stdin == nil {
			return nil, func() {}, fmt.Errorf("standard input is unavailable")
		}
		return io.LimitReader(stdin, maxBytes+1), func() {}, nil
	}
	if filepath.Ext(path) != extension {
		return nil, func() {}, fmt.Errorf("ceremony file must use the %s extension", extension)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, func() {}, fmt.Errorf("inspect ceremony file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxBytes {
		return nil, func() {}, fmt.Errorf("ceremony file must be a non-empty regular file no larger than %d bytes", maxBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, func() {}, fmt.Errorf("open ceremony file: %w", err)
	}
	return file, func() { _ = file.Close() }, nil
}

func writeCeremony(path, extension string, value any, stdout io.Writer) error {
	if path == "-" {
		return encodeJSON(stdout, value)
	}
	if filepath.Ext(path) != extension {
		return fmt.Errorf("ceremony output must use the %s extension", extension)
	}
	directory := filepath.Dir(path)
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("ceremony output directory must be an existing directory")
	}
	temp, err := os.CreateTemp(directory, ".witness-key-ceremony-")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer func() { _ = temp.Close(); _ = os.Remove(tempPath) }()
	if err := temp.Chmod(0o600); err != nil {
		return err
	}
	if err := encodeJSON(temp, value); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Link(tempPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("refusing to overwrite existing path %q", path)
		}
		return err
	}
	if err := os.Remove(tempPath); err != nil {
		_ = os.Remove(path)
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		_ = os.Remove(path)
		return err
	}
	err = dir.Sync()
	_ = dir.Close()
	if err != nil {
		_ = os.Remove(path)
	}
	return err
}

func encodeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
