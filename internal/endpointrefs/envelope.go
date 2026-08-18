// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package endpointrefs defines public endpoint handoff envelopes used by
// apadmin export and apshell import.
package endpointrefs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
)

const (
	Schema = "aplane.endpoint.v1"
)

// Envelope is the public, portable endpoint handoff document.
type Envelope struct {
	Schema     string `json:"schema"`
	URL        string `json:"url"`
	SignerPort int    `json:"signer_port,omitempty"`
	LocalPort  int    `json:"local_port,omitempty"`
}

// Parse decodes and validates a strict endpoint envelope.
func Parse(data []byte) (Envelope, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var env Envelope
	if err := dec.Decode(&env); err != nil {
		return Envelope{}, fmt.Errorf("failed to parse endpoint envelope: %w", err)
	}
	var extra struct{}
	if err := dec.Decode(&extra); err != io.EOF {
		return Envelope{}, fmt.Errorf("endpoint envelope has trailing JSON content")
	}
	return Normalize(env)
}

// Marshal validates and serializes an endpoint envelope with stable formatting.
func Marshal(env Envelope) ([]byte, error) {
	normalized, err := Normalize(env)
	if err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to encode endpoint envelope: %w", err)
	}
	return append(data, '\n'), nil
}

// Normalize validates and canonicalizes an endpoint envelope.
func Normalize(env Envelope) (Envelope, error) {
	if strings.TrimSpace(env.Schema) == "" {
		return Envelope{}, fmt.Errorf("schema is required")
	}
	if env.Schema != Schema {
		return Envelope{}, fmt.Errorf("unsupported endpoint envelope schema %q", env.Schema)
	}

	env.URL = strings.TrimRight(strings.TrimSpace(env.URL), "/")
	if err := ValidatePortableURL(env.URL); err != nil {
		return Envelope{}, err
	}
	if env.SignerPort < 0 || env.SignerPort > 65535 {
		return Envelope{}, fmt.Errorf("signer_port must be 1-65535 when set")
	}
	if env.LocalPort < 0 || env.LocalPort > 65535 {
		return Envelope{}, fmt.Errorf("local_port must be 1-65535 when set")
	}
	return env, nil
}

// ValidatePortableURL validates a URL that is safe to put in a public endpoint
// handoff envelope.
func ValidatePortableURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("url is required")
	}
	if raw == "self" {
		return fmt.Errorf("url %q is not allowed in exported endpoint envelopes", raw)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	switch parsed.Scheme {
	case "ssh", "https", "http":
	default:
		return fmt.Errorf("unsupported url scheme %q", parsed.Scheme)
	}
	if parsed.Hostname() == "" {
		return fmt.Errorf("url host is required")
	}
	if parsed.Port() != "" {
		port, err := strconv.Atoi(parsed.Port())
		if err != nil || port <= 0 || port > 65535 {
			return fmt.Errorf("invalid url port %q", parsed.Port())
		}
	}
	if parsed.Scheme == "http" && !isLoopbackHost(parsed.Hostname()) {
		return fmt.Errorf("raw http endpoints must be loopback; use ssh:// or https:// for remote endpoints")
	}
	return nil
}

func isLoopbackHost(host string) bool {
	host = strings.Trim(strings.ToLower(host), "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
