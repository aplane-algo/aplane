// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package endpointrefs defines public endpoint handoff envelopes used by
// apadmin export and apshell import, and the URL rule every endpoint URL
// follows.
package endpointrefs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
)

const (
	Schema = "aplane.endpoint.v1"
)

// Envelope is the public, portable endpoint handoff document: the schema and
// the URL. Nothing else selects the service; an ssh:// node forwards every
// channel to its own REST listener.
type Envelope struct {
	Schema string `json:"schema"`
	URL    string `json:"url"`
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
	if _, _, err := ParseURL(env.URL); err != nil {
		return Envelope{}, err
	}
	return env, nil
}

// ParseURL parses an endpoint URL, which is ssh://host[:port]. A node is
// reached only through its SSH server, which authenticates the client's
// enrolled key and hands each API channel to the node's REST handler with
// that identity; no other scheme could carry it. port is 0 when the URL
// names none.
func ParseURL(raw string) (host string, port int, err error) {
	if raw == "" {
		return "", 0, fmt.Errorf("url is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", 0, fmt.Errorf("invalid url: %w", err)
	}
	if parsed.Scheme != "ssh" {
		return "", 0, fmt.Errorf("unsupported url scheme %q; endpoints are ssh://host[:port]", parsed.Scheme)
	}
	host = parsed.Hostname()
	if host == "" {
		return "", 0, fmt.Errorf("url host is required")
	}
	if parsed.Port() != "" {
		port, err = strconv.Atoi(parsed.Port())
		if err != nil || port <= 0 || port > 65535 {
			return "", 0, fmt.Errorf("invalid url port %q", parsed.Port())
		}
	}
	return host, port, nil
}
