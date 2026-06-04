// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package endpointrefs defines public endpoint handoff envelopes used by
// apstore export and apshell import.
package endpointrefs

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
	"github.com/aplane-algo/aplane/internal/config"
)

const (
	Kind          = "aplane.endpoint.v1"
	SchemaVersion = 1

	RoleSigning     = "signing"
	RoleAttestation = "attestation"
	RoleDual        = "dual"
)

// Envelope is the public, portable endpoint handoff document.
type Envelope struct {
	Kind               string              `json:"kind"`
	SchemaVersion      int                 `json:"schema_version"`
	Alias              string              `json:"alias"`
	Role               string              `json:"role"`
	URL                string              `json:"url"`
	SignerPort         int                 `json:"signer_port,omitempty"`
	LocalPort          int                 `json:"local_port,omitempty"`
	AttestorPublicKeys []AttestorPublicKey `json:"attestor_public_keys,omitempty"`
}

// AttestorPublicKey is public component-key metadata that can be imported as a
// local attestor route.
type AttestorPublicKey struct {
	KeyType      string `json:"key_type"`
	PublicKeyHex string `json:"public_key_hex"`
	ComponentKey string `json:"component_key"`
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
	if strings.TrimSpace(env.Kind) == "" {
		return Envelope{}, fmt.Errorf("kind is required")
	}
	if env.Kind != Kind {
		return Envelope{}, fmt.Errorf("unsupported endpoint envelope kind %q", env.Kind)
	}
	if env.SchemaVersion == 0 {
		return Envelope{}, fmt.Errorf("schema_version is required and must be %d", SchemaVersion)
	}
	if env.SchemaVersion > SchemaVersion {
		return Envelope{}, fmt.Errorf("unsupported future endpoint envelope schema_version %d", env.SchemaVersion)
	}
	if env.SchemaVersion != SchemaVersion {
		return Envelope{}, fmt.Errorf("unsupported endpoint envelope schema_version %d", env.SchemaVersion)
	}

	env.Alias = strings.TrimSpace(env.Alias)
	if err := config.ValidateClientEndpointAlias(env.Alias); err != nil {
		return Envelope{}, fmt.Errorf("invalid alias: %w", err)
	}

	env.Role = strings.ToLower(strings.TrimSpace(env.Role))
	switch env.Role {
	case RoleSigning, RoleAttestation, RoleDual:
	default:
		return Envelope{}, fmt.Errorf("role must be %s, %s, or %s", RoleSigning, RoleAttestation, RoleDual)
	}

	env.URL = strings.TrimRight(strings.TrimSpace(env.URL), "/")
	if err := validatePortableURL(env.URL); err != nil {
		return Envelope{}, err
	}
	if env.SignerPort < 0 || env.SignerPort > 65535 {
		return Envelope{}, fmt.Errorf("signer_port must be 1-65535 when set")
	}
	if env.LocalPort < 0 || env.LocalPort > 65535 {
		return Envelope{}, fmt.Errorf("local_port must be 1-65535 when set")
	}

	normalizedKeys := make([]AttestorPublicKey, 0, len(env.AttestorPublicKeys))
	seenPublicKeys := map[string]struct{}{}
	seenComponentKeys := map[string]struct{}{}
	for i, key := range env.AttestorPublicKeys {
		normalized, err := NormalizeAttestorPublicKey(key)
		if err != nil {
			return Envelope{}, fmt.Errorf("attestor_public_keys[%d]: %w", i, err)
		}
		if _, ok := seenPublicKeys[normalized.PublicKeyHex]; ok {
			return Envelope{}, fmt.Errorf("attestor_public_keys[%d]: duplicate public_key_hex", i)
		}
		if _, ok := seenComponentKeys[normalized.ComponentKey]; ok {
			return Envelope{}, fmt.Errorf("attestor_public_keys[%d]: duplicate component_key", i)
		}
		seenPublicKeys[normalized.PublicKeyHex] = struct{}{}
		seenComponentKeys[normalized.ComponentKey] = struct{}{}
		normalizedKeys = append(normalizedKeys, normalized)
	}
	env.AttestorPublicKeys = normalizedKeys
	return env, nil
}

func NormalizeAttestorPublicKey(key AttestorPublicKey) (AttestorPublicKey, error) {
	key.KeyType = strings.TrimSpace(key.KeyType)
	if !keytypes.IsAttestorComponentKeyType(key.KeyType) {
		return AttestorPublicKey{}, fmt.Errorf("key_type %q is not an attestor component key type", key.KeyType)
	}

	componentKey, err := keytypes.NormalizeComponentKeySelector(key.ComponentKey)
	if err != nil {
		return AttestorPublicKey{}, fmt.Errorf("invalid component_key: %w", err)
	}

	publicKeyHex := strings.ToLower(strings.TrimSpace(key.PublicKeyHex))
	publicKey, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return AttestorPublicKey{}, fmt.Errorf("public_key_hex must be hex: %w", err)
	}
	wantSize, ok := keytypes.ComponentPublicKeySize(key.KeyType)
	if !ok {
		return AttestorPublicKey{}, fmt.Errorf("key_type %q is not an attestor component key type", key.KeyType)
	}
	if len(publicKey) != wantSize {
		return AttestorPublicKey{}, fmt.Errorf("public_key_hex length %d invalid (expected %d bytes)", len(publicKey), wantSize)
	}
	derived, err := keytypes.ComponentKeySelector(key.KeyType, publicKey)
	if err != nil {
		return AttestorPublicKey{}, err
	}
	if componentKey != derived {
		return AttestorPublicKey{}, fmt.Errorf("component_key %q does not match public_key_hex-derived selector %q", componentKey, derived)
	}

	return AttestorPublicKey{
		KeyType:      key.KeyType,
		PublicKeyHex: publicKeyHex,
		ComponentKey: componentKey,
	}, nil
}

func validatePortableURL(raw string) error {
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
