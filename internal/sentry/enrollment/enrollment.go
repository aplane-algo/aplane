// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package enrollment defines the public composition envelope used to hand a
// sentry witness reference and optional endpoint metadata to an operator.
package enrollment

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/aplane-algo/aplane/internal/endpointrefs"
	"github.com/aplane-algo/aplane/internal/witness"
)

const (
	// Schema is the compatibility discriminator for the combined public
	// sentry-enrollment envelope.
	Schema = "aplane.sentry-enrollment.v1"

	// MaxEnvelopeBytes bounds public enrollment input before JSON decoding.
	MaxEnvelopeBytes = 64 * 1024
)

// Envelope composes a canonical public witness reference with optional,
// portable endpoint routing metadata. It contains no client-local alias,
// endpoint role, token, host trust, or private witness material.
type Envelope struct {
	Schema   string                  `json:"schema"`
	Witness  witness.PublicReference `json:"witness"`
	Endpoint *endpointrefs.Envelope  `json:"endpoint,omitempty"`
}

// Artifact is the provenance-agnostic public authority projection accepted by
// enrollment workflows. Combined reports whether the source used Envelope;
// Endpoint is nil for a legacy witness-only public reference.
type Artifact struct {
	Witness  witness.PublicReference
	Endpoint *endpointrefs.Envelope
	Combined bool
}

type rawEnvelope struct {
	Schema   string          `json:"schema"`
	Witness  json.RawMessage `json:"witness"`
	Endpoint json.RawMessage `json:"endpoint,omitempty"`
}

// Normalize validates and canonicalizes a combined enrollment envelope by
// delegating nested contracts to their owning packages.
func Normalize(envelope Envelope) (Envelope, error) {
	if envelope.Schema == "" {
		return Envelope{}, fmt.Errorf("schema is required")
	}
	if envelope.Schema != Schema {
		return Envelope{}, fmt.Errorf("unsupported sentry enrollment schema %q", envelope.Schema)
	}

	reference, err := witness.NewPublicReference(
		envelope.Witness.KeyType,
		envelope.Witness.WitnessKeyID,
		envelope.Witness.PublicKeyHex,
	)
	if err != nil {
		return Envelope{}, fmt.Errorf("invalid witness reference: %w", err)
	}

	normalized := Envelope{Schema: Schema, Witness: reference}
	if envelope.Endpoint != nil {
		endpoint, err := endpointrefs.Normalize(*envelope.Endpoint)
		if err != nil {
			return Envelope{}, fmt.Errorf("invalid endpoint reference: %w", err)
		}
		normalized.Endpoint = &endpoint
	}
	return normalized, nil
}

// Parse strictly decodes and validates a combined sentry-enrollment envelope.
func Parse(data []byte) (Envelope, error) {
	if err := validateSize(data); err != nil {
		return Envelope{}, err
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var raw rawEnvelope
	if err := decoder.Decode(&raw); err != nil {
		return Envelope{}, fmt.Errorf("decode sentry enrollment envelope: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return Envelope{}, fmt.Errorf("decode sentry enrollment envelope: %w", err)
	}
	if raw.Schema == "" {
		return Envelope{}, fmt.Errorf("schema is required")
	}
	if raw.Schema != Schema {
		return Envelope{}, fmt.Errorf("unsupported sentry enrollment schema %q", raw.Schema)
	}
	if missingOrNull(raw.Witness) {
		return Envelope{}, fmt.Errorf("witness is required and must not be null")
	}

	reference, err := witness.ParsePublicReference(raw.Witness)
	if err != nil {
		return Envelope{}, fmt.Errorf("invalid witness reference: %w", err)
	}

	envelope := Envelope{Schema: Schema, Witness: reference}
	if len(raw.Endpoint) != 0 {
		if missingOrNull(raw.Endpoint) {
			return Envelope{}, fmt.Errorf("endpoint must not be null")
		}
		endpoint, err := endpointrefs.Parse(raw.Endpoint)
		if err != nil {
			return Envelope{}, fmt.Errorf("invalid endpoint reference: %w", err)
		}
		envelope.Endpoint = &endpoint
	}
	return envelope, nil
}

// Marshal validates and emits a stable combined enrollment envelope.
func Marshal(envelope Envelope) ([]byte, error) {
	normalized, err := Normalize(envelope)
	if err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode sentry enrollment envelope: %w", err)
	}
	data = append(data, '\n')
	if err := validateSize(data); err != nil {
		return nil, err
	}
	return data, nil
}

// ParseArtifact accepts either the existing witness-only public reference or
// the combined enrollment envelope and projects the same validated authority.
func ParseArtifact(data []byte) (Artifact, error) {
	if err := validateSize(data); err != nil {
		return Artifact{}, err
	}

	var discriminator struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &discriminator); err != nil {
		return Artifact{}, fmt.Errorf("decode sentry enrollment artifact: %w", err)
	}
	switch discriminator.Schema {
	case witness.PublicReferenceSchema:
		reference, err := witness.ParsePublicReference(data)
		if err != nil {
			return Artifact{}, err
		}
		return Artifact{Witness: reference}, nil
	case Schema:
		envelope, err := Parse(data)
		if err != nil {
			return Artifact{}, err
		}
		return Artifact{Witness: envelope.Witness, Endpoint: envelope.Endpoint, Combined: true}, nil
	case "":
		return Artifact{}, fmt.Errorf("sentry enrollment artifact schema is required")
	default:
		return Artifact{}, fmt.Errorf("unsupported sentry enrollment artifact schema %q", discriminator.Schema)
	}
}

// MarshalWitness emits the canonical witness-only document submitted through
// the existing authorized signer-reference import RPC.
func MarshalWitness(reference witness.PublicReference) ([]byte, error) {
	normalized, err := witness.NewPublicReference(
		reference.KeyType,
		reference.WitnessKeyID,
		reference.PublicKeyHex,
	)
	if err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode public witness reference: %w", err)
	}
	return append(data, '\n'), nil
}

func validateSize(data []byte) error {
	if len(data) == 0 || len(data) > MaxEnvelopeBytes {
		return fmt.Errorf("sentry enrollment artifact size %d is invalid", len(data))
	}
	return nil
}

func missingOrNull(data json.RawMessage) bool {
	return len(data) == 0 || bytes.Equal(bytes.TrimSpace(data), []byte("null"))
}

func requireEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}
