// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package protocol defines the Falcon-free external bounded-admin wire format.
package protocol

import (
	"bytes"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/signerapi"
)

const (
	RequestSchemaV1  = "aplane.bounded-admin-request.v1"
	ResponseSchemaV1 = "aplane.bounded-admin-signature.v1"

	requestHashDomainV1 = "APLANE_BOUNDED_ADMIN_REQUEST_V1"

	ErrorUnsupportedRequestSchema  = "unsupported_request_schema"
	ErrorUnsupportedResponseSchema = "unsupported_response_schema"

	MaxRequestBytes  = 512 * 1024
	MaxResponseBytes = 16 * 1024
)

// Error carries a stable protocol failure code where version skew must be
// distinguishable from malformed ceremony data.
type Error struct {
	Code string
	Err  error
}

func (e *Error) Error() string {
	if e == nil || e.Err == nil {
		return "bounded-admin protocol error"
	}
	return e.Err.Error()
}

func (e *Error) Unwrap() error { return e.Err }

// ErrorCode returns a stable protocol error code, if present.
func ErrorCode(err error) string {
	var protocolErr *Error
	if errors.As(err, &protocolErr) {
		return protocolErr.Code
	}
	return ""
}

// RequestPayload is the exact non-secret authority fragment reviewed by the
// external contract-admin helper.
type RequestPayload struct {
	Partial            signerapi.BoundedAdminPartialResponse `json:"partial"`
	Network            string                                `json:"network"`
	GenesisHashHex     string                                `json:"genesis_hash_hex"`
	CurrentAuthAddress string                                `json:"current_auth_address"`
}

// Request binds a signer partial to its network and authorization context.
type Request struct {
	Schema         string         `json:"schema"`
	Payload        RequestPayload `json:"payload"`
	RequestHashHex string         `json:"request_hash_hex"`
}

// Response contains only the request-bound Falcon contract-admin signature.
type Response struct {
	Schema             string `json:"schema"`
	RequestHashHex     string `json:"request_hash_hex"`
	ContractAdminKeyID string `json:"contract_admin_key_id"`
	SignatureHex       string `json:"signature_hex"`
}

// NewRequest constructs and hashes one canonical ceremony request envelope.
func NewRequest(payload RequestPayload) (Request, error) {
	hash, err := RequestHash(payload)
	if err != nil {
		return Request{}, err
	}
	request := Request{Schema: RequestSchemaV1, Payload: payload, RequestHashHex: fmt.Sprintf("%x", hash[:])}
	if err := ValidateEnvelope(request); err != nil {
		return Request{}, err
	}
	return request, nil
}

// RequestHash computes the frozen length-prefixed request transcript.
func RequestHash(payload RequestPayload) ([sha512.Size256]byte, error) {
	var encoded []byte
	encoded = boundedmeta.AppendField(encoded, []byte(requestHashDomainV1))
	encoded = boundedmeta.AppendField(encoded, []byte(payload.Network))
	encoded = boundedmeta.AppendField(encoded, []byte(payload.GenesisHashHex))
	encoded = boundedmeta.AppendField(encoded, []byte(payload.CurrentAuthAddress))
	partial := payload.Partial
	encoded = boundedmeta.AppendField(encoded, []byte(partial.Schema))
	encoded = boundedmeta.AppendField(encoded, []byte(partial.Operation))
	encoded = boundedmeta.AppendUint32(encoded, uint32(len(partial.Transactions)))
	for _, value := range partial.Transactions {
		encoded = boundedmeta.AppendField(encoded, []byte(value))
	}
	encoded = boundedmeta.AppendUint32(encoded, uint32(len(partial.PartialSigned)))
	for _, value := range partial.PartialSigned {
		encoded = boundedmeta.AppendField(encoded, []byte(value))
	}
	encoded = boundedmeta.AppendUint32(encoded, uint32(partial.TargetIndex))
	metadata := partial.Authorization
	encoded = boundedmeta.AppendField(encoded, []byte(metadata.ContractAdminKeyID))
	encoded = boundedmeta.AppendField(encoded, []byte(metadata.PublicKeyHex))
	encoded = boundedmeta.AppendField(encoded, []byte(metadata.SpendingPublicKeyHex))
	encoded = boundedmeta.AppendField(encoded, []byte(metadata.ProgramBindingHex))
	encoded = boundedmeta.AppendField(encoded, []byte(metadata.TransactionID))
	encoded = boundedmeta.AppendField(encoded, []byte(metadata.MessageHex))
	encoded = boundedmeta.AppendUint32(encoded, uint32(metadata.BaseSignatureArgCount))
	encoded = boundedmeta.AppendUint32(encoded, uint32(metadata.AdminSignatureArgIndex))
	encoded = boundedmeta.AppendUint32(encoded, uint32(len(metadata.SpendEffects)))
	for _, effect := range metadata.SpendEffects {
		encoded = boundedmeta.AppendField(encoded, []byte(effect))
	}
	encoded = boundedmeta.AppendUint64(encoded, metadata.MaxFee)
	encoded = appendMutation(encoded, partial.Mutations)
	return sha512.Sum512_256(encoded), nil
}

// ValidateEnvelope validates the request schema and payload hash without
// interpreting or verifying the contained bounded authorization.
func ValidateEnvelope(request Request) error {
	if request.Schema != RequestSchemaV1 {
		return &Error{Code: ErrorUnsupportedRequestSchema, Err: fmt.Errorf("unsupported bounded-admin request schema %q", request.Schema)}
	}
	wantHash, err := RequestHash(request.Payload)
	if err != nil {
		return err
	}
	if request.RequestHashHex != fmt.Sprintf("%x", wantHash[:]) {
		return fmt.Errorf("bounded-admin request hash does not match payload")
	}
	return nil
}

// DecodeRequest reads one strict, bounded request object.
func DecodeRequest(reader io.Reader) (Request, error) {
	var request Request
	if err := decodeStrictBounded(reader, MaxRequestBytes, &request); err != nil {
		return Request{}, fmt.Errorf("decode bounded-admin request: %w", err)
	}
	return request, nil
}

// DecodeResponse reads one strict, bounded response object.
func DecodeResponse(reader io.Reader) (Response, error) {
	var response Response
	if err := decodeStrictBounded(reader, MaxResponseBytes, &response); err != nil {
		return Response{}, fmt.Errorf("decode bounded-admin response: %w", err)
	}
	return response, nil
}

func appendMutation(dst []byte, mutation *signerapi.MutationReport) []byte {
	if mutation == nil {
		return boundedmeta.AppendUint32(dst, 0)
	}
	dst = boundedmeta.AppendUint32(dst, 1)
	dst = boundedmeta.AppendUint32(dst, uint32(mutation.DummiesAdded))
	dst = appendBool(dst, mutation.GroupIDChanged)
	dst = boundedmeta.AppendUint32(dst, uint32(len(mutation.FeesModified)))
	for _, value := range mutation.FeesModified {
		dst = boundedmeta.AppendUint32(dst, uint32(value))
	}
	for _, value := range []int{mutation.TotalFeesDelta, mutation.OriginalCount, mutation.FinalCount, mutation.PassthroughCount, mutation.ForeignCount} {
		dst = boundedmeta.AppendUint32(dst, uint32(value))
	}
	return boundedmeta.AppendField(dst, []byte(mutation.Reason))
}

func appendBool(dst []byte, value bool) []byte {
	if value {
		return boundedmeta.AppendUint32(dst, 1)
	}
	return boundedmeta.AppendUint32(dst, 0)
}

func decodeStrictBounded(reader io.Reader, max int64, target any) error {
	limited := io.LimitReader(reader, max+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if len(data) == 0 || int64(len(data)) > max {
		return fmt.Errorf("JSON object size %d is invalid", len(data))
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}
