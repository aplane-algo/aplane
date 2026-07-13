// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
)

const (
	tokenProofVersion       = 1
	tokenProofDomain        = "aplane-ssh-token-proof-v1"
	tokenProofServerDomain  = "server"
	tokenProofClientDomain  = "client"
	tokenProofNonceSize     = 32
	tokenProofMACSize       = sha256.Size
	tokenProofHostHashSize  = sha256.Size
	tokenProofMaxIdentity   = 128
	tokenProofMaxJSONLength = 1024
)

const (
	tokenProofStepClientNonce = "client_nonce"
	tokenProofStepServerProof = "server_proof"
)

type tokenProofTranscript struct {
	Identity    string
	HostKeyHash []byte
	ClientNonce []byte
	ServerNonce []byte
}

type tokenProofClientNonceQuestion struct {
	Version int    `json:"version"`
	Step    string `json:"step"`
}

type tokenProofClientNonceAnswer struct {
	ClientNonce string `json:"client_nonce"`
}

type tokenProofServerProofQuestion struct {
	Version     int    `json:"version"`
	Step        string `json:"step"`
	ServerNonce string `json:"server_nonce"`
	Proof       string `json:"proof"`
}

type tokenProofClientProofAnswer struct {
	ClientProof string `json:"client_proof"`
}

func hashSSHHostKey(key ssh.PublicKey) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("SSH host key is nil")
	}
	hash := sha256.Sum256(key.Marshal())
	return hash[:], nil
}

func encodeTokenProofTranscript(transcript tokenProofTranscript) ([]byte, error) {
	if transcript.Identity == "" {
		return nil, fmt.Errorf("identity is empty")
	}
	if len(transcript.Identity) > tokenProofMaxIdentity {
		return nil, fmt.Errorf("identity exceeds %d bytes", tokenProofMaxIdentity)
	}
	if len(transcript.HostKeyHash) != tokenProofHostHashSize {
		return nil, fmt.Errorf("host key hash is %d bytes, want %d", len(transcript.HostKeyHash), tokenProofHostHashSize)
	}
	if len(transcript.ClientNonce) != tokenProofNonceSize {
		return nil, fmt.Errorf("client nonce is %d bytes, want %d", len(transcript.ClientNonce), tokenProofNonceSize)
	}
	if len(transcript.ServerNonce) != tokenProofNonceSize {
		return nil, fmt.Errorf("server nonce is %d bytes, want %d", len(transcript.ServerNonce), tokenProofNonceSize)
	}

	var encoded bytes.Buffer
	for _, field := range [][]byte{
		[]byte(tokenProofDomain),
		[]byte(transcript.Identity),
		transcript.HostKeyHash,
		transcript.ClientNonce,
		transcript.ServerNonce,
	} {
		if err := binary.Write(&encoded, binary.BigEndian, uint32(len(field))); err != nil {
			return nil, fmt.Errorf("encode token proof field length: %w", err)
		}
		if _, err := encoded.Write(field); err != nil {
			return nil, fmt.Errorf("encode token proof field: %w", err)
		}
	}
	return encoded.Bytes(), nil
}

func computeTokenProof(token, role string, transcript []byte) ([]byte, error) {
	if token == "" {
		return nil, fmt.Errorf("token is empty")
	}
	if role != tokenProofServerDomain && role != tokenProofClientDomain {
		return nil, fmt.Errorf("unsupported token proof role %q", role)
	}
	if len(transcript) == 0 {
		return nil, fmt.Errorf("token proof transcript is empty")
	}

	mac := hmac.New(sha256.New, []byte(token))
	writeTokenProofField(mac, []byte(role))
	writeTokenProofField(mac, transcript)
	return mac.Sum(nil), nil
}

func writeTokenProofField(w io.Writer, field []byte) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(field)))
	_, _ = w.Write(length[:])
	_, _ = w.Write(field)
}

func verifyTokenProof(expected, provided []byte) bool {
	return len(expected) == tokenProofMACSize && len(provided) == tokenProofMACSize && hmac.Equal(expected, provided)
}

func marshalClientNonceQuestion() (string, error) {
	return marshalTokenProofJSON(tokenProofClientNonceQuestion{
		Version: tokenProofVersion,
		Step:    tokenProofStepClientNonce,
	})
}

func parseClientNonceQuestion(value string) error {
	var question tokenProofClientNonceQuestion
	if err := unmarshalStrictTokenProofJSON(value, &question); err != nil {
		return err
	}
	if question.Version != tokenProofVersion || question.Step != tokenProofStepClientNonce {
		return fmt.Errorf("unexpected token proof client-nonce question")
	}
	return nil
}

func marshalClientNonceAnswer(nonce []byte) (string, error) {
	if len(nonce) != tokenProofNonceSize {
		return "", fmt.Errorf("client nonce is %d bytes, want %d", len(nonce), tokenProofNonceSize)
	}
	return marshalTokenProofJSON(tokenProofClientNonceAnswer{
		ClientNonce: encodeTokenProofBytes(nonce),
	})
}

func parseClientNonceAnswer(value string) ([]byte, error) {
	var answer tokenProofClientNonceAnswer
	if err := unmarshalStrictTokenProofJSON(value, &answer); err != nil {
		return nil, err
	}
	return decodeTokenProofBytes("client nonce", answer.ClientNonce, tokenProofNonceSize)
}

func marshalServerProofQuestion(serverNonce, proof []byte) (string, error) {
	if len(serverNonce) != tokenProofNonceSize {
		return "", fmt.Errorf("server nonce is %d bytes, want %d", len(serverNonce), tokenProofNonceSize)
	}
	if len(proof) != tokenProofMACSize {
		return "", fmt.Errorf("server proof is %d bytes, want %d", len(proof), tokenProofMACSize)
	}
	return marshalTokenProofJSON(tokenProofServerProofQuestion{
		Version:     tokenProofVersion,
		Step:        tokenProofStepServerProof,
		ServerNonce: encodeTokenProofBytes(serverNonce),
		Proof:       encodeTokenProofBytes(proof),
	})
}

func parseServerProofQuestion(value string) (serverNonce, proof []byte, err error) {
	var question tokenProofServerProofQuestion
	if err := unmarshalStrictTokenProofJSON(value, &question); err != nil {
		return nil, nil, err
	}
	if question.Version != tokenProofVersion || question.Step != tokenProofStepServerProof {
		return nil, nil, fmt.Errorf("unexpected token proof server-proof question")
	}
	serverNonce, err = decodeTokenProofBytes("server nonce", question.ServerNonce, tokenProofNonceSize)
	if err != nil {
		return nil, nil, err
	}
	proof, err = decodeTokenProofBytes("server proof", question.Proof, tokenProofMACSize)
	if err != nil {
		return nil, nil, err
	}
	return serverNonce, proof, nil
}

func marshalClientProofAnswer(proof []byte) (string, error) {
	if len(proof) != tokenProofMACSize {
		return "", fmt.Errorf("client proof is %d bytes, want %d", len(proof), tokenProofMACSize)
	}
	return marshalTokenProofJSON(tokenProofClientProofAnswer{
		ClientProof: encodeTokenProofBytes(proof),
	})
}

func parseClientProofAnswer(value string) ([]byte, error) {
	var answer tokenProofClientProofAnswer
	if err := unmarshalStrictTokenProofJSON(value, &answer); err != nil {
		return nil, err
	}
	return decodeTokenProofBytes("client proof", answer.ClientProof, tokenProofMACSize)
}

func marshalTokenProofJSON(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode token proof message: %w", err)
	}
	if len(encoded) > tokenProofMaxJSONLength {
		return "", fmt.Errorf("token proof message exceeds %d bytes", tokenProofMaxJSONLength)
	}
	return string(encoded), nil
}

func unmarshalStrictTokenProofJSON(value string, dst any) error {
	if value == "" {
		return fmt.Errorf("token proof message is empty")
	}
	if len(value) > tokenProofMaxJSONLength {
		return fmt.Errorf("token proof message exceeds %d bytes", tokenProofMaxJSONLength)
	}
	if err := rejectDuplicateJSONFields([]byte(value)); err != nil {
		return err
	}

	decoder := json.NewDecoder(bytes.NewBufferString(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("decode token proof message: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return err
	}
	return nil
}

func rejectDuplicateJSONFields(value []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(value))
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("decode token proof message: %w", err)
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return fmt.Errorf("token proof message must be a JSON object")
	}

	seen := make(map[string]struct{})
	for decoder.More() {
		fieldToken, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("decode token proof field: %w", err)
		}
		field, ok := fieldToken.(string)
		if !ok {
			return fmt.Errorf("token proof field name is not a string")
		}
		if _, exists := seen[field]; exists {
			return fmt.Errorf("duplicate token proof field %q", field)
		}
		seen[field] = struct{}{}

		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return fmt.Errorf("decode token proof field %q: %w", field, err)
		}
	}
	if _, err := decoder.Token(); err != nil {
		return fmt.Errorf("decode token proof message: %w", err)
	}
	return requireJSONEOF(decoder)
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("token proof message has trailing data")
		}
		return fmt.Errorf("decode token proof trailing data: %w", err)
	}
	return nil
}

func encodeTokenProofBytes(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func decodeTokenProofBytes(name, value string, size int) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("%s is empty", name)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", name, err)
	}
	if len(decoded) != size {
		return nil, fmt.Errorf("%s is %d bytes, want %d", name, len(decoded), size)
	}
	if encodeTokenProofBytes(decoded) != value {
		return nil, fmt.Errorf("%s is not canonical base64url", name)
	}
	return decoded, nil
}
