// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func tokenProofTestClientConfig(t *testing.T, srv *Server, signer ssh.Signer, token string) *ssh.ClientConfig {
	t.Helper()
	authState := newTokenProofClientAuth(token)
	if err := authState.captureHostKey(srv.hostKey.PublicKey()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authState.clear)
	return &ssh.ClientConfig{
		User: productSSHUsername,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
			ssh.KeyboardInteractive(authState.challenge),
		},
		HostKeyCallback: ssh.FixedHostKey(srv.hostKey.PublicKey()),
	}
}

func TestHashSSHHostKey(t *testing.T) {
	publicKey, err := ssh.NewPublicKey(ed25519.PublicKey(bytes.Repeat([]byte{0x42}, ed25519.PublicKeySize)))
	if err != nil {
		t.Fatal(err)
	}
	got, err := hashSSHHostKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(publicKey.Marshal())
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("host key hash = %x, want %x", got, want)
	}
	if _, err := hashSSHHostKey(nil); err == nil {
		t.Fatal("hashSSHHostKey(nil) succeeded, want error")
	}
}

func TestTokenProofHostKeyChangeReturnsTypedMismatch(t *testing.T) {
	first, err := ssh.NewPublicKey(ed25519.PublicKey(bytes.Repeat([]byte{0x42}, ed25519.PublicKeySize)))
	if err != nil {
		t.Fatal(err)
	}
	second, err := ssh.NewPublicKey(ed25519.PublicKey(bytes.Repeat([]byte{0x43}, ed25519.PublicKeySize)))
	if err != nil {
		t.Fatal(err)
	}
	auth := newTokenProofClientAuth("token")
	if err := auth.captureHostKey(first); err != nil {
		t.Fatal(err)
	}
	if err := auth.captureHostKey(second); !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("captureHostKey() error = %v, want ErrHostKeyMismatch", err)
	}
}

func TestTokenProofContractVector(t *testing.T) {
	vector := loadTokenProofContractVector(t)
	hostKeyHash, err := decodeTokenProofBytes("host key hash", vector.HostKeyHash, tokenProofHostHashSize)
	if err != nil {
		t.Fatal(err)
	}
	clientNonce, err := decodeTokenProofBytes("client nonce", vector.ClientNonce, tokenProofNonceSize)
	if err != nil {
		t.Fatal(err)
	}
	serverNonce, err := decodeTokenProofBytes("server nonce", vector.ServerNonce, tokenProofNonceSize)
	if err != nil {
		t.Fatal(err)
	}

	transcript, err := encodeTokenProofTranscript(tokenProofTranscript{
		Username:    vector.Username,
		HostKeyHash: hostKeyHash,
		ClientNonce: clientNonce,
		ServerNonce: serverNonce,
	})
	if err != nil {
		t.Fatalf("encodeTokenProofTranscript() error = %v", err)
	}

	if got := hex.EncodeToString(transcript); got != vector.TranscriptHex {
		t.Fatalf("transcript = %q, want %q", got, vector.TranscriptHex)
	}

	serverProof, err := computeTokenProof(vector.Token, tokenProofServerDomain, transcript)
	if err != nil {
		t.Fatalf("computeTokenProof(server) error = %v", err)
	}
	clientProof, err := computeTokenProof(vector.Token, tokenProofClientDomain, transcript)
	if err != nil {
		t.Fatalf("computeTokenProof(client) error = %v", err)
	}

	if got := encodeTokenProofBytes(serverProof); got != vector.ServerProof {
		t.Errorf("server proof = %q, want %q", got, vector.ServerProof)
	}
	if got := encodeTokenProofBytes(clientProof); got != vector.ClientProof {
		t.Errorf("client proof = %q, want %q", got, vector.ClientProof)
	}
	if bytes.Equal(serverProof, clientProof) {
		t.Fatal("server and client proofs must be domain-separated")
	}

	clientNonceQuestion, err := marshalClientNonceQuestion()
	if err != nil {
		t.Fatal(err)
	}
	clientNonceAnswer, err := marshalClientNonceAnswer(clientNonce)
	if err != nil {
		t.Fatal(err)
	}
	serverProofQuestion, err := marshalServerProofQuestion(serverNonce, serverProof)
	if err != nil {
		t.Fatal(err)
	}
	clientProofAnswer, err := marshalClientProofAnswer(clientProof)
	if err != nil {
		t.Fatal(err)
	}
	if clientNonceQuestion != vector.ClientNonceQuestion ||
		clientNonceAnswer != vector.ClientNonceAnswer ||
		serverProofQuestion != vector.ServerProofQuestion ||
		clientProofAnswer != vector.ClientProofAnswer {
		t.Fatal("keyboard-interactive wire messages do not match the contract vector")
	}
}

type tokenProofContractVector struct {
	SchemaVersion       int    `json:"schema_version"`
	Protocol            string `json:"protocol"`
	Username            string `json:"username"`
	Token               string `json:"token"`
	HostKeyHash         string `json:"host_key_hash"`
	ClientNonce         string `json:"client_nonce"`
	ServerNonce         string `json:"server_nonce"`
	TranscriptHex       string `json:"transcript_hex"`
	ServerProof         string `json:"server_proof"`
	ClientProof         string `json:"client_proof"`
	ClientNonceQuestion string `json:"client_nonce_question"`
	ClientNonceAnswer   string `json:"client_nonce_answer"`
	ServerProofQuestion string `json:"server_proof_question"`
	ClientProofAnswer   string `json:"client_proof_answer"`
}

func loadTokenProofContractVector(t *testing.T) tokenProofContractVector {
	t.Helper()
	path := filepath.Join("..", "..", "test", "contracts", "sshtunnel", "token_proof_v1.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read token proof contract vector: %v", err)
	}
	var vector tokenProofContractVector
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&vector); err != nil {
		t.Fatalf("decode token proof contract vector: %v", err)
	}
	if vector.SchemaVersion != tokenProofVersion || vector.Protocol != tokenProofDomain || vector.Username != productSSHUsername {
		t.Fatalf("unexpected token proof contract vector version: %#v", vector)
	}
	return vector
}

func TestTokenProofMessageRoundTrip(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x44}, tokenProofNonceSize)
	proof := bytes.Repeat([]byte{0x55}, tokenProofMACSize)

	clientQuestion, err := marshalClientNonceQuestion()
	if err != nil {
		t.Fatal(err)
	}
	if err := parseClientNonceQuestion(clientQuestion); err != nil {
		t.Fatalf("parseClientNonceQuestion() error = %v", err)
	}

	clientAnswer, err := marshalClientNonceAnswer(nonce)
	if err != nil {
		t.Fatal(err)
	}
	gotNonce, err := parseClientNonceAnswer(clientAnswer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotNonce, nonce) {
		t.Fatalf("client nonce = %x, want %x", gotNonce, nonce)
	}

	serverQuestion, err := marshalServerProofQuestion(nonce, proof)
	if err != nil {
		t.Fatal(err)
	}
	gotServerNonce, gotServerProof, err := parseServerProofQuestion(serverQuestion)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotServerNonce, nonce) || !bytes.Equal(gotServerProof, proof) {
		t.Fatalf("server question decoded to nonce=%x proof=%x", gotServerNonce, gotServerProof)
	}

	clientProof, err := marshalClientProofAnswer(proof)
	if err != nil {
		t.Fatal(err)
	}
	gotClientProof, err := parseClientProofAnswer(clientProof)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotClientProof, proof) {
		t.Fatalf("client proof = %x, want %x", gotClientProof, proof)
	}
}

func TestTokenProofMessagesRejectInvalidShapes(t *testing.T) {
	validNonce := encodeTokenProofBytes(bytes.Repeat([]byte{1}, tokenProofNonceSize))
	validProof := encodeTokenProofBytes(bytes.Repeat([]byte{2}, tokenProofMACSize))

	tests := []struct {
		name  string
		value string
		parse func(string) error
	}{
		{
			name:  "duplicate field",
			value: `{"client_nonce":"` + validNonce + `","client_nonce":"` + validNonce + `"}`,
			parse: func(value string) error { _, err := parseClientNonceAnswer(value); return err },
		},
		{
			name:  "unknown field",
			value: `{"client_nonce":"` + validNonce + `","extra":true}`,
			parse: func(value string) error { _, err := parseClientNonceAnswer(value); return err },
		},
		{
			name:  "padded base64",
			value: `{"client_nonce":"` + validNonce + `="}`,
			parse: func(value string) error { _, err := parseClientNonceAnswer(value); return err },
		},
		{
			name:  "wrong nonce length",
			value: `{"client_nonce":"AQ"}`,
			parse: func(value string) error { _, err := parseClientNonceAnswer(value); return err },
		},
		{
			name:  "wrong version",
			value: `{"version":2,"step":"client_nonce"}`,
			parse: parseClientNonceQuestion,
		},
		{
			name:  "wrong step",
			value: `{"version":1,"step":"other"}`,
			parse: parseClientNonceQuestion,
		},
		{
			name:  "trailing data",
			value: `{"client_nonce":"` + validNonce + `"} {}`,
			parse: func(value string) error { _, err := parseClientNonceAnswer(value); return err },
		},
		{
			name:  "oversized",
			value: strings.Repeat("x", tokenProofMaxJSONLength+1),
			parse: func(value string) error { _, err := parseClientNonceAnswer(value); return err },
		},
		{
			name:  "wrong proof length",
			value: `{"version":1,"step":"server_proof","server_nonce":"` + validNonce + `","proof":"AQ"}`,
			parse: func(value string) error { _, _, err := parseServerProofQuestion(value); return err },
		},
		{
			name:  "empty proof",
			value: `{"client_proof":""}`,
			parse: func(value string) error { _, err := parseClientProofAnswer(value); return err },
		},
		{
			name:  "server question unknown field",
			value: `{"version":1,"step":"server_proof","server_nonce":"` + validNonce + `","proof":"` + validProof + `","token":"secret"}`,
			parse: func(value string) error { _, _, err := parseServerProofQuestion(value); return err },
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.parse(test.value); err == nil {
				t.Fatal("parse succeeded, want error")
			}
		})
	}
}

func TestEncodeTokenProofTranscriptRejectsInvalidFields(t *testing.T) {
	valid := tokenProofTranscript{
		Username:    productSSHUsername,
		HostKeyHash: bytes.Repeat([]byte{1}, tokenProofHostHashSize),
		ClientNonce: bytes.Repeat([]byte{2}, tokenProofNonceSize),
		ServerNonce: bytes.Repeat([]byte{3}, tokenProofNonceSize),
	}

	tests := []struct {
		name   string
		mutate func(*tokenProofTranscript)
	}{
		{name: "username", mutate: func(value *tokenProofTranscript) { value.Username = "other" }},
		{name: "host hash", mutate: func(value *tokenProofTranscript) { value.HostKeyHash = []byte{1} }},
		{name: "client nonce", mutate: func(value *tokenProofTranscript) { value.ClientNonce = []byte{1} }},
		{name: "server nonce", mutate: func(value *tokenProofTranscript) { value.ServerNonce = []byte{1} }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := valid
			test.mutate(&value)
			if _, err := encodeTokenProofTranscript(value); err == nil {
				t.Fatal("encodeTokenProofTranscript() succeeded, want error")
			}
		})
	}
}

func TestVerifyTokenProof(t *testing.T) {
	expected := bytes.Repeat([]byte{1}, tokenProofMACSize)
	if !verifyTokenProof(expected, bytes.Clone(expected)) {
		t.Fatal("matching proof rejected")
	}
	wrong := bytes.Clone(expected)
	wrong[len(wrong)-1] ^= 1
	if verifyTokenProof(expected, wrong) {
		t.Fatal("wrong proof accepted")
	}
	if verifyTokenProof(expected, expected[:len(expected)-1]) {
		t.Fatal("short proof accepted")
	}
}
