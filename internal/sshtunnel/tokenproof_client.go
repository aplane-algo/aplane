// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"sync"

	"golang.org/x/crypto/ssh"
)

type tokenProofClientAuth struct {
	mu sync.Mutex

	identityID  string
	token       string
	hostHash    []byte
	clientNonce []byte
	round       int
	verified    bool
}

func newTokenProofClientAuth(identityID, token string) *tokenProofClientAuth {
	return &tokenProofClientAuth{identityID: identityID, token: token}
}

func (a *tokenProofClientAuth) captureHostKey(key ssh.PublicKey) error {
	hash, err := hashSSHHostKey(key)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.hostHash) != 0 && !bytes.Equal(a.hostHash, hash) {
		return fmt.Errorf("%w during authentication", ErrHostKeyMismatch)
	}
	a.hostHash = hash
	return nil
}

func (a *tokenProofClientAuth) challenge(name, instruction string, questions []string, echos []bool) ([]string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if name != tokenProofDomain || instruction != "" || len(questions) != 1 || len(echos) != 1 || echos[0] {
		return nil, fmt.Errorf("unexpected SSH token proof challenge shape")
	}
	if len(a.hostHash) != tokenProofHostHashSize {
		return nil, fmt.Errorf("SSH host key was not verified before token proof")
	}

	switch a.round {
	case 0:
		if err := parseClientNonceQuestion(questions[0]); err != nil {
			return nil, err
		}
		a.clientNonce = make([]byte, tokenProofNonceSize)
		if _, err := rand.Read(a.clientNonce); err != nil {
			return nil, fmt.Errorf("generate token proof client nonce: %w", err)
		}
		answer, err := marshalClientNonceAnswer(a.clientNonce)
		if err != nil {
			return nil, err
		}
		a.round = 1
		return []string{answer}, nil
	case 1:
		serverNonce, serverProof, err := parseServerProofQuestion(questions[0])
		if err != nil {
			return nil, err
		}
		transcript, err := encodeTokenProofTranscript(tokenProofTranscript{
			Identity:    a.identityID,
			HostKeyHash: a.hostHash,
			ClientNonce: a.clientNonce,
			ServerNonce: serverNonce,
		})
		if err != nil {
			return nil, err
		}
		expectedServerProof, err := computeTokenProof(a.token, tokenProofServerDomain, transcript)
		if err != nil {
			return nil, err
		}
		if !verifyTokenProof(expectedServerProof, serverProof) {
			return nil, fmt.Errorf("SSH server token proof is invalid")
		}
		clientProof, err := computeTokenProof(a.token, tokenProofClientDomain, transcript)
		if err != nil {
			return nil, err
		}
		answer, err := marshalClientProofAnswer(clientProof)
		if err != nil {
			return nil, err
		}
		a.round = 2
		a.verified = true
		return []string{answer}, nil
	default:
		return nil, fmt.Errorf("unexpected additional SSH token proof challenge")
	}
}

func (a *tokenProofClientAuth) serverVerified() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.verified && a.round == 2
}

func (a *tokenProofClientAuth) clear() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.hostHash {
		a.hostHash[i] = 0
	}
	for i := range a.clientNonce {
		a.clientNonce[i] = 0
	}
	a.hostHash = nil
	a.clientNonce = nil
	a.token = ""
}
