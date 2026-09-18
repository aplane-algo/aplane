// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"io"

	"golang.org/x/crypto/ssh"
)

// observeAuthSigner reports the key that actually signs authentication, including
// agent-selected keys. Preserve the signer's algorithm interfaces so observation
// cannot change SSH algorithm negotiation.
func observeAuthSigner(signer ssh.Signer, notify func(string)) ssh.Signer {
	if notify == nil {
		return signer
	}
	basic := &observedSigner{Signer: signer, notify: notify}
	algorithm, ok := signer.(ssh.AlgorithmSigner)
	if !ok {
		return basic
	}
	wrapped := &observedAlgorithmSigner{observedSigner: basic, algorithm: algorithm}
	if multi, ok := signer.(ssh.MultiAlgorithmSigner); ok {
		return &observedMultiAlgorithmSigner{observedAlgorithmSigner: wrapped, multi: multi}
	}
	return wrapped
}

type observedSigner struct {
	ssh.Signer
	notify func(string)
}

func (s *observedSigner) Sign(random io.Reader, data []byte) (*ssh.Signature, error) {
	signature, err := s.Signer.Sign(random, data)
	if err == nil {
		s.notify(ssh.FingerprintSHA256(s.PublicKey()))
	}
	return signature, err
}

type observedAlgorithmSigner struct {
	*observedSigner
	algorithm ssh.AlgorithmSigner
}

func (s *observedAlgorithmSigner) SignWithAlgorithm(random io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	signature, err := s.algorithm.SignWithAlgorithm(random, data, algorithm)
	if err == nil {
		s.notify(ssh.FingerprintSHA256(s.PublicKey()))
	}
	return signature, err
}

type observedMultiAlgorithmSigner struct {
	*observedAlgorithmSigner
	multi ssh.MultiAlgorithmSigner
}

func (s *observedMultiAlgorithmSigner) Algorithms() []string { return s.multi.Algorithms() }
