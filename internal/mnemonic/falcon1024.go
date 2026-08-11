// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package mnemonic

import (
	"crypto/rand"
	"fmt"
	"strings"
	"sync"

	algomnemonic "github.com/algorand/go-algorand-sdk/v2/mnemonic"
	securecrypto "github.com/aplane-algo/aplane/internal/crypto"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
)

// NativeFalconHandler encodes the 32-byte recovery entropy used by the
// protocol-native Falcon scheme as a standard 25-word Algorand mnemonic.
type NativeFalconHandler struct{}

func (*NativeFalconHandler) RoutingFamily() string { return nativefalcon.KeyType }

func (*NativeFalconHandler) GenerateMnemonic() (string, []byte, []byte, error) {
	entropy := make([]byte, nativefalcon.RecoveryEntropySize)
	if _, err := rand.Read(entropy); err != nil {
		return "", nil, nil, fmt.Errorf("generate native Falcon recovery entropy: %w", err)
	}
	words, err := algomnemonic.FromKey(entropy)
	if err != nil {
		securecrypto.ZeroBytes(entropy)
		return "", nil, nil, fmt.Errorf("encode native Falcon mnemonic: %w", err)
	}
	return words, append([]byte(nil), entropy...), entropy, nil
}

func (*NativeFalconHandler) SeedFromMnemonic(words []string, passphrase string) ([]byte, error) {
	if passphrase != "" {
		return nil, fmt.Errorf("native Falcon Algorand mnemonics do not support passphrases")
	}
	if len(words) != nativefalcon.MnemonicWordCount {
		return nil, fmt.Errorf("native Falcon requires exactly %d words, got %d", nativefalcon.MnemonicWordCount, len(words))
	}
	entropy, err := algomnemonic.ToKey(strings.Join(words, " "))
	if err != nil {
		return nil, fmt.Errorf("decode native Falcon mnemonic: %w", err)
	}
	return entropy, nil
}

func (*NativeFalconHandler) EntropyToMnemonic(entropy []byte) (string, error) {
	if len(entropy) != nativefalcon.RecoveryEntropySize {
		return "", fmt.Errorf("native Falcon recovery entropy length %d, want %d", len(entropy), nativefalcon.RecoveryEntropySize)
	}
	return algomnemonic.FromKey(entropy)
}

func (h *NativeFalconHandler) MnemonicToEntropy(words []string) ([]byte, error) {
	return h.SeedFromMnemonic(words, "")
}

func (*NativeFalconHandler) ValidateWordCount(wordCount int) error {
	if wordCount != nativefalcon.MnemonicWordCount {
		return fmt.Errorf("native Falcon requires exactly %d words, got %d", nativefalcon.MnemonicWordCount, wordCount)
	}
	return nil
}

func (*NativeFalconHandler) WordCount() int { return nativefalcon.MnemonicWordCount }

var registerNativeFalconHandlerOnce sync.Once

func RegisterNativeFalconHandler() {
	registerNativeFalconHandlerOnce.Do(func() { Register(&NativeFalconHandler{}) })
}
