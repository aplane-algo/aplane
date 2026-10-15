// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import "testing"

func TestSensitiveFormattedName(t *testing.T) {
	for _, tc := range []struct {
		line string
		want string
	}{
		// Words in the message must not vouch for the argument.
		{`log.Printf("private key: %x", privateKey)`, "privateKey"},
		{`return fmt.Errorf("secret material %x", secretKey)`, "secretKey"},
		{`log.Printf("mnemonic: %s", mnemonic)`, "mnemonic"},
		{`log.Printf("loaded %x (size %d)", account.PrivateKey, n)`, "account.PrivateKey"},
		{`fmt.Printf("public %v", seed)`, "seed"},
		{`log.Printf("%v", mnemonicWords)`, "mnemonicWords"},
		{`log.Printf("%s", strings.Join(mnemonics, " "))`, "mnemonics"},
		{"log.Printf(`raw %x`, entropy)", "entropy"},
		{`log.Printf("key: %x", privKey) // privKey is public here`, "privKey"},

		// Names about key material, not the material.
		{`log.Printf("public key %x", publicKey)`, ""},
		{`fmt.Errorf("unsupported mnemonic type %s", mnemonicType)`, ""},
		{`log.Printf("%d mnemonic words", len(mnemonicWords))`, ""},
		{`fmt.Errorf("handlers: %v", mnemonicHandlers)`, ""},
		{`logInfof("mnemonic handlers: %v", mnemonicFamilies)`, ""},
		{`log.Printf("%s", cfg.KeyTypeSeed)`, ""},
		{`log.Printf("%x", accountSeed)`, "accountSeed"},
		// A security term only inside the message, with no argument naming it.
		{`return fmt.Errorf("invalid private key: %w", err)`, ""},
		{`log.Printf("the seed phrase was rejected: %v", err)`, ""},
		// No content verb.
		{`log.Printf("generated %d keys", privateKeyCount)`, ""},
		{`zero(privateKey)`, ""},
		// Struct field assignment for encrypted storage.
		{`	PrivateKeyHex: fmt.Sprintf("%x", privateKey),`, ""},
	} {
		if got := sensitiveFormattedName(tc.line); got != tc.want {
			t.Errorf("sensitiveFormattedName(%q) = %q, want %q", tc.line, got, tc.want)
		}
	}
}

func TestSplitStringLiterals(t *testing.T) {
	literals, code := splitStringLiterals(`log.Printf("a \"q\" %x", k, 'x', "%v") // trailing privateKey`)
	if code != `log.Printf( , k, ,  ) ` || literals != `a "q" %x %v ` {
		t.Fatalf("got literals %q code %q", literals, code)
	}
}
