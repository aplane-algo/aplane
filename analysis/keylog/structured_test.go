// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"slices"
	"strings"
	"testing"
)

func structuredFindingsIn(t *testing.T, body string) []string {
	t.Helper()
	src := `package sample

import (
	"context"
	"encoding/hex"
	"log/slog"
)

func f(ctx context.Context, l *slog.Logger, n int) {
` + body + `
}
`
	findings, err := structuredLogFindings("sample.go", []byte(src))
	if err != nil {
		t.Fatalf("structuredLogFindings() error = %v\n%s", err, src)
	}
	var names []string
	for _, f := range findings {
		names = append(names, strings.TrimPrefix(f.reason, "Potential key material in structured log argument: "))
	}
	return names
}

func TestStructuredLoggingFindsKeyMaterial(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"slog function", `slog.Info("details", "secret", privateKey)`, "privateKey"},
		{"debug mnemonic", `slog.Debug("details", "m", mnemonic)`, "mnemonic"},
		{"context form", `slog.WarnContext(ctx, "details", "s", seed)`, "seed"},
		{"logger method", `l.Warn("details", "secret", privateKey)`, "privateKey"},
		{"logger from a call", `logger().Error("details", "k", secretKey)`, "secretKey"},
		{"inherited attribute", `l = l.With("secret", privateKey)`, "privateKey"},
		{"package With", `_ = slog.With("secret", privKey)`, "privKey"},
		{"LogAttrs with Any", `l.LogAttrs(ctx, slog.LevelInfo, "x", slog.Any("k", privateKey))`, "privateKey"},
		{"Log", `l.Log(ctx, slog.LevelInfo, "x", "k", entropy)`, "entropy"},
		{"attribute built apart", `attr := slog.String("k", mnemonic); _ = attr`, "mnemonic"},
		{"group", `_ = slog.Group("g", "k", seed)`, "seed"},
		{"repository wrapper", `cache.Debug("details", "k", privateKey)`, "privateKey"},
		{"unqualified wrapper", `Debug("details", "k", privateKey)`, "privateKey"},
		{"field", `slog.Info("details", "k", account.PrivateKey)`, "PrivateKey"},
		{"conversion", `slog.Info("details", "k", string(seed))`, "seed"},
		{"encoding call", `slog.Info("details", "k", hex.EncodeToString(privateKey))`, "privateKey"},
		{"method on the value", `slog.Info("details", "k", privateKey.String())`, "privateKey"},
		{"multiline", "slog.Info(\"details\",\n\t\t\"secret\",\n\t\tprivateKey)", "privateKey"},
		{"wrapper with verb across lines", "logWarnf(\"key %x\",\n\t\tprivateKey)", "privateKey"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := structuredFindingsIn(t, tc.body); !slices.Equal(got, []string{tc.want}) {
				t.Fatalf("findings = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestStructuredLoggingIgnoresBenignCode(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"words only in the message", `slog.Info("private key rejected")`},
		{"words only in an attribute key", `slog.Info("x", "seed_count", n)`},
		{"public key", `slog.Info("x", "k", publicKey)`},
		{"metadata name", `slog.Info("x", "t", mnemonicType)`},
		{"fingerprint", `slog.Info("x", "f", keyFingerprint)`},
		{"selector judged by its last name", `slog.Info("x", "t", cfg.KeyTypeSeed)`},
		{"length of a secret", `slog.Info("x", "n", len(privateKey))`},
		{"called function name", `slog.Info("x", "n", countSeeds(n))`},
		{"error text", `slog.Warn("x", "error", err)`},
		{"not a logging call", `zero(privateKey)`},
		{"not a logging method", `hex.EncodeToString(privateKey)`},
		{"function literal argument", `run(func() { _ = privateKey })`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := structuredFindingsIn(t, tc.body); len(got) != 0 {
				t.Fatalf("findings = %q, want none", got)
			}
		})
	}
}

func TestStructuredLoggingFollowsImportAlias(t *testing.T) {
	src := `package sample

import logs "log/slog"

func f() { _ = logs.Int("k", seed) }
`
	findings, err := structuredLogFindings("sample.go", []byte(src))
	if err != nil {
		t.Fatalf("structuredLogFindings() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want one through the alias", findings)
	}
}

func TestStructuredLoggingReportsTheArgumentLine(t *testing.T) {
	src := "package sample\n\nimport \"log/slog\"\n\nfunc f() {\n\tslog.Info(\"x\",\n\t\t\"k\",\n\t\tprivateKey)\n}\n"
	findings, err := structuredLogFindings("sample.go", []byte(src))
	if err != nil {
		t.Fatalf("structuredLogFindings() error = %v", err)
	}
	if len(findings) != 1 || findings[0].line != 8 || !strings.Contains(findings[0].content, "privateKey") {
		t.Fatalf("findings = %+v, want line 8", findings)
	}
}

func TestStructuredLoggingRejectsUnparsableSource(t *testing.T) {
	if _, err := structuredLogFindings("bad.go", []byte("package sample\nfunc (")); err == nil {
		t.Fatal("expected a parse error, so an unread file is not reported clean")
	}
}
