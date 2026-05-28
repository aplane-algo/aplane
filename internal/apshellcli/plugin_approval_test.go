// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Developers

package apshellcli

import (
	"bytes"
	"testing"

	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
)

func TestReviewPluginTransactionsCancelsOnNegativeResponse(t *testing.T) {
	var out bytes.Buffer
	state := &REPLState{
		Out:         &out,
		AutoConfirm: false,
		LineReader: func() (string, error) {
			return "n", nil
		},
	}

	cancelled, err := reviewPluginTransactions(state, &jsonrpc.ExecuteResult{
		RequiresApproval: true,
		Transactions: []jsonrpc.TransactionIntent{
			{Type: "raw"},
		},
	})
	if err != nil {
		t.Fatalf("reviewPluginTransactions() error = %v", err)
	}
	if !cancelled {
		t.Fatal("reviewPluginTransactions() should cancel on negative response")
	}
	if bytes.Contains(out.Bytes(), []byte("Proceed with signing and submission?")) {
		t.Fatalf("output = %q, approval prompt should be handled by readline prompt, not printed output", out.String())
	}
}

func TestReviewPluginTransactionsSkipsPromptWhenAutoConfirm(t *testing.T) {
	var out bytes.Buffer
	state := &REPLState{
		Out:         &out,
		AutoConfirm: true,
	}

	cancelled, err := reviewPluginTransactions(state, &jsonrpc.ExecuteResult{
		RequiresApproval: true,
		Transactions: []jsonrpc.TransactionIntent{
			{Type: "raw"},
		},
	})
	if err != nil {
		t.Fatalf("reviewPluginTransactions() error = %v", err)
	}
	if cancelled {
		t.Fatal("reviewPluginTransactions() should not cancel with AutoConfirm")
	}
}

func TestReviewPluginTransactionsClearsReadlinePromptBeforeApproval(t *testing.T) {
	var out bytes.Buffer
	var prompts []string
	state := &REPLState{
		Out:         &out,
		AutoConfirm: false,
		SetPrompt: func(p string) {
			prompts = append(prompts, p)
		},
		LineReader: func() (string, error) {
			return "y", nil
		},
	}

	cancelled, err := reviewPluginTransactions(state, &jsonrpc.ExecuteResult{
		RequiresApproval: true,
		Transactions: []jsonrpc.TransactionIntent{
			{Type: "raw"},
		},
	})
	if err != nil {
		t.Fatalf("reviewPluginTransactions() error = %v", err)
	}
	if cancelled {
		t.Fatal("reviewPluginTransactions() should not cancel on affirmative response")
	}
	if len(prompts) < 2 {
		t.Fatalf("prompts = %#v, want temporary prompt and restore", prompts)
	}
	if prompts[0] != "Proceed with signing and submission? [y/N]: " {
		t.Fatalf("first prompt = %q, want approval prompt", prompts[0])
	}
	if prompts[len(prompts)-1] != "" {
		t.Fatalf("last prompt = %q, want test fixture restore to empty prompt", prompts[len(prompts)-1])
	}
}
