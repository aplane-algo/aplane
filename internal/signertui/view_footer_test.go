// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"strings"
	"testing"
)

func TestWindowFooterAndStatusArePinnedAcrossScreens(t *testing.T) {
	for _, tt := range []struct {
		name       string
		model      Model
		footerWant string
	}{
		{
			name: "key list",
			model: Model{
				viewState: ViewKeyList,
				keys:      []KeyInfo{{Address: "ADDR", KeyType: "ed25519"}},
			},
			footerWant: "g: Generate",
		},
		{
			name: "admin panel",
			model: Model{
				viewState: ViewAdminPanel,
				adminSettings: &AdminSettings{
					PassphraseMethod: "none",
					Theme:            "auto",
				},
			},
			footerWant: "p: Policy",
		},
		{
			name:       "generate form",
			model:      Model{viewState: ViewGenerateForm},
			footerWant: "t: Template",
		},
		{
			name:       "template library",
			model:      Model{viewState: ViewTemplateLibrary},
			footerWant: "Toggle availability",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := tt.model
			m.width = 88
			m.height = 22
			m.connectionState = ConnectionConnected
			m.signerStatusKnown = true

			lines := renderedViewLines(m.View())
			if got := len(lines); got != m.height {
				t.Fatalf("View() rendered %d lines, want %d:\n%s", got, m.height, strings.Join(lines, "\n"))
			}
			footerHeight := renderedBlockHeight(m.renderWindowFooter())
			footerBlock := strings.Join(lines[len(lines)-1-footerHeight:len(lines)-1], "\n")
			if !strings.Contains(footerBlock, tt.footerWant) {
				t.Fatalf("footer block missing %q:\n%s", tt.footerWant, strings.Join(lines, "\n"))
			}
			if !strings.Contains(lines[len(lines)-1], "Connected") {
				t.Fatalf("status line not pinned at bottom: %q\n%s", lines[len(lines)-1], strings.Join(lines, "\n"))
			}
		})
	}
}

func TestWindowFooterWrapsAbovePinnedStatus(t *testing.T) {
	m := Model{
		viewState:         ViewKeyList,
		width:             34,
		height:            18,
		connectionState:   ConnectionConnected,
		signerStatusKnown: true,
		keys:              []KeyInfo{{Address: "ADDR", KeyType: "ed25519"}},
	}

	lines := renderedViewLines(m.View())
	if got := len(lines); got != m.height {
		t.Fatalf("View() rendered %d lines, want %d:\n%s", got, m.height, strings.Join(lines, "\n"))
	}
	if !strings.Contains(lines[len(lines)-1], "Connected") {
		t.Fatalf("status line not pinned at bottom: %q\n%s", lines[len(lines)-1], strings.Join(lines, "\n"))
	}
	footerHeight := renderedBlockHeight(m.renderWindowFooter())
	footerBlock := strings.Join(lines[len(lines)-1-footerHeight:len(lines)-1], "\n")
	for _, want := range []string{"g: Generate", "p: Policy", "q: Quit"} {
		if !strings.Contains(footerBlock, want) {
			t.Fatalf("wrapped footer block missing %q:\n%s", want, strings.Join(lines, "\n"))
		}
	}
}

func TestAdminTitleUsesAttestorNodeRole(t *testing.T) {
	if got := (Model{}).AdminTitle(); got != "Signer Admin" {
		t.Fatalf("default AdminTitle() = %q, want Signer Admin", got)
	}
	m := Model{adminSettings: &AdminSettings{NodeRole: "attestor"}}
	if got := m.AdminTitle(); got != "Attestor Admin" {
		t.Fatalf("attestor AdminTitle() = %q, want Attestor Admin", got)
	}
}

func renderedViewLines(rendered string) []string {
	return strings.Split(strings.TrimRight(stripANSI(rendered), "\n"), "\n")
}
