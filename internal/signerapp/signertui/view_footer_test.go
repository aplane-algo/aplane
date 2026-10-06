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
				keylist:   keyListState{keys: []KeyInfo{{Address: "ADDR", KeyType: "ed25519"}}},
			},
			footerWant: "g: Generate",
		},
		{
			name: "admin panel",
			model: Model{
				viewState: ViewAdminPanel,
				admin: adminPanelState{settings: &AdminSettings{
					PassphraseMethod: "none",
					Theme:            "auto",
				}},
			},
			footerWant: "k: KeyTypes",
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
		keylist:           keyListState{keys: []KeyInfo{{Address: "ADDR", KeyType: "ed25519"}}},
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
	for _, want := range []string{"g: Generate", "l: Lock", "q: Quit"} {
		if !strings.Contains(footerBlock, want) {
			t.Fatalf("wrapped footer block missing %q:\n%s", want, strings.Join(lines, "\n"))
		}
	}
}

func TestAdminTitleUsesCosignerNodeRole(t *testing.T) {
	if got := (Model{}).AdminTitle(); got != "Signer Admin" {
		t.Fatalf("default AdminTitle() = %q, want Signer Admin", got)
	}
	m := Model{initialNodeRole: "cosigner"}
	if got := m.AdminTitle(); got != "Cosigner Admin" {
		t.Fatalf("initial cosigner AdminTitle() = %q, want Cosigner Admin", got)
	}
	m = Model{admin: adminPanelState{settings: &AdminSettings{NodeRole: "cosigner"}}}
	if got := m.AdminTitle(); got != "Cosigner Admin" {
		t.Fatalf("cosigner AdminTitle() = %q, want Cosigner Admin", got)
	}
}

func TestStandaloneAdminHeaderShowsEndpointWithoutRESTPort(t *testing.T) {
	m := Model{
		width: 120,
		admin: adminPanelState{settings: &AdminSettings{
			NodeRole:             "cosigner",
			SSHEnabled:           true,
			SSHPort:              1127,
			SignerPort:           11270,
			EndpointAdvertiseURL: "ssh://cosigner.example.test:1127",
		}},
	}

	got := stripANSI(m.renderAdminHeader())
	for _, want := range []string{
		"Cosigner Admin",
		"Endpoint: ssh://cosigner.example.test:1127",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("renderAdminHeader() missing %q:\n%s", want, got)
		}
	}
	// The REST port is a loopback detail behind the endpoint, not something
	// a client needs; it stays in the settings panel only.
	if strings.Contains(got, "Port") {
		t.Fatalf("renderAdminHeader() shows a port:\n%s", got)
	}
}

func TestStandaloneAdminHeaderBuildsEndpointWhenAdvertiseURLEmpty(t *testing.T) {
	m := Model{
		width: 120,
		admin: adminPanelState{settings: &AdminSettings{
			NodeRole:         "signer",
			SSHEnabled:       true,
			SSHListenAddress: "192.0.2.10",
			SSHPort:          1127,
			SignerPort:       11270,
		}},
	}

	got := stripANSI(m.renderAdminHeader())
	for _, want := range []string{
		"Signer Admin",
		"Endpoint: ssh://192.0.2.10:1127",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("renderAdminHeader() missing %q:\n%s", want, got)
		}
	}
}

func TestStandaloneAdminHeaderDefaultsEndpointHostForOlderSettings(t *testing.T) {
	m := Model{
		width: 120,
		admin: adminPanelState{settings: &AdminSettings{
			NodeRole:   "signer",
			SSHEnabled: true,
			SSHPort:    1127,
			SignerPort: 11270,
		}},
	}

	got := stripANSI(m.renderAdminHeader())
	if !strings.Contains(got, "Endpoint: ssh://127.0.0.1:1127") {
		t.Fatalf("renderAdminHeader() missing default endpoint:\n%s", got)
	}
}

func TestStandaloneAdminHeaderUsesServerDerivedEndpointForWildcardBind(t *testing.T) {
	m := Model{
		width: 120,
		admin: adminPanelState{settings: &AdminSettings{
			NodeRole:           "signer",
			SSHEnabled:         true,
			SSHListenAddress:   "0.0.0.0",
			SSHPort:            64804,
			SignerPort:         11270,
			EndpointDisplayURL: "ssh://192.168.1.42:64804",
		}},
	}

	got := stripANSI(m.renderAdminHeader())
	if !strings.Contains(got, "Endpoint: ssh://192.168.1.42:64804") {
		t.Fatalf("renderAdminHeader() missing server-derived endpoint for wildcard bind:\n%s", got)
	}
	if strings.Contains(got, "ssh://0.0.0.0:64804") {
		t.Fatalf("renderAdminHeader() advertised wildcard bind address:\n%s", got)
	}
}

func TestStandaloneAdminHeaderUsesLoopbackEndpointForOlderWildcardSettings(t *testing.T) {
	m := Model{
		width: 120,
		admin: adminPanelState{settings: &AdminSettings{
			NodeRole:         "signer",
			SSHEnabled:       true,
			SSHListenAddress: "0.0.0.0",
			SSHPort:          64804,
			SignerPort:       11270,
		}},
	}

	got := stripANSI(m.renderAdminHeader())
	if !strings.Contains(got, "Endpoint: ssh://127.0.0.1:64804") {
		t.Fatalf("renderAdminHeader() missing loopback endpoint for wildcard bind:\n%s", got)
	}
	if strings.Contains(got, "ssh://0.0.0.0:64804") {
		t.Fatalf("renderAdminHeader() advertised wildcard bind address:\n%s", got)
	}
}

func TestStandaloneAdminHeaderStaysWithinWidth(t *testing.T) {
	m := Model{
		width: 58,
		admin: adminPanelState{settings: &AdminSettings{
			NodeRole:             "signer",
			SignerPort:           11270,
			EndpointAdvertiseURL: "ssh://very-long-signer-hostname.example.test:1127",
		}},
	}

	got := m.renderAdminHeader()
	if width := visibleWidth(got); width > m.width {
		t.Fatalf("renderAdminHeader() width = %d, want <= %d\n%s", width, m.width, stripANSI(got))
	}
	clean := stripANSI(got)
	if !strings.Contains(clean, "Signer Admin") || !strings.Contains(clean, "Endpoint:") {
		t.Fatalf("renderAdminHeader() missing role or endpoint:\n%s", clean)
	}
}

func renderedViewLines(rendered string) []string {
	return strings.Split(strings.TrimRight(stripANSI(rendered), "\n"), "\n")
}
