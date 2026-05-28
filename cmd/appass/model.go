// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"os"
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
)

// ViewState represents which screen the TUI is showing.
type ViewState int

const (
	ViewHome              ViewState = iota // Status + menu
	ViewPassphraseInput                    // First passphrase entry
	ViewConfirmPassphrase                  // Confirm passphrase
	ViewResult                             // Success/error after action
)

// menuItem represents a selectable menu entry.
type menuItem struct {
	label    string
	action   string // "set-passfile", "set-systemd-creds", "set-none", "quit"
	disabled bool
	note     string // e.g. "(no systemd service)"
	current  bool   // true if this is the currently active method
}

// Model is the Bubbletea model for appass.
type Model struct {
	viewState  ViewState
	dataDir    string
	identityID string
	width      int
	height     int
	quitting   bool

	// Status info (loaded on init and after actions)
	method  string       // "none", "passfile", "systemd-creds", "custom"
	isLocal bool         // true when no systemd service file exists
	isRoot  bool         // true when running as root
	svcInfo *serviceInfo // resolved service info

	// Menu
	menuItems    []menuItem
	selectedMenu int

	// Passphrase input
	passphraseInput  string
	passphraseMasked bool
	passphraseFirst  string // stored first entry for confirmation
	passphraseError  string

	// Current action being performed
	currentAction string // "set-passfile", "set-systemd-creds", "set-none"

	// Result
	resultMessage string
	resultError   string
}

// StatusLoadedMsg is sent when initial status loading completes.
type StatusLoadedMsg struct {
	method  string
	isLocal bool
	svcInfo *serviceInfo
}

// ActionDoneMsg is sent when an action completes (direct, no sudo).
type ActionDoneMsg struct {
	err     error
	warning string
}

// NewModel creates a new appass TUI model.
func NewModel(dataDir, identityID string) Model {
	return Model{
		viewState:        ViewHome,
		dataDir:          dataDir,
		identityID:       identityID,
		passphraseMasked: true,
		isRoot:           os.Getuid() == 0,
	}
}

// Init returns the initial command to load status.
func (m Model) Init() tea.Cmd {
	return loadStatusCmd(m.dataDir, m.identityID)
}

// loadStatusCmd loads the current identity-scoped auto-unlock configuration.
func loadStatusCmd(dataDir, identityID string) tea.Cmd {
	return func() tea.Msg {
		prodManaged, err := signerstartup.IsProductionManagedDataDir(dataDir)
		if err != nil {
			prodManaged = false
		}
		var svc *serviceInfo
		isLocal := !prodManaged
		if prodManaged {
			svc, isLocal = resolveServiceInfo()
		} else {
			svc = localServiceInfo()
		}

		method := "none"

		unlockCfg, err := identity.LoadUnlockConfig(dataDir, identityID)
		if err == nil && unlockCfg.HasPassphraseCommand() {
			method = detectMethod(unlockCfg.PassphraseCommandArgv)
		}

		return StatusLoadedMsg{
			method:  method,
			isLocal: isLocal,
			svcInfo: svc,
		}
	}
}

// buildMenu constructs a radio-style menu of passphrase handling modes.
func (m Model) buildMenu() []menuItem {
	var items []menuItem
	canMutate := m.isLocal || m.isRoot

	// Prompt (manual unlock)
	promptItem := menuItem{
		label:   "Prompt",
		action:  "set-none",
		current: m.method == "none",
	}
	if !canMutate {
		promptItem.disabled = true
		promptItem.note = "(run as root)"
	}
	items = append(items, promptItem)

	// Passfile
	passfileItem := menuItem{
		label:   "Passfile",
		action:  "set-passfile",
		current: m.method == "passfile",
	}
	if !canMutate {
		passfileItem.disabled = true
		passfileItem.note = "(run as root)"
	}
	items = append(items, passfileItem)

	// Systemd
	sysCreds := menuItem{
		label:   "Systemd",
		action:  "set-systemd-creds",
		current: m.method == "systemd-creds",
	}
	if m.isLocal {
		sysCreds.disabled = true
		sysCreds.note = "(no systemd service)"
	} else if !m.isRoot {
		sysCreds.disabled = true
		sysCreds.note = "(run as root)"
	}
	items = append(items, sysCreds)

	items = append(items, menuItem{
		label:  "Quit",
		action: "quit",
	})

	return items
}

// statusHelperInfo returns display info about the helper binary and associated file.
func (m Model) statusHelperInfo() (helperPath, helperStatus, filePath, fileLabel, fileStatus string) {
	var argv []string
	if unlockCfg, err := identity.LoadUnlockConfig(m.dataDir, m.identityID); err == nil && unlockCfg.HasPassphraseCommand() {
		argv = unlockCfg.PassphraseCommandArgv
	}

	if len(argv) > 0 {
		helperPath = argv[0]
		if info, err := os.Stat(helperPath); err != nil {
			helperStatus = "NOT FOUND"
		} else if info.Mode()&0111 == 0 {
			helperStatus = "exists but NOT executable"
		} else {
			helperStatus = "OK"
		}
	}

	switch m.method {
	case "passfile":
		filePath = filepath.Join(m.dataDir, "identities", m.identityID, "passphrase")
		if len(argv) > 1 {
			filePath = argv[1]
		}
		fileLabel = "Passphrase file"
		if _, err := os.Stat(filePath); err != nil {
			fileStatus = "NOT FOUND"
		} else {
			fileStatus = "OK"
		}

	case "systemd-creds":
		filePath = filepath.Join(m.dataDir, "identities", m.identityID, "passphrase.cred")
		if len(argv) > 1 {
			filePath = argv[1]
		}
		fileLabel = "Credential file"
		if _, err := os.Stat(filePath); err != nil {
			fileStatus = "NOT FOUND"
		} else {
			fileStatus = "OK"
		}
	}

	return
}
