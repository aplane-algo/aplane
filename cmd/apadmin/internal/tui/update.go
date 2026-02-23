// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package tui

// Core update loop and message handling.
// View-specific handlers are in update_*.go files.

import (
	"fmt"
	"sort"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/keystore"
	falcon1024template "github.com/aplane-algo/aplane/lsig/falcon1024/v1/template"
	"github.com/aplane-algo/aplane/lsig/multitemplate"

	tea "github.com/charmbracelet/bubbletea"
)

// Update handles all TUI events and messages
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return m.handleKeyPress(msg)

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case ConnectedMsg:
		m.connectionState = ConnectionConnected
		// Start listening for messages - server will send auth_required first
		return m, WaitForMessageCmd()

	case AuthRequiredMsg:
		// Server requires authentication - show auth screen
		m.viewState = ViewAuth
		m.passphraseInput = ""
		m.passphraseError = ""
		return m, WaitForMessageCmd()

	case AuthResultMsg:
		m.loggingIn = false
		if msg.Success {
			// Authentication successful - load runtime templates using master key
			if m.passphraseInput != "" && m.dataDir != "" {
				m.loadRuntimeTemplates([]byte(m.passphraseInput))
				m.setTemplateWarning()
			}
			// Server will send signer status next
			m.passphraseError = ""
			m.passphraseInput = ""
		} else {
			// Authentication failed - show error and stay on auth screen
			m.passphraseError = msg.Error
			if m.passphraseError == "" {
				m.passphraseError = "Authentication failed"
			}
		}
		return m, WaitForMessageCmd()

	case DisconnectedMsg:
		m.connectionState = ConnectionDisconnected
		if msg.Error != nil {
			m.lastError = msg.Error.Error()
		}
		return m, nil

	case SignerStatusMsg:
		m.signerLocked = msg.Locked
		m.keyCount = msg.KeyCount
		if msg.Locked {
			// Signer locked (e.g., inactivity timeout) — show unlock screen
			// immediately regardless of current view. Any in-progress operation
			// would fail anyway since the master key has been zeroed.
			m.viewState = ViewUnlock
			m.passphraseInput = ""
			m.passphraseError = ""
		} else {
			m.viewState = ViewKeyList
			// If signer is already unlocked, request key list
			return m, tea.Batch(WaitForMessageCmd(), SendListKeysCmd())
		}
		// Continue listening for messages
		return m, WaitForMessageCmd()

	case UnlockResultMsg:
		m.loggingIn = false
		if msg.Success {
			// Load runtime templates using master key
			if m.passphraseInput != "" && m.dataDir != "" {
				m.loadRuntimeTemplates([]byte(m.passphraseInput))
				m.setTemplateWarning()
			}
			m.signerLocked = false
			m.keyCount = msg.KeyCount
			m.viewState = ViewKeyList
			m.passphraseError = ""
			m.passphraseInput = ""
			// Request the key list after unlocking
			return m, tea.Batch(WaitForMessageCmd(), SendListKeysCmd())
		} else {
			m.passphraseError = msg.Error
		}
		// Continue listening for messages
		return m, WaitForMessageCmd()

	case SignRequestReceivedMsg:
		m.pendingSign = &msg.Request
		m.pendingSignFocus = 0 // Default to approve button
		m.viewState = ViewSigningPopup
		// Initialize scrollable viewport for the description
		m.initSigningViewport(msg.Request.Description)
		// Continue listening for messages
		return m, WaitForMessageCmd()

	case TokenProvisioningRequestReceivedMsg:
		m.pendingTokenRequest = &msg.Request
		m.pendingTokenRequestFocus = 0 // Default to approve button
		m.viewState = ViewTokenProvisioningPopup
		// Continue listening for messages
		return m, WaitForMessageCmd()

	case KeysListMsg:
		// Sort keys alphabetically by address
		sort.Slice(msg.Keys, func(i, j int) bool {
			return msg.Keys[i].Address < msg.Keys[j].Address
		})
		m.keys = msg.Keys
		m.keyCount = len(msg.Keys)
		// Ensure selectedKey and scrollOffset are within bounds
		if m.selectedKey >= len(m.keys) {
			m.selectedKey = len(m.keys) - 1
			if m.selectedKey < 0 {
				m.selectedKey = 0
			}
		}
		if m.scrollOffset > m.selectedKey {
			m.scrollOffset = m.selectedKey
		}
		// Continue listening for messages
		return m, WaitForMessageCmd()

	case ErrorMsg:
		m.lastError = msg.Error.Error()
		// Continue listening for messages
		return m, WaitForMessageCmd()

	case KeysChangedMsg:
		// Server notified us that keys changed - request updated list
		return m, tea.Batch(WaitForMessageCmd(), SendListKeysCmd())

	case ReconnectingMsg:
		m.connectionState = ConnectionConnecting
		// Continue listening for messages
		return m, WaitForMessageCmd()

	case GenerateResultMsg:
		if msg.Success {
			m.lastError = ""
			// Store generated key info for display
			m.generatedAddress = msg.Address
			m.generatedKeyType = msg.KeyType
			// Hold mnemonic so the user can view it with (e) before dismissing
			m.exportedMnemonic = msg.Mnemonic
			m.exportedAddress = msg.Address
			m.exportedKeyType = msg.KeyType
			m.exportedWordCount = msg.WordCount
			m.exportedParameters = msg.Parameters
			m.viewState = ViewGenerateDisplay
			// Also refresh key list in background
			return m, tea.Batch(WaitForMessageCmd(), SendListKeysCmd())
		} else {
			m.generateError = msg.Error
			// Go back to params view for generic LogicSigs, otherwise form
			if m.genericLSigParams != nil {
				m.viewState = ViewGenerateParams
			} else {
				m.viewState = ViewGenerateForm
			}
		}
		return m, WaitForMessageCmd()

	case DeleteResultMsg:
		if msg.Success {
			m.lastError = ""
			// Clear delete state and return to key list
			m.deleteAddress = ""
			m.deleteKeyType = ""
			m.viewState = ViewKeyList
			// Request updated key list
			return m, tea.Batch(WaitForMessageCmd(), SendListKeysCmd())
		} else {
			m.lastError = msg.Error
			// Return to confirm dialog on error
			m.viewState = ViewDeleteConfirm
		}
		return m, WaitForMessageCmd()

	case ExportResultMsg:
		if msg.Success {
			m.lastError = ""
			m.exportedMnemonic = msg.Mnemonic
			m.exportedAddress = msg.Address
			m.exportedKeyType = msg.KeyType
			m.exportedWordCount = msg.WordCount
			m.exportedParameters = msg.Parameters
			// Clear confirmation state
			m.exportConfirmAddress = ""
			m.exportConfirmKeyType = ""
			m.exportConfirmPassphrase = ""
			m.exportConfirmError = ""
			m.viewState = ViewExportDisplay
		} else {
			// If we're on the confirm screen, show error there
			if m.viewState == ViewExportConfirm {
				m.exportConfirmError = msg.Error
			} else {
				m.lastError = msg.Error
			}
		}
		return m, WaitForMessageCmd()

	case ImportResultMsg:
		if msg.Success {
			m.lastError = ""
			m.importMnemonicInput = ""
			m.importError = ""
			// Store imported key info for display
			m.importedAddress = msg.Address
			m.importedKeyType = msg.KeyType
			m.viewState = ViewImportDisplay
			// Also refresh key list in background
			return m, tea.Batch(WaitForMessageCmd(), SendListKeysCmd())
		} else {
			m.importError = msg.Error
			// Return to the appropriate form to show the error
			if m.viewState == ViewImportParams || m.viewState == ViewImporting {
				m.viewState = ViewImportParams
			}
		}
		return m, WaitForMessageCmd()

	case ClientExistsMsg:
		// Server says another client is already connected - show confirmation modal
		m.viewState = ViewDisplaceConfirm
		m.displaceConfirmFocus = 0 // Default to Cancel
		return m, WaitForMessageCmd()

	case DisplacedMsg:
		// We've been displaced by another apadmin client
		m.connectionState = ConnectionDisconnected
		m.lastError = msg.Reason
		// Do NOT issue WaitForMessageCmd - no reconnect
		return m, nil

	case KeyDetailsMsg:
		if msg.Success {
			m.detailsAddress = msg.Address
			m.detailsKeyType = msg.KeyType
			m.detailsParameters = msg.Parameters
			m.detailsTEAL = msg.DisplayTEAL
			m.detailsScrollOffset = 0 // Reset scroll on open
			m.detailsShowTEAL = false // Start with info view, not TEAL
			m.viewState = ViewKeyDetails
		} else {
			m.lastError = msg.Error
		}
		return m, WaitForMessageCmd()
	}

	return m, nil
}

// handleKeyPress handles keyboard input based on current view
func (m Model) handleKeyPress(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Global quit handling
	switch msg.String() {
	case "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	}

	// Global reconnect handling when disconnected
	if m.connectionState == ConnectionDisconnected && msg.String() == "c" {
		m.connectionState = ConnectionConnecting
		m.lastError = ""
		return m, ReconnectCmd(m.ipcPath)
	}

	// View-specific handling
	switch m.viewState {
	case ViewAuth:
		return m.handleAuthKeys(msg)
	case ViewUnlock:
		return m.handleUnlockKeys(msg)
	case ViewKeyList:
		return m.handleKeyListKeys(msg)
	case ViewSigningPopup:
		return m.handleSigningPopupKeys(msg)
	case ViewTokenProvisioningPopup:
		return m.handleTokenProvisioningPopupKeys(msg)
	case ViewExportConfirm:
		return m.handleExportConfirmKeys(msg)
	case ViewExportDisplay:
		return m.handleExportDisplayKeys(msg)
	case ViewGenerateDisplay:
		return m.handleGenerateDisplayKeys(msg)
	case ViewImportDisplay:
		return m.handleImportDisplayKeys(msg)
	case ViewImportForm:
		return m.handleImportFormKeys(msg)
	case ViewGenerateForm:
		return m.handleGenerateFormKeys(msg)
	case ViewGenerateParams:
		return m.handleGenerateParamsKeys(msg)
	case ViewImportParams:
		return m.handleImportParamsKeys(msg)
	case ViewDeleteConfirm:
		return m.handleDeleteConfirmKeys(msg)
	case ViewDisplaceConfirm:
		return m.handleDisplaceConfirmKeys(msg)
	case ViewKeyDetails:
		return m.handleKeyDetailsKeys(msg)
	}

	return m, nil
}

// loadRuntimeTemplates loads runtime templates from the keystore using the master key.
// This is needed to recognize generic LogicSig key types (e.g., hashlock-v3, timelock-v3)
// and Falcon-1024 DSA composition templates (e.g., falcon1024-timedlock-v1).
func (m *Model) loadRuntimeTemplates(passphrase []byte) {
	// Reset template warnings for this load attempt
	m.templateLoadWarnings = nil
	m.lastWarning = ""

	// Create a keystore to derive the master key using configured keystore path
	ks := keystore.NewFileKeyStore(auth.DefaultIdentityID)

	// Initialize master key (verifies passphrase and derives key from metadata salt)
	masterKey, err := ks.InitializeMasterKey(passphrase)
	if err != nil {
		// Can't load templates without master key - this is expected if keystore
		// metadata is missing or passphrase verification failed
		return
	}

	// Load generic LogicSig templates (multitemplate)
	if err := multitemplate.RegisterKeystoreTemplates(masterKey); err != nil {
		m.templateLoadWarnings = append(m.templateLoadWarnings,
			fmt.Sprintf("Failed to load generic templates: %v", err))
	}

	// Load Falcon-1024 DSA composition templates (falcon1024template)
	if err := falcon1024template.RegisterKeystoreTemplates(masterKey); err != nil {
		m.templateLoadWarnings = append(m.templateLoadWarnings,
			fmt.Sprintf("Failed to load falcon templates: %v", err))
	}
}

// setTemplateWarning sets lastWarning if any template load warnings were collected.
func (m *Model) setTemplateWarning() {
	if len(m.templateLoadWarnings) > 0 {
		m.lastWarning = fmt.Sprintf("%d template(s) failed to load", len(m.templateLoadWarnings))
	}
}
