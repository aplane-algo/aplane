// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package tui

import (
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/protocol"
)

// ViewState represents the current UI state
type ViewState int

const (
	ViewAuth ViewState = iota // IPC session authentication
	ViewUnlock
	ViewKeyList
	ViewKeyDetails // Shows key metadata (parameters for generic LogicSigs)
	ViewSigningPopup
	ViewTokenProvisioningPopup // Token provisioning approval popup
	ViewGenerateForm
	ViewGenerateParams  // Parameter input modal for generic LogicSigs
	ViewGenerating      // Loading state while generating
	ViewGenerateDisplay // Shows the generated mnemonic (once)
	ViewImportForm
	ViewImportParams    // Parameter input modal for DSA hybrids with params
	ViewImporting       // Loading state while importing
	ViewImportDisplay   // Shows import success confirmation
	ViewExportConfirm   // Confirm address before export
	ViewExportDisplay   // Shows the exported mnemonic
	ViewDeleteConfirm   // Delete confirmation dialog
	ViewDeleting        // Loading state while deleting
	ViewDisplaceConfirm // Confirmation modal for displacing existing client
	ViewError
)

// ConnectionState represents IPC connection status
type ConnectionState int

const (
	ConnectionDisconnected ConnectionState = iota
	ConnectionConnecting
	ConnectionConnected
)

// KeyInfo holds information about a key
type KeyInfo struct {
	Address  string
	KeyType  string // Full versioned type: "ed25519", "falcon1024-v1", etc.
	FilePath string
}

// PendingSignRequest holds a signing request waiting for approval
type PendingSignRequest struct {
	ID          string
	Address     string
	TxnSender   string
	Description string
	Timestamp   time.Time
	FirstValid  uint64
	LastValid   uint64
	Violations  []protocol.PolicyViolation
	Mode        string // "dsa" (default) or "attach" for generic lsigs
}

// PendingTokenRequest holds a token provisioning request waiting for approval
type PendingTokenRequest struct {
	ID             string
	IdentityID     string
	SSHFingerprint string
	RemoteAddr     string
	Timestamp      time.Time
}

// Model is the main TUI application model
type Model struct {
	// Current view state
	viewState ViewState

	// Connection state
	connectionState ConnectionState
	ipcPath         string
	dataDir         string // APSIGNER_DATA directory

	// Signer state
	signerLocked bool
	keyCount     int

	// Key list
	keys         []KeyInfo
	selectedKey  int
	scrollOffset int

	// Key list filter
	filterInput  string // Current filter text
	filterActive bool   // True when filter input is focused

	// Passphrase input (for unlock screen)
	passphraseInput  string
	passphraseMasked bool
	passphraseError  string
	loggingIn        bool // True while waiting for auth/unlock response

	// Pending signing request
	pendingSign         *PendingSignRequest
	pendingSignFocus    int            // 0 = approve, 1 = reject
	pendingSignViewport viewport.Model // Scrollable viewport for transaction description

	// Pending token provisioning request
	pendingTokenRequest      *PendingTokenRequest
	pendingTokenRequestFocus int // 0 = approve, 1 = reject

	// Export confirmation state
	exportConfirmAddress    string // Address of key to export
	exportConfirmKeyType    string // Key type being exported
	exportConfirmPassphrase string // User's passphrase input to confirm
	exportConfirmError      string // Error message if mismatch

	// Export display state
	exportedMnemonic   string
	exportedAddress    string
	exportedKeyType    string
	exportedWordCount  int
	exportedParameters map[string]string // Creation parameters for composeDSA types

	// Generate display state (confirmation after generation)
	generatedAddress string
	generatedKeyType string

	// Import form state
	importKeyType       int // 0 = ed25519, 1 = falcon1024
	importMnemonicInput string
	importError         string
	importFocus         int // 0 = key type, 1 = mnemonic input, 2 = submit button

	// Import display state (confirmation after import)
	importedAddress string
	importedKeyType string

	// Generate form state
	generateKeyType           int // Index into key type list (cryptographic types + generic lsigs)
	generateError             string
	generateFocus             int // 0 = key type, then dynamic params, then generate button
	generateParamScrollOffset int // Scroll offset for parameter list (used when params exceed visible area)

	// Generic LogicSig parameters (used when generateKeyType is a generic lsig)
	genericLSigParams     map[string]string // Parameter name -> value
	genericLSigParamOrder []string          // Ordered list of parameter names for focus navigation
	genericLSigParamModes map[string]int    // Parameter name -> selected input mode index

	// Delete confirmation state
	deleteAddress      string // Address of key to delete
	deleteKeyType      string // Type of key to delete
	deleteConfirmFocus int    // 0 = cancel, 1 = delete

	// Displace confirmation state
	displaceConfirmFocus int // 0 = cancel, 1 = proceed

	// Key details state (for viewing key metadata)
	detailsAddress      string            // Address of key being viewed
	detailsKeyType      string            // Key type
	detailsParameters   map[string]string // Parameters for generic LogicSigs
	detailsScrollOffset int               // Scroll offset for parameter list
	detailsTEAL         string            // TEAL source (for LogicSig keys)
	detailsShowTEAL     bool              // Toggle to show TEAL view
	detailsSaveStatus   string            // Status message after save

	// Error message
	lastError string

	// Warning message (shown in status bar)
	lastWarning string

	// Template load warnings (collected during unlock)
	templateLoadWarnings []string

	// Screen dimensions
	width  int
	height int

	// Quit flag
	quitting bool
}

// NewModel creates a new TUI model
func NewModel(ipcPath, dataDir string) Model {
	return Model{
		viewState:        ViewUnlock,
		connectionState:  ConnectionDisconnected,
		ipcPath:          ipcPath,
		dataDir:          dataDir,
		signerLocked:     true,
		passphraseMasked: true,
	}
}

// Init initializes the TUI model
func (m Model) Init() tea.Cmd {
	return tea.Batch(
		ConnectCmd(m.ipcPath, ""),
		tea.EnterAltScreen,
	)
}

// Tea messages for async operations

// ConnectedMsg is sent when IPC connection is established
type ConnectedMsg struct{}

// AuthRequiredMsg is sent when IPC server requires authentication
type AuthRequiredMsg struct{}

// AuthResultMsg is sent when authentication result is received
type AuthResultMsg struct {
	Success bool
	Error   string
}

// DisconnectedMsg is sent when IPC connection is lost
type DisconnectedMsg struct {
	Error error
}

// SignerStatusMsg is sent when signer status is received
type SignerStatusMsg struct {
	Locked   bool
	KeyCount int
}

// UnlockResultMsg is sent when unlock result is received
type UnlockResultMsg struct {
	Success  bool
	KeyCount int
	Error    string
}

// SignRequestReceivedMsg is sent when a signing request is received
type SignRequestReceivedMsg struct {
	Request PendingSignRequest
}

// TokenProvisioningRequestReceivedMsg is sent when a token provisioning request is received
type TokenProvisioningRequestReceivedMsg struct {
	Request PendingTokenRequest
}

// KeysListMsg is sent when key list is received
type KeysListMsg struct {
	Keys []KeyInfo
}

// KeysChangedMsg is sent when the server notifies that keys have changed
// This triggers a refresh of the key list
type KeysChangedMsg struct {
	KeyCount int
}

// ErrorMsg is sent when an error occurs
type ErrorMsg struct {
	Error error
}

// GenerateResultMsg is sent when key generation completes
type GenerateResultMsg struct {
	Success    bool
	Address    string
	KeyType    string // Full versioned type: "ed25519", "falcon1024-v1", etc.
	Mnemonic   string
	WordCount  int
	Parameters map[string]string
	Error      string
}

// DeleteResultMsg is sent when key deletion completes
type DeleteResultMsg struct {
	Success bool
	Error   string
}

// ExportResultMsg is sent when key export completes
type ExportResultMsg struct {
	Success    bool
	Address    string
	KeyType    string // Full versioned type: "ed25519", "falcon1024-v1", etc.
	Mnemonic   string
	WordCount  int
	Parameters map[string]string
	Error      string
}

// ImportResultMsg is sent when key import completes
type ImportResultMsg struct {
	Success bool
	Address string
	KeyType string
	Error   string
}

// ClientExistsMsg is sent when the server reports another client is already connected
type ClientExistsMsg struct{}

// DisplacedMsg is sent when this client has been displaced by another apadmin
type DisplacedMsg struct {
	Reason string
}

// KeyDetailsMsg is sent when key details are retrieved
type KeyDetailsMsg struct {
	Success     bool
	Address     string
	KeyType     string
	Parameters  map[string]string
	DisplayTEAL string
	Error       string
}
