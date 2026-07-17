// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"time"

	"github.com/charmbracelet/bubbles/textarea"
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
	ViewTEALFullDisplay
	ViewSigningPopup
	ViewTokenProvisioningPopup // Token provisioning approval popup
	ViewGenerateForm
	ViewGenerateParams  // Parameter input modal for generic LogicSigs
	ViewGenerating      // Loading state while generating
	ViewGenerateDisplay // Shows generated key confirmation
	ViewImportForm
	ViewImportParams       // Parameter input modal for DSA hybrids with params
	ViewImporting          // Loading state while importing
	ViewImportDisplay      // Shows import success confirmation
	ViewBackupConfirm      // Confirm export passphrase and create managed backup
	ViewBackingUp          // Loading state while creating backup
	ViewBackupDisplay      // Shows created backup archive path
	ViewRestoreList        // Browse signer-managed backup archives
	ViewRestorePassphrase  // Enter export passphrase before previewing restore metadata
	ViewRestorePreview     // Select keys to restore from a backup archive
	ViewRestoring          // Loading state while restoring backup keys
	ViewRestoreDisplay     // Shows backup restore result
	ViewDeleteConfirm      // Delete confirmation dialog
	ViewDeleting           // Loading state while deleting
	ViewRevokeTokenConfirm // Token revocation confirmation dialog
	ViewLockConfirm        // Manual signer lock confirmation dialog
	ViewDisplaceConfirm    // Confirmation modal for displacing existing client
	ViewAdminPanel         // Admin control panel
	ViewPolicyEditor       // Guided online policy editor
	ViewTemplateLibrary    // Browse optional KeyType Library entries
	ViewTemplateInstallConfirm
	ViewTemplateInstalling
	ViewLibraryTemplateDetails // Full-screen view of a library entry's source (YAML or synthesized parameters)
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
	Address                  string
	KeyType                  string // Full versioned type: "ed25519", "aplane.falcon1024.v1", etc.
	FilePath                 string
	TemplateProvenanceStatus string
	TemplateProvenanceNote   string
}

type keyListTab int

const (
	keyListTabSigning keyListTab = iota
	keyListTabSentry
)

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

// activityState tracks local user activity for idle locking.
type activityState struct {
	lastInputAt        time.Time
	idleDisconnectSent bool
	idleGeneration     uint64
	idleDueAt          time.Time
	sessionTimeout     time.Duration
}

// authState is the unlock/auth passphrase prompt.
type authState struct {
	passphraseInput  string
	passphraseMasked bool
	passphraseError  string
	loggingIn        bool // true while waiting for auth/unlock response
}

// keyListState is the main key list with filter and tabs.
type keyListState struct {
	keys         []KeyInfo
	selectedKey  int
	scrollOffset int
	tab          keyListTab
	filterInput  string // current filter text
	filterActive bool   // true when filter input is focused
}

// signingState is the signing-approval popup.
type signingState struct {
	request  *PendingSignRequest
	focus    int            // 0 = approve, 1 = reject
	viewport viewport.Model // scrollable transaction description
}

// tokenApprovalState is the token-provisioning approval popup.
type tokenApprovalState struct {
	request *PendingTokenRequest
	focus   int // 0 = approve, 1 = reject
}

// backupState is the managed-backup confirm/result flow.
type backupState struct {
	exportPassphrase  string
	confirmPassphrase string
	confirmError      string
	confirmFocus      int // 0 = export passphrase, 1 = confirm passphrase
	archivePath       string
	// skippedKeys maps address -> reason for keys the all-keys backup
	// excluded because their payload failed canonical validation.
	skippedKeys map[string]string
}

// restoreState is the backup browse/preview/restore flow.
type restoreState struct {
	backups             []BackupInfo
	backupsLoaded       bool
	selectedBackup      int
	backupScrollOffset  int
	archivePath         string
	passphrase          []byte
	passphraseError     string
	previewing          bool
	previewKeys         []RestoreKeyInfo
	previewErrors       []RestoreError
	selected            map[string]bool
	selectedKey         int
	previewScrollOffset int
	previewError        string
	overwrite           bool
	displaySelectedKey  int
	displayScrollOffset int
	result              RestoreBackupResultMessage
}

// formsState covers the generate and import forms, their parameter modals,
// and the post-completion display screens.
type formsState struct {
	generatedAddress string
	generatedKeyType string

	importKeyType       int // 0 = ed25519, 1 = falcon1024
	importMnemonicInput textarea.Model
	importError         string
	importFocus         int // 0 = key type, 1 = mnemonic input, 2 = submit button
	importedAddress     string
	importedKeyType     string

	generateKeyType           int // index into key type list
	generateError             string
	generateFocus             int // 0 = key type, then dynamic params, then generate button
	generateParamScrollOffset int

	genericLSigParams      map[string]string
	genericLSigParamOrder  []string
	genericLSigParamModes  map[string]int
	genericLSigParamScroll map[string]int
}

// deleteConfirmState is the key-deletion confirmation dialog.
type deleteConfirmState struct {
	address string
	keyType string
	focus   int // 0 = cancel, 1 = delete
}

// adminPanelState is the admin control panel.
type adminPanelState struct {
	settings         *AdminSettings
	selectedRow      int
	editingRow       int // -1 = none
	editValue        string
	revokeTokenFocus int // 0 = cancel, 1 = revoke
}

// manualLockState is the manual signer-lock confirmation dialog.
type manualLockState struct {
	focus      int       // 0 = cancel, 1 = lock
	returnView ViewState // view to restore when canceling or if lock fails
	pending    bool
}

// keyDetailsState is the key metadata viewer.
type keyDetailsState struct {
	address                  string
	keyType                  string
	publicKeyHex             string
	parameters               map[string]string
	scrollOffset             int
	teal                     string
	templateProvenanceStatus string
	templateProvenanceNote   string
	saveStatus               string
}

// policyEditorState is the embedded guided policy editor.
type policyEditorState struct {
	editor     tea.Model
	loading    bool
	err        string
	target     string
	returnView ViewState
}

// libraryState is the KeyType Library browser, install confirm flow, and the
// full-screen details viewer.
type libraryState struct {
	templates        []protocol.LibraryTemplateInfo
	selectedTemplate int
	scrollOffset     int
	installFocus     int // 0 = cancel, 1 = confirm action
	installError     string
	installStatus    string
	pendingTemplate  *protocol.LibraryTemplateInfo

	detailsKeyType       string
	detailsTemplateType  string
	detailsSourcePath    string
	detailsSourceSHA256  string
	detailsSourceModTime int64
	detailsContent       string
	detailsScrollOffset  int
	detailsLoading       bool
	detailsError         string
	detailsReturnView    ViewState
}

// errorPopupState is the blocking serious-error popup.
type errorPopupState struct {
	title      string
	message    string
	returnView ViewState
}

// Model is the main TUI application model. Cross-view state lives directly on
// the struct; each view's state lives in its per-view sub-model.
type Model struct {
	// Current view state
	viewState ViewState

	// Connection state
	connectionState ConnectionState
	connector       AdminConnector
	adminClient     *IPCClient
	transportLabel  string
	dataDir         string // APSIGNER_DATA directory

	// Signer state
	signerLocked      bool
	signerStatusKnown bool // true once we've received a status from apsigner
	keyCount          int
	serverKeyTypes    []protocol.KeyTypeInfo

	// Per-view sub-models
	activity      activityState
	auth          authState
	keylist       keyListState
	signing       signingState
	tokenApproval tokenApprovalState
	backup        backupState
	restore       restoreState
	forms         formsState
	del           deleteConfirmState
	admin         adminPanelState
	manualLock    manualLockState
	details       keyDetailsState
	policyEd      policyEditorState
	library       libraryState
	errorPopup    errorPopupState

	// Displace confirmation state
	displaceConfirmFocus int // 0 = cancel, 1 = proceed

	// Error message
	lastError string

	// Warning message (shown in status bar)
	lastWarning           string
	lastWarningGeneration uint64

	// Screen dimensions
	width  int
	height int

	// Shared popup viewport state. Position is normalized to
	// panelScrollScale so it remains valid when the panel is resized.
	panelScrollView     ViewState
	panelScrollPosition int

	// standalone is true when apadmin is running directly in a terminal
	// rather than embedded inside apconsole. It enables the role-specific
	// admin header label and reserves a line of height for it.
	standalone bool

	// initialNodeRole is an early title/display hint loaded before the first
	// admin settings response arrives.
	initialNodeRole string

	// Quit flag
	quitting bool
}

// NewModel creates a new TUI model
func NewModel(connector AdminConnector, dataDir string) Model {
	return Model{
		viewState:       ViewUnlock,
		connectionState: ConnectionConnecting,
		connector:       connector,
		transportLabel:  connector.Label(),
		dataDir:         dataDir,
		signerLocked:    true,
		auth:            authState{passphraseMasked: true},
		forms:           formsState{importMnemonicInput: newImportMnemonicInput()},
	}
}

// WithStandalone marks the model as running in a standalone terminal rather
// than embedded in apconsole. Enables the role-specific admin header label.
func (m Model) WithStandalone() Model {
	m.standalone = true
	return m
}

// WithInitialNodeRole sets the role hint used before admin settings arrive.
func (m Model) WithInitialNodeRole(role string) Model {
	m.initialNodeRole = role
	return m
}

func newImportMnemonicInput() textarea.Model {
	input := textarea.New()
	input.Prompt = ""
	input.Placeholder = "enter recovery phrase words separated by spaces"
	input.ShowLineNumbers = false
	input.EndOfBufferCharacter = ' '
	input.SetWidth(62)
	input.SetHeight(4)
	input.MaxHeight = 4
	return input
}

// Init initializes the TUI model
func (m Model) Init() tea.Cmd {
	return tea.Batch(
		ConnectCmd(m.connector),
		tea.EnterAltScreen,
	)
}

// Tea messages for async operations

// ConnectedMsg is sent when IPC connection is established.
type ConnectedMsg struct {
	Client *IPCClient
}

// AuthRequiredMsg is sent when IPC server requires authentication
type AuthRequiredMsg struct{}

// AuthResultMsg is sent when authentication result is received
type AuthResultMsg struct {
	Success bool
	Code    string
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
	Code     string
	Error    string
}

// LockIdentityResultMsg is sent when an explicit identity lock request completes.
type LockIdentityResultMsg struct {
	Success bool
	Error   string
}

// SignRequestReceivedMsg is sent when a signing request is received
type SignRequestReceivedMsg struct {
	Request PendingSignRequest
}

// SignRequestCanceledMsg is sent when apsigner reports that a pending signing
// request is no longer actionable.
type SignRequestCanceledMsg struct {
	ID     string
	Reason string
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
	Success bool
	Address string
	KeyType string // Full versioned type: "ed25519", "aplane.falcon1024.v1", etc.
	Error   string
}

// DeleteResultMsg is sent when key deletion completes
type DeleteResultMsg struct {
	Success bool
	Error   string
}

// RevokeTokenResultMsg is sent when token revocation completes
type RevokeTokenResultMsg struct {
	Success bool
	Error   string
}

// BackupResultMsg is sent when signer-managed backup creation completes.
type BackupResultMsg struct {
	Success     bool
	ArchivePath string
	// SkippedKeys maps address -> reason for keys excluded from an all-keys
	// backup because their payload failed canonical validation.
	SkippedKeys map[string]string
	Error       string
}

// BackupsListMsg is sent when signer-managed backup archives are listed.
type BackupsListMsg struct {
	Backups []BackupInfo
	Error   string
}

// RestorePreviewMsg is sent when a backup archive preview completes.
type RestorePreviewMsg struct {
	ArchivePath string
	Keys        []RestoreKeyInfo
	Errors      []RestoreError
	Error       string
}

// RestoreBackupResultMsg is sent when backup restore completes.
type RestoreBackupResultMsg struct {
	ArchivePath string
	Success     bool
	Restored    []RestoreKeyInfo
	Skipped     []RestoreKeyInfo
	Errors      []RestoreError
	Warnings    []RestoreWarning
	KeyCount    int
	Error       string
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

// AdminSettings holds the admin panel settings received from the server
type AdminSettings struct {
	UserAutoApprove      bool
	LockOnDisconnect     bool
	PassphraseTimeout    string
	PassphraseMethod     string
	NodeRole             string
	SSHEnabled           bool
	SSHListenAddress     string
	SSHPort              int
	SSHFingerprint       string
	SSHClients           int
	SignerPort           int
	TEALCompileNet       string
	EndpointAdvertiseURL string
	EndpointDisplayURL   string
	Theme                string
}

// AdminSettingsMsg is sent when admin settings are received
type AdminSettingsMsg struct {
	Settings AdminSettings
}

// AdminSettingUpdatedMsg is sent when an admin setting update completes
type AdminSettingUpdatedMsg struct {
	Success bool
	Key     string
	Value   string
	Error   string
}

// adminRefreshTickMsg triggers a periodic refresh of admin panel data.
type adminRefreshTickMsg struct{}

type clearWarningMsg struct {
	Generation uint64
}

type localIdleTickMsg struct {
	Generation uint64
	DueAt      time.Time
}

type localIdleDisconnectedMsg struct {
	Reason string
}

type lockIdentitySendFailedMsg struct {
	Error error
}

// KeyDetailsMsg is sent when key details are retrieved
type KeyDetailsMsg struct {
	Success                  bool
	Address                  string
	KeyType                  string
	PublicKeyHex             string
	Parameters               map[string]string
	DisplayTEAL              string
	TemplateProvenanceStatus string
	TemplateProvenanceNote   string
	Error                    string
}

type LibraryTemplatesMsg struct {
	Templates []protocol.LibraryTemplateInfo
	Error     string
}

type InstallLibraryTemplateResultMsg struct {
	Success       bool
	KeyType       string
	TemplateType  string
	AlreadyExists bool
	Error         string
}

type ShowLibraryTemplateResultMsg struct {
	Success       bool
	KeyType       string
	TemplateType  string
	SourcePath    string
	SourceSHA256  string
	SourceModTime int64
	TemplateYAML  []byte
	Error         string
}

type ActivateKeyTypeResultMsg struct {
	Success       bool
	KeyType       string
	AlreadyExists bool
	Error         string
}

type DeactivateKeyTypeResultMsg struct {
	Success bool
	KeyType string
	Removed bool
	Error   string
}

type KeyTypesMsg struct {
	KeyTypes []protocol.KeyTypeInfo
	Error    string
}
