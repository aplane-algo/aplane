// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"time"

	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/policyview"
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
	ViewPolicyViewer       // Read-only active policy snapshot viewer
	ViewPolicyPanel        // Legacy policy editor state; not exposed from apadmin
	ViewPolicyASAModal     // Legacy per-network transfer guard editor; not exposed from apadmin
	ViewTemplateLibrary    // Browse optional KeyType Library entries
	ViewTemplateInstallConfirm
	ViewTemplateInstalling
	ViewLibraryTemplateDetails // Full-screen view of a library entry's source (YAML or synthesized parameters)
	ViewError
)

type policyASAMode int

const (
	policyASAModeNetworks policyASAMode = iota
	policyASAModeLimits
	policyASAModeAddRef
	policyASAModeChoose
	policyASAModeAddAmount
	policyASAModeAlgoAmount
)

type policyViewerMode int

const (
	policyViewerModeOverview policyViewerMode = iota
	policyViewerModeGuardDetail
	policyViewerModeYAML
	policyViewerModeOverrides
)

type policyLoadState int

const (
	policyLoadIdle policyLoadState = iota
	policyLoadPath
	policyLoadReading
	policyLoadConfirm
	policyLoadReplacing
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
	connector       AdminConnector
	adminClient     *IPCClient
	transportLabel  string
	dataDir         string // APSIGNER_DATA directory

	// Signer state
	signerLocked      bool
	signerStatusKnown bool // true once we've received a status from apsigner
	keyCount          int

	// Local activity and idle locking state
	lastUserInputAt          time.Time
	lastActivityReportAt     time.Time
	activityReportPending    bool
	activityReportArmed      bool
	activityReportDueAt      time.Time
	activityReportGeneration uint64
	localIdleLockSent        bool
	localIdleLockRetryDelay  time.Duration
	localIdleLockRetryAt     time.Time
	localIdleGeneration      uint64
	localIdleDueAt           time.Time
	effectiveSessionTimeout  time.Duration

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

	// Backup confirmation / result state
	backupExportPassphrase  string
	backupConfirmPassphrase string
	backupConfirmError      string
	backupConfirmFocus      int // 0 = export passphrase, 1 = confirm passphrase
	backupArchivePath       string

	// Restore backup state
	restoreBackups             []BackupInfo
	restoreBackupsLoaded       bool
	selectedBackup             int
	restoreBackupScrollOffset  int
	restoreArchivePath         string
	restorePassphrase          []byte
	restorePassphraseError     string
	restorePreviewing          bool
	restorePreviewKeys         []RestoreKeyInfo
	restorePreviewErrors       []RestoreError
	restoreSelected            map[string]bool
	restoreSelectedKey         int
	restorePreviewScrollOffset int
	restorePreviewError        string
	restoreOverwrite           bool
	restoreDisplaySelectedKey  int
	restoreDisplayScrollOffset int
	restoreResult              RestoreBackupResultMessage

	// Generate display state (confirmation after generation)
	generatedAddress string
	generatedKeyType string

	// Import form state
	importKeyType       int // 0 = ed25519, 1 = falcon1024
	importMnemonicInput textarea.Model
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
	genericLSigParams      map[string]string // Parameter name -> value
	genericLSigParamOrder  []string          // Ordered list of parameter names for focus navigation
	genericLSigParamModes  map[string]int    // Parameter name -> selected input mode index
	genericLSigParamScroll map[string]int    // Parameter name -> multiline input scroll offset

	// Delete confirmation state
	deleteAddress      string // Address of key to delete
	deleteKeyType      string // Type of key to delete
	deleteConfirmFocus int    // 0 = cancel, 1 = delete

	// Token revocation confirmation state
	revokeTokenConfirmFocus int // 0 = cancel, 1 = revoke

	// Manual lock confirmation state
	manualLockConfirmFocus int       // 0 = cancel, 1 = lock
	manualLockReturnView   ViewState // View to restore when canceling or if lock fails
	manualLockPending      bool

	// Displace confirmation state
	displaceConfirmFocus int // 0 = cancel, 1 = proceed

	// Key details state (for viewing key metadata)
	detailsAddress                  string            // Address of key being viewed
	detailsKeyType                  string            // Key type
	detailsParameters               map[string]string // Parameters for generic LogicSigs
	detailsScrollOffset             int               // Scroll offset for parameter list
	detailsTEAL                     string            // TEAL source (for LogicSig keys)
	detailsTemplateProvenanceStatus string
	detailsTemplateProvenanceNote   string
	detailsSaveStatus               string // Status message after save

	// Admin panel state
	adminSettings    *AdminSettings // Current settings from server
	adminSelectedRow int            // Currently selected row in admin panel
	adminEditingRow  int            // Row being edited (-1 = none)
	adminEditValue   string         // Value being edited

	// Legacy policy panel state retained for compatibility handlers; apadmin
	// no longer exposes a policy editing entry point.
	policySettings                 *PolicySettings
	policySnapshot                 *PolicySnapshot
	policyView                     policyview.Model
	policyViewLoaded               bool
	policyViewLoading              bool
	policyViewError                string
	policyViewMode                 policyViewerMode
	policyViewReturnView           ViewState
	policyViewSelectedGuard        int
	policyViewSelectedGuardField   int
	policyViewGuardScrollOffset    int
	policyViewYAMLScrollOffset     int
	policyViewSelectedOverride     int
	policyViewOverrideScrollOffset int
	policyViewListPopupField       string
	policyViewListPopupScroll      int
	policyLoadState                policyLoadState
	policyLoadPath                 string
	policyLoadYAML                 string
	policyLoadBytes                int
	policyLoadError                string
	policyLoadStatus               string
	policySelectedRow              int
	policyEditingRow               int
	policyEditValue                string
	policyASAFocus                 int
	policyASANetworks              []string
	policyASAValues                map[string]string
	policyASAReviewValues          map[string]string
	policyASAMetadata              map[string]map[uint64]ASAMetadataInfo
	policyAlgoValues               map[string]string
	policyAlgoReviewValues         map[string]string
	policyASAPending               bool
	policyASAPendingValues         map[string]string
	policyASAReviewPendingValues   map[string]string
	policyAlgoPendingValues        map[string]string
	policyAlgoReviewPendingValues  map[string]string
	policyASAMode                  policyASAMode
	policyASASelectedNet           string
	policyASAEntries               []policyASAEntry
	policyASAInput                 string
	policyASAReviewInput           string
	policyASADenyInput             string
	policyASAAmountField           int
	policyASAMatches               []ASAMetadataInfo
	policyASASelectedAsset         *ASAMetadataInfo

	// KeyType Library state
	libraryTemplates      []protocol.LibraryTemplateInfo
	selectedTemplate      int
	templateScrollOffset  int
	templateInstallFocus  int // 0 = cancel, 1 = confirm action
	templateInstallError  string
	templateInstallStatus string
	pendingTemplate       *protocol.LibraryTemplateInfo
	serverKeyTypes        []protocol.KeyTypeInfo

	// Library details viewer (YAML for YAML templates, synthesized parameter
	// listing for compiled providers).
	libraryDetailsKeyType       string
	libraryDetailsTemplateType  string
	libraryDetailsSourcePath    string
	libraryDetailsSourceSHA256  string
	libraryDetailsSourceModTime int64
	libraryDetailsContent       string
	libraryDetailsScrollOffset  int
	libraryDetailsLoading       bool
	libraryDetailsError         string
	libraryDetailsReturnView    ViewState

	// Error message
	lastError string

	// Blocking serious error popup.
	errorPopupTitle      string
	errorPopupMessage    string
	errorPopupReturnView ViewState

	// Warning message (shown in status bar)
	lastWarning           string
	lastWarningGeneration uint64

	// Template load warnings (collected during unlock)
	templateLoadWarnings []string

	// Screen dimensions
	width  int
	height int

	// standalone is true when apadmin is running directly in a terminal
	// rather than embedded inside apconsole. It enables the "Signer Admin"
	// header label and reserves a line of height for it.
	standalone bool

	// Quit flag
	quitting bool
}

// NewModel creates a new TUI model
func NewModel(connector AdminConnector, dataDir string) Model {
	return Model{
		viewState:           ViewUnlock,
		connectionState:     ConnectionConnecting,
		connector:           connector,
		transportLabel:      connector.Label(),
		dataDir:             dataDir,
		signerLocked:        true,
		passphraseMasked:    true,
		importMnemonicInput: newImportMnemonicInput(),
	}
}

// WithStandalone marks the model as running in a standalone terminal rather
// than embedded in apconsole. Enables the "Signer Admin" header label.
func (m Model) WithStandalone() Model {
	m.standalone = true
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
	UserAutoApprove   bool
	LockOnDisconnect  bool
	PassphraseTimeout string
	PassphraseMethod  string
	SSHEnabled        bool
	SSHPort           int
	SSHFingerprint    string
	SSHClients        int
	SignerPort        int
	TEALCompileNet    string
	Theme             string
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

// PolicySettings holds the policy panel settings received from the server.
type PolicySettings struct {
	RejectForeignRekey          bool
	RejectCloseRemainder        bool
	RejectAssetClose            bool
	RejectClawback              bool
	AlwaysReviewWarnings        bool
	AutoApproveSelfNoOpTransfer bool
	MaxFeeMicroAlgos            string
	ReviewAlgoPayments          map[string]string
	MaxAlgoPayments             map[string]string
	PolicyNetworks              []string
	ReviewASAAmounts            map[string]string
	MaxASAAmounts               map[string]string
	PolicyASAMetadata           map[string][]ASAMetadataInfo
	MaxASAAmountsMainnet        string
	MaxASAAmountsTestnet        string
	MaxASAAmountsBetanet        string
}

// PolicySettingsMsg is sent when policy settings are received.
type PolicySettingsMsg struct {
	Settings PolicySettings
}

// PolicySnapshot holds the active read-only signer policy snapshot received
// from the server.
type PolicySnapshot struct {
	Success      bool
	IdentityID   string
	PolicyYAML   string
	PolicySHA256 string
	Canonical    bool
	Code         string
	Error        string
}

// PolicySnapshotMsg is sent when a policy snapshot is received.
type PolicySnapshotMsg struct {
	Snapshot PolicySnapshot
}

type PolicyReplaceResultMsg struct {
	Snapshot PolicySnapshot
}

type PolicyLoadFileMsg struct {
	Path       string
	PolicyYAML string
	Bytes      int
	Error      error
}

// PolicySettingUpdatedMsg is sent when a policy setting update completes.
type PolicySettingUpdatedMsg struct {
	Success bool
	Key     string
	Value   string
	Error   string
}

type ASAMetadataResultsMsg struct {
	Network string
	Query   string
	Results []ASAMetadataInfo
	Error   string
}

type ASAMetadataResultMsg struct {
	Network string
	Asset   ASAMetadataInfo
	Error   string
}

// adminRefreshTickMsg triggers a periodic refresh of admin panel data.
type adminRefreshTickMsg struct{}

type clearWarningMsg struct {
	Generation uint64
}

type activityReportTickMsg struct {
	Generation uint64
	DueAt      time.Time
}

type localIdleTickMsg struct {
	Generation uint64
	DueAt      time.Time
}

type localIdleLockRetryTickMsg struct {
	DueAt time.Time
}

type adminActivitySendFailedMsg struct {
	Error error
}

type lockIdentitySendFailedMsg struct {
	Error error
}

// KeyDetailsMsg is sent when key details are retrieved
type KeyDetailsMsg struct {
	Success                  bool
	Address                  string
	KeyType                  string
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
