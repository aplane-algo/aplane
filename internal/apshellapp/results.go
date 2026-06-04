// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"github.com/aplane-algo/aplane/internal/appresult"
	"github.com/aplane-algo/aplane/internal/asa"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/signerapi"
)

// Warning is a structured user-visible warning emitted by application use-cases.
type Warning struct {
	Code    string
	Message string
}

func warningsFromTransactionWriteNotices(notices []engine.TransactionWriteNotice) []Warning {
	if len(notices) == 0 {
		return nil
	}
	warnings := make([]Warning, 0, len(notices))
	for _, notice := range notices {
		if notice.Error != "" {
			warnings = append(warnings, Warning{
				Code:    "transaction_json_write_failed",
				Message: "failed to write transaction JSON: " + notice.Error,
			})
			continue
		}
		if notice.Filename != "" {
			warnings = append(warnings, Warning{
				Code:    "transaction_json_written",
				Message: "Saved transaction to " + notice.Filename,
			})
		}
	}
	return warnings
}

// Summary is a short user-visible summary emitted by application use-cases.
type Summary struct {
	Message string
}

// StatusDetails is the app-owned status view returned from apshellapp.
type StatusDetails struct {
	Network          string
	IsConnected      bool
	ConnectionTarget string
	WriteMode        bool
	ASACacheCount    int
	AliasCacheCount  int
	SetCacheCount    int
	SignerCacheCount int
}

// AssetHolding describes one account asset balance.
type AssetHolding struct {
	AssetID   uint64
	Amount    uint64
	UnitName  string
	Decimals  uint64
	IsFrozen  bool
	IsOptedIn bool
}

// BalanceDetails is the app-owned balance view returned from apshellapp.
type BalanceDetails struct {
	Address     string
	Alias       string
	AlgoBalance uint64
	Assets      []AssetHolding
	AuthAddr    string
	MinBalance  uint64
}

// AccountSummary is the app-owned account listing item.
type AccountSummary struct {
	Address    string
	Alias      string
	Source     string
	IsSignable bool
	KeyType    string
}

// ParticipationDetails is the app-owned participation status view.
type ParticipationDetails struct {
	Address           string
	IsOnline          bool
	VoteKey           string
	SelectionKey      string
	StateProofKey     string
	VoteFirstValid    uint64
	VoteLastValid     uint64
	VoteKeyDilution   uint64
	IncentiveEligible bool
}

// AliasEntry is the app-owned alias listing item.
type AliasEntry struct {
	Name       string
	Address    string
	IsSignable bool
	KeyType    string
}

// AliasMutation is the app-owned alias upsert result.
type AliasMutation struct {
	Name       string
	Address    string
	WasUpdated bool
	OldAddress string
	IsSignable bool
	KeyType    string
}

func aliasEntryFromEngine(alias engine.AliasInfo) AliasEntry {
	return AliasEntry{
		Name:       alias.Name,
		Address:    alias.Address,
		IsSignable: alias.IsSignable,
		KeyType:    alias.KeyType,
	}
}

func aliasEntryListFromEngine(aliases []engine.AliasInfo) []AliasEntry {
	result := make([]AliasEntry, len(aliases))
	for i, alias := range aliases {
		result[i] = aliasEntryFromEngine(alias)
	}
	return result
}

func aliasMutationFromEngine(result *engine.AddAliasResult) *AliasMutation {
	if result == nil {
		return nil
	}
	return &AliasMutation{
		Name:       result.Name,
		Address:    result.Address,
		WasUpdated: result.WasUpdated,
		OldAddress: result.OldAddress,
		IsSignable: result.IsSignable,
		KeyType:    result.KeyType,
	}
}

// SetEntry is the app-owned set listing item.
type SetEntry struct {
	Name      string
	Addresses []string
	Count     int
}

// SetMutation is the app-owned set mutation result.
type SetMutation struct {
	Name       string
	Addresses  []string
	WasUpdated bool
	OldCount   int
}

func setEntryFromEngine(set engine.SetInfo) SetEntry {
	return SetEntry{
		Name:      set.Name,
		Addresses: append([]string(nil), set.Addresses...),
		Count:     set.Count,
	}
}

func setEntryListFromEngine(sets []engine.SetInfo) []SetEntry {
	result := make([]SetEntry, len(sets))
	for i, set := range sets {
		result[i] = setEntryFromEngine(set)
	}
	return result
}

func setMutationFromEngine(result *engine.AddSetResult) *SetMutation {
	if result == nil {
		return nil
	}
	return &SetMutation{
		Name:       result.Name,
		Addresses:  append([]string(nil), result.Addresses...),
		WasUpdated: result.WasUpdated,
		OldCount:   result.OldCount,
	}
}

// ASAInfoDetails is the app-owned ASA metadata view.
type ASAInfoDetails struct {
	AssetID       uint64
	UnitName      string
	Name          string
	Decimals      uint64
	Total         uint64
	Creator       string
	Manager       string
	Reserve       string
	Freeze        string
	Clawback      string
	DefaultFrozen bool
	URL           string
}

// RekeyEntry is the app-owned rekey listing item.
type RekeyEntry struct {
	Address     string
	AuthAddress string
}

func rekeyEntryFromEngine(rekey engine.RekeyInfo) RekeyEntry {
	return RekeyEntry{
		Address:     rekey.Address,
		AuthAddress: rekey.AuthAddress,
	}
}

func rekeyEntryListFromEngine(rekeys []engine.RekeyInfo) []RekeyEntry {
	result := make([]RekeyEntry, len(rekeys))
	for i, rekey := range rekeys {
		result[i] = rekeyEntryFromEngine(rekey)
	}
	return result
}

// AppStateSchemaDetails is the app-owned application state schema view.
type AppStateSchemaDetails struct {
	NumUint      uint64 `json:"num_uint"`
	NumByteSlice uint64 `json:"num_byte_slice"`
}

// AppStateValueDetails is the app-owned TEAL state value view.
type AppStateValueDetails struct {
	Type        string `json:"type"`
	Uint        uint64 `json:"uint,omitempty"`
	BytesBase64 string `json:"bytes_base64,omitempty"`
	BytesText   string `json:"bytes_text,omitempty"`
}

// AppStateEntryDetails is one app-owned global or local state entry.
type AppStateEntryDetails struct {
	KeyBase64 string               `json:"key_base64"`
	KeyText   string               `json:"key_text,omitempty"`
	Value     AppStateValueDetails `json:"value"`
}

// AppInfoDetails is the app-owned application metadata view.
type AppInfoDetails struct {
	AppID               uint64                `json:"app_id"`
	AppAddress          string                `json:"app_address"`
	Creator             string                `json:"creator,omitempty"`
	CreatedAtRound      uint64                `json:"created_at_round,omitempty"`
	Deleted             bool                  `json:"deleted,omitempty"`
	DeletedAtRound      uint64                `json:"deleted_at_round,omitempty"`
	Version             uint64                `json:"version,omitempty"`
	ExtraProgramPages   uint64                `json:"extra_program_pages,omitempty"`
	GlobalStateSchema   AppStateSchemaDetails `json:"global_state_schema"`
	LocalStateSchema    AppStateSchemaDetails `json:"local_state_schema"`
	ApprovalProgramSize int                   `json:"approval_program_size"`
	ApprovalProgramB64  string                `json:"approval_program_base64,omitempty"`
	ApprovalProgramHash string                `json:"approval_program_hash,omitempty"`
	ClearProgramSize    int                   `json:"clear_state_program_size"`
	ClearProgramB64     string                `json:"clear_state_program_base64,omitempty"`
	ClearProgramHash    string                `json:"clear_state_program_hash,omitempty"`
}

// AppGlobalStateDetails is the app-owned application global state view.
type AppGlobalStateDetails struct {
	AppID             uint64                 `json:"app_id"`
	Creator           string                 `json:"creator,omitempty"`
	GlobalState       []AppStateEntryDetails `json:"global_state"`
	GlobalStateSchema AppStateSchemaDetails  `json:"global_state_schema"`
	LocalStateSchema  AppStateSchemaDetails  `json:"local_state_schema"`
}

// AppLocalStateDetails is the app-owned local state view for one account.
type AppLocalStateDetails struct {
	AppID            uint64                 `json:"app_id"`
	Account          string                 `json:"account"`
	Round            uint64                 `json:"round"`
	Deleted          bool                   `json:"deleted,omitempty"`
	OptedInAtRound   uint64                 `json:"opted_in_at_round,omitempty"`
	ClosedOutAtRound uint64                 `json:"closed_out_at_round,omitempty"`
	LocalState       []AppStateEntryDetails `json:"local_state"`
	Schema           AppStateSchemaDetails  `json:"schema"`
}

// AppBoxDetails is the app-owned application box view.
type AppBoxDetails struct {
	AppID       uint64 `json:"app_id"`
	NameBase64  string `json:"name_base64"`
	NameText    string `json:"name_text,omitempty"`
	Round       uint64 `json:"round"`
	ValueBase64 string `json:"value_base64"`
	ValueText   string `json:"value_text,omitempty"`
}

// AppBoxNameDetails identifies one application box.
type AppBoxNameDetails struct {
	NameBase64 string `json:"name_base64"`
	NameText   string `json:"name_text,omitempty"`
}

// AppBoxesDetails lists application box names.
type AppBoxesDetails struct {
	AppID uint64              `json:"app_id"`
	Boxes []AppBoxNameDetails `json:"boxes"`
}

// SubmitSummary is the app-owned summary of a single submitted transaction.
type SubmitSummary struct {
	TxID      string
	Confirmed bool
	Output    string
	Warnings  []Warning
}

// GroupSubmitSummary is the app-owned summary of a submitted group.
type GroupSubmitSummary struct {
	TxIDs     []string
	Confirmed bool
	Output    string
	Warnings  []Warning
}

func newGroupSubmitSummary(txIDs []string, confirmed bool, output string, warnings []Warning) *GroupSubmitSummary {
	return &GroupSubmitSummary{
		TxIDs:     append([]string(nil), txIDs...),
		Confirmed: confirmed,
		Output:    output,
		Warnings:  append([]Warning(nil), warnings...),
	}
}

// CreatedAppDetails is the app-owned created-application identity view.
type CreatedAppDetails struct {
	AppID      uint64
	AppAddress string
}

func createdAppDetailsFromEngine(result *engine.AppDeployResult) *CreatedAppDetails {
	if result == nil {
		return nil
	}
	return &CreatedAppDetails{
		AppID:      result.AppID,
		AppAddress: result.AppAddress,
	}
}

// ConnectionDetails is the app-owned signer connection outcome.
type ConnectionDetails struct {
	Connected    bool
	Target       string
	Port         int
	KeyCount     int
	Locked       bool
	ErrorMessage string
}

func connectionDetailsFromEngine(result *engine.ConnectionResult) *ConnectionDetails {
	if result == nil {
		return nil
	}
	return &ConnectionDetails{
		Connected:    result.Connected,
		Target:       result.Target,
		Port:         result.Port,
		KeyCount:     result.KeyCount,
		Locked:       result.Locked,
		ErrorMessage: result.ErrorMessage,
	}
}

// SwitchNetworkResult describes the outcome of a network switch.
type SwitchNetworkResult struct {
	OldNetwork string
	NewNetwork string
	Warnings   []Warning
	Summary    Summary
}

// BalanceMode indicates how a balance request should be rendered.
type BalanceMode string

const (
	BalanceModeSingleFull  BalanceMode = "single_full"
	BalanceModeSingleAsset BalanceMode = "single_asset"
	BalanceModeMulti       BalanceMode = "multi"
)

// BalanceCommandResult describes the semantic outcome of a balance command.
type BalanceCommandResult struct {
	Mode           BalanceMode
	AssetRef       string
	AssetSpecified bool
	Single         *BalanceDetails
	Addresses      []string
}

// StatusCommandResult describes the semantic outcome of a status command.
type StatusCommandResult struct {
	Status          StatusDetails
	LogicSigTypes   []string
	Algorithms      []string
	TunnelConnected bool
}

// AccountsCommandResult describes the semantic outcome of an accounts command.
type AccountsCommandResult struct {
	Accounts []AccountSummary
}

// HoldersCommandResult describes the semantic outcome of a holders command.
type HoldersCommandResult struct {
	Addresses []string
	AssetRef  string
	Warnings  []Warning
}

// ParticipationCommandResult describes the semantic outcome of a participation command.
type ParticipationCommandResult struct {
	Participation ParticipationDetails
	IsRekeyed     bool
	AuthAddress   string
}

// IncentiveEligibilityResult describes whether keyreg should charge the incentive fee.
type IncentiveEligibilityResult struct {
	AlreadyEligible bool
	Requested       bool
	ChargeFee       bool
}

// SignersCommandResult describes the semantic outcome of a signers/keys refresh.
type SignersCommandResult struct {
	Keys appresult.Keys
}

// KeyTypesCommandResult describes the semantic outcome of a keytypes command.
type KeyTypesCommandResult struct {
	KeyTypes []signerapi.KeyTypeInfo
}

// PluginCommandSummary describes one discovered plugin for shell rendering.
type PluginCommandSummary struct {
	Name        string
	Version     string
	Description string
	Author      string
	Networks    []string
	Commands    []PluginExposedCommand
}

// PluginExposedCommand describes one command exposed by a plugin.
type PluginExposedCommand struct {
	Name        string
	Description string
	Usage       string
}

// PluginsCommandResult describes the semantic outcome of a plugins command.
type PluginsCommandResult struct {
	Mode     string
	Plugin   *PluginCommandSummary
	Plugins  []PluginCommandSummary
	Summary  Summary
	Warnings []Warning
}

// GenerateKeyCommandResult describes the semantic outcome of key generation.
type GenerateKeyCommandResult struct {
	KeyType string
	Address string
}

func generateKeyCommandResultFromEngine(result *engine.GenerateKeyResult) *GenerateKeyCommandResult {
	if result == nil {
		return nil
	}
	return &GenerateKeyCommandResult{
		KeyType: result.KeyType,
		Address: result.Address,
	}
}

// ValidateItemResult describes one validate attempt.
type ValidateItemResult struct {
	Address   string
	TxID      string
	Confirmed bool
	Output    string
	Error     string
	Warnings  []Warning
}

// ValidateCommandResult describes the semantic outcome of a validate command.
type ValidateCommandResult struct {
	Input        string
	IsSet        bool
	Items        []ValidateItemResult
	SuccessCount int
	FailureCount int
	SummaryLines []string
}

// SignFileCommandResult describes the semantic outcome of signing transactions
// loaded from a file.
type SignFileCommandResult struct {
	FilePath  string
	TxCount   int
	TxIDs     []string
	Confirmed bool
	Output    string
	Warnings  []Warning
}

// AliasCommandResult describes the semantic outcome of an alias command.
type AliasCommandResult struct {
	Mode     string
	Usage    []string
	Aliases  []AliasEntry
	Alias    *AliasEntry
	Added    *AliasMutation
	Removed  string
	Name     string
	Warnings []Warning
}

// SetsCommandResult describes the semantic outcome of a sets command.
type SetsCommandResult struct {
	Mode      string
	Usage     []string
	Sets      []SetEntry
	SetName   string
	Addresses []string
	Mutation  *SetMutation
	Count     int
}

// ASAInfoCommandResult describes the semantic outcome of an ASA info command.
type ASAInfoCommandResult struct {
	Info ASAInfoDetails
}

// ASACommandResult describes the semantic outcome of an asa cache command.
type ASACommandResult struct {
	Mode    string
	Network string
	ASAs    []ASAInfoDetails
	Info    *ASAInfoDetails
	AssetID uint64
	Count   int
}

// OptInCommandResult describes the semantic outcome of an ASA opt-in command.
type OptInCommandResult struct {
	Account        string
	Asset          asa.Metadata
	SigningKeyType string
	TxID           string
	Confirmed      bool
	Output         string
	Warnings       []Warning
}

// OptOutCommandResult describes the semantic outcome of an ASA opt-out command.
type OptOutCommandResult struct {
	Account        string
	CloseTo        string
	Asset          asa.Metadata
	AssetBalance   uint64
	SigningKeyType string
	TxID           string
	Confirmed      bool
	Output         string
	Warnings       []Warning
}

// KeyRegCommandResult describes the semantic outcome of a keyreg command.
type KeyRegCommandResult struct {
	Account        string
	Mode           string
	VoteFirst      uint64
	VoteLast       uint64
	SigningKeyType string
	TxID           string
	Confirmed      bool
	Output         string
	Warnings       []Warning
}

// RekeyListCommandResult describes the semantic outcome of listing rekeyed accounts.
type RekeyListCommandResult struct {
	Rekeys []RekeyEntry
}

// AuthRefreshCommandResult describes the outcome of refreshing one auth-cache entry.
type AuthRefreshCommandResult struct {
	Address     string
	AuthAddress string
	IsRekeyed   bool
}

// RekeyCommandResult describes the semantic outcome of a rekey or unrekey command.
type RekeyCommandResult struct {
	From               string
	To                 string
	CurrentAuthAddress string
	IsUnrekey          bool
	CanSignForTarget   bool
	TargetIsLsig       bool
	TxID               string
	Confirmed          bool
	Output             string
	RefreshWarning     string
	PreSubmitLines     []string
	ConfirmedLines     []string
	PendingLines       []string
	Warnings           []Warning
}

// CloseCommandResult describes the semantic outcome of a close command.
type CloseCommandResult struct {
	From           string
	CloseTo        string
	Balance        uint64
	SigningKeyType string
	TxID           string
	Confirmed      bool
	Output         string
	PreSubmitLines []string
	ConfirmedLines []string
	Warnings       []Warning
}

// SweepItemResult describes one source-account attempt in a sweep flow.
type SweepItemResult struct {
	From          string
	To            string
	Amount        asa.Amount
	SkippedReason string
	TxID          string
	Confirmed     bool
	Output        string
	Error         string
	Warnings      []Warning
}

// SweepCommandResult describes the semantic outcome of a sweep command.
type SweepCommandResult struct {
	Asset           asa.Metadata
	Leaving         asa.Amount
	FromAddresses   []string
	ToAddress       string
	UsedAllSignable bool
	ReceiverOptedIn bool
	Items           []SweepItemResult
	SuccessCount    int
	FailureCount    int
	LastTxID        string
	InfoLines       []string
	HeaderLine      string
	SummaryLines    []string
}

// ConnectResult describes the outcome of a signer connection attempt.
type ConnectResult struct {
	Target           string
	Port             int
	KeyCount         int
	Locked           bool
	AlreadyConnected bool
	RenderLines      []string
	Summary          Summary
	Warnings         []Warning
}

// DisconnectResult describes the outcome of a disconnect operation.
type DisconnectResult struct {
	WasConnected bool
	Summary      Summary
}

// RequestTokenResult describes the outcome of token enrollment.
type RequestTokenResult struct {
	TokenPath        string
	DisconnectedPrev bool
	RenderLines      []string
	Summary          Summary
}

// EndpointEntry describes one client-local signer endpoint profile.
type EndpointEntry struct {
	Alias                   string
	Role                    string
	URL                     string
	SignerPort              int
	LocalPort               int
	IdentityFile            string
	KnownHostsPath          string
	TokenFile               string
	TokenPresent            bool
	TokenError              string
	IsDefault               bool
	LocalAttestorPublicKeys []string
}

// EndpointsListResult describes the endpoint registry entries visible to apshell.
type EndpointsListResult struct {
	Endpoints []EndpointEntry
}

// EndpointShowResult describes one endpoint registry entry.
type EndpointShowResult struct {
	Endpoint EndpointEntry
}

// EndpointImportResult describes a public endpoint-envelope import.
type EndpointImportResult struct {
	Alias          string
	Role           string
	URL            string
	SignerPort     int
	LocalPort      int
	TokenFile      string
	DryRun         bool
	Created        bool
	Updated        bool
	DefaultChanged bool
	RenderLines    []string
}

// EndpointDefaultResult describes a default endpoint change.
type EndpointDefaultResult struct {
	Alias         string
	PreviousAlias string
	RenderLines   []string
}

// EndpointDeleteResult describes an endpoint deletion.
type EndpointDeleteResult struct {
	Alias       string
	RenderLines []string
}

// StartupConnectDecision describes what apshell should do at startup about signer connectivity.
type StartupConnectDecision struct {
	EndpointName  string
	HasToken      bool
	TokenPath     string
	HasSSHConfig  bool
	Host          string
	SSHPort       int
	SignerPort    int
	ShouldConnect bool
}

// CommandExecutionState exposes the shell-relevant runtime state needed by command dispatch.
type CommandExecutionState struct {
	Network       string
	IsConnected   bool
	IsTunnelBound bool
	WriteMode     bool
	Simulate      bool
}

// SigningContextResult describes the semantic outcome of signing-context resolution.
type SigningContextResult struct {
	SigningContext SigningContextDetails
	IsRekeyed      bool
	AuthAddress    string
}

// AppReadResult describes the structured result of an app read command.
type AppReadResult struct {
	Data any
}

// AppDeployResult describes the semantic outcome of an app deploy command.
type AppDeployResult struct {
	FromAddress    string
	SigningKeyType string
	Submitted      bool
	Output         string
	PreSubmitLines []string
	ConfirmedLines []string
	Structured     appresult.AppDeploy
	Warnings       []Warning
}

// AppCallRawResult describes the semantic outcome of a raw app call command.
type AppCallRawResult struct {
	FromAddress    string
	SigningKeyType string
	AppArgsCount   int
	AccountsCount  int
	AppsCount      int
	AssetsCount    int
	BoxesCount     int
	Note           string
	PayAmount      uint64
	Output         string
	PreSubmitLines []string
	ConfirmedLines []string
	Structured     appresult.AppCall
	Warnings       []Warning
}

// AppCallMethodResult describes the semantic outcome of an ABI/method app call command.
type AppCallMethodResult struct {
	FromAddress    string
	SigningKeyType string
	Method         string
	ArgsCount      int
	AccountsCount  int
	AppsCount      int
	AssetsCount    int
	BoxesCount     int
	Note           string
	PayAmount      uint64
	Output         string
	PreSubmitLines []string
	ConfirmedLines []string
	Structured     appresult.AppCall
	Warnings       []Warning
}

// SendMode indicates the execution shape for a send command.
type SendMode string

const (
	SendModeNonAtomic          SendMode = "non_atomic"
	SendModeAtomicToMultiple   SendMode = "atomic_to_multiple"
	SendModeAtomicFromMultiple SendMode = "atomic_from_multiple"
)

// SendItemResult describes the outcome of one non-atomic send transaction.
type SendItemResult struct {
	From           string
	To             string
	SigningKeyType string
	TxID           string
	Confirmed      bool
	Output         string
	Error          string
	Warnings       []Warning
}

// NonAtomicSendResult describes the outcome of a non-atomic send flow.
type NonAtomicSendResult struct {
	Amount       asa.Amount
	Items        []SendItemResult
	SuccessCount int
	FailureCount int
	LastError    string
	FromCount    int
	ToCount      int
}

// AtomicSendResult describes the outcome of an atomic send flow.
type AtomicSendResult struct {
	Mode            SendMode
	Amount          asa.Amount
	From            []string
	To              []string
	ValidationNotes []string
	TxIDs           []string
	Confirmed       bool
	Output          string
	Warnings        []Warning
}

// SendExecutionResult describes the full outcome of a send command execution.
// It is the command-family result returned to adapters like cmd/apshell after
// apshellapp has chosen the execution path.
type SendExecutionResult struct {
	Mode      SendMode
	Amount    asa.Amount
	Note      string
	Wait      bool
	From      []string
	To        []string
	NonAtomic *NonAtomicSendResult
	Atomic    *AtomicSendResult
}
