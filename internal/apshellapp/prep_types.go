// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/asa"
	"github.com/aplane-algo/aplane/internal/engine"
)

// SigningContextDetails is the app-owned signer context view.
type SigningContextDetails struct {
	Address           string
	SigningAddress    string
	KeyType           string
	SigSize           int
	IsLogicSig        bool
	AuthorizationKind algorithm.AuthorizationKind
	DisplayKeyType    string
}

// PreparedTxn is the app-owned prepared transaction summary plus its internal engine handle.
type PreparedTxn struct {
	SigningContext SigningContextDetails
	enginePrep     *engine.TransactionPrepResult
}

// PreparedAtomicGroup is the app-owned prepared atomic-group handle.
type PreparedAtomicGroup struct {
	enginePrep *engine.AtomicPrepResult
}

// PreparedTxnGroup is the app-owned prepared group handle.
type PreparedTxnGroup struct {
	engineGroup *engine.PreparedGroup
}

// PreparedMethodCall is the app-owned ABI method-call preparation summary.
type PreparedMethodCall struct {
	Prep            *PreparedTxn
	MethodSignature string
}

func preparedTxnFromEngine(prep *engine.TransactionPrepResult) *PreparedTxn {
	if prep == nil {
		return nil
	}
	return &PreparedTxn{
		SigningContext: signingContextDetailsFromEngine(prep.SigningContext),
		enginePrep:     prep,
	}
}

func preparedAtomicGroupFromEngine(prep *engine.AtomicPrepResult) *PreparedAtomicGroup {
	if prep == nil {
		return nil
	}
	return &PreparedAtomicGroup{enginePrep: prep}
}

func preparedMethodCallFromEngine(prepared *engine.PreparedMethodAppCall) *PreparedMethodCall {
	if prepared == nil {
		return nil
	}
	return &PreparedMethodCall{
		Prep:            preparedTxnFromEngine(prepared.Prep),
		MethodSignature: prepared.Method.Signature(),
	}
}

func prepareTxnGroup(preps ...*PreparedTxn) (*PreparedTxnGroup, error) {
	enginePreps := make([]*engine.TransactionPrepResult, len(preps))
	for i, prep := range preps {
		if prep == nil {
			enginePreps[i] = nil
			continue
		}
		enginePreps[i] = prep.enginePrep
	}
	group, err := engine.PrepareGroup(enginePreps...)
	if err != nil {
		return nil, err
	}
	return &PreparedTxnGroup{engineGroup: group}, nil
}

// BalanceCheckDetails is the app-owned transaction validation view.
type BalanceCheckDetails struct {
	SenderBalance    float64
	RequiredAmount   float64
	SufficientFunds  bool
	ReceiverOptedIn  bool
	NewAccount       bool
	BelowMinBalance  bool
	MinBalance       uint64
	RemainingBalance uint64
}

// RekeyCheckDetails is the app-owned rekey validation view.
type RekeyCheckDetails struct {
	TargetIsRekeyed bool
	TargetAuthAddr  string
	IsUnrekey       bool
}

// OptOutCheckDetails is the app-owned opt-out validation view.
type OptOutCheckDetails struct {
	AssetBalance      uint64
	IsOptedIn         bool
	CloseToOptedIn    bool
	NeedsCloseTo      bool
	UsingImplicitSelf bool
}

// CloseCheckDetails is the app-owned close-account validation view.
type CloseCheckDetails struct {
	Balance      uint64
	IsOnline     bool
	HasASAs      bool
	ASACount     int
	ASAIDs       []uint64
	CloseToValid bool
}

func balanceCheckDetailsFromEngine(check *engine.BalanceCheckResult) *BalanceCheckDetails {
	if check == nil {
		return nil
	}
	return &BalanceCheckDetails{
		SenderBalance:    check.SenderBalance,
		RequiredAmount:   check.RequiredAmount,
		SufficientFunds:  check.SufficientFunds,
		ReceiverOptedIn:  check.ReceiverOptedIn,
		NewAccount:       check.NewAccount,
		BelowMinBalance:  check.BelowMinBalance,
		MinBalance:       check.MinBalance,
		RemainingBalance: check.RemainingBalance,
	}
}

func balanceCheckDetailsListFromEngine(checks []engine.BalanceCheckResult) []BalanceCheckDetails {
	result := make([]BalanceCheckDetails, len(checks))
	for i := range checks {
		result[i] = *balanceCheckDetailsFromEngine(&checks[i])
	}
	return result
}

func rekeyCheckDetailsFromEngine(check *engine.RekeyCheckResult) *RekeyCheckDetails {
	if check == nil {
		return nil
	}
	return &RekeyCheckDetails{
		TargetIsRekeyed: check.TargetIsRekeyed,
		TargetAuthAddr:  check.TargetAuthAddr,
		IsUnrekey:       check.IsUnrekey,
	}
}

func optOutCheckDetailsFromEngine(check *engine.OptOutCheckResult) *OptOutCheckDetails {
	if check == nil {
		return nil
	}
	return &OptOutCheckDetails{
		AssetBalance:      check.AssetBalance,
		IsOptedIn:         check.IsOptedIn,
		CloseToOptedIn:    check.CloseToOptedIn,
		NeedsCloseTo:      check.NeedsCloseTo,
		UsingImplicitSelf: check.UsingImplicitSelf,
	}
}

func closeCheckDetailsFromEngine(check *engine.CloseAccountCheckResult) *CloseCheckDetails {
	if check == nil {
		return nil
	}
	return &CloseCheckDetails{
		Balance:      check.Balance,
		IsOnline:     check.IsOnline,
		HasASAs:      check.HasASAs,
		ASACount:     check.ASACount,
		ASAIDs:       append([]uint64(nil), check.ASAIDs...),
		CloseToValid: check.CloseToValid,
	}
}

// SendPlan describes the resolved execution plan for a send command.
type SendPlan struct {
	Mode          SendMode
	FromAddresses []string
	ToAddresses   []string
	Amount        asa.Amount
	Note          string
	Wait          bool
	Fee           uint64
	UseFlatFee    bool
	LsigArgs      map[string][]byte
}

// PreparedSendItem describes one prepared non-atomic send.
type PreparedSendItem struct {
	From         string
	To           string
	Prep         *PreparedTxn
	BalanceCheck *BalanceCheckDetails
}

// NonAtomicSendPlan describes prepared non-atomic send execution.
type NonAtomicSendPlan struct {
	Amount    asa.Amount
	Items     []PreparedSendItem
	FromCount int
	ToCount   int
}

// AtomicSendPlan describes prepared atomic send execution.
type AtomicSendPlan struct {
	Mode        SendMode
	Amount      asa.Amount
	Prep        *PreparedAtomicGroup
	Checks      []BalanceCheckDetails
	From        []string
	To          []string
	Wait        bool
	GroupParams engine.AtomicGroupParams
}
