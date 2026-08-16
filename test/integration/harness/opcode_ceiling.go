// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package harness

import (
	"bytes"
	"context"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/lsigresource"
)

// OpcodeCeilingVector is one accepted maximum-input LogicSig execution. The
// transaction at LSigIndex must carry FinalProgram and exercise Path.
type OpcodeCeilingVector struct {
	Name       string
	Path       lsigresource.AuthorizationPath
	SignedTxns []types.SignedTxn
	LSigIndex  int
}

// OpcodeCeilingValidation describes one final compiled LogicSig program and
// the concrete executions used to validate its reviewed opcode declarations.
type OpcodeCeilingValidation struct {
	Name          string
	FinalProgram  []byte
	Profile       lsigresource.OpcodeProfile
	Bounded       bool
	RequiredPaths []lsigresource.AuthorizationPath
	Vectors       []OpcodeCeilingVector
}

// OpcodePathReport records the largest concrete cost observed for a path.
type OpcodePathReport struct {
	DeclaredCeiling uint64
	MaximumObserved uint64
	Vector          string
}

// OpcodeCeilingReport is the result of validating every supplied execution.
type OpcodeCeilingReport struct {
	ProgramBytes int
	Paths        map[lsigresource.AuthorizationPath]OpcodePathReport
}

// ValidateDeclaredOpcodeCeiling runs every accepted maximum-input vector
// through the supplied algod simulation endpoint and compares the reported
// LogicSig cost with the provider/template declaration. It validates one
// concrete execution per vector; it does not prove group-level feasibility or
// a maximum for arbitrary TEAL.
func ValidateDeclaredOpcodeCeiling(
	ctx context.Context,
	algodClient *algod.Client,
	input OpcodeCeilingValidation,
) (OpcodeCeilingReport, error) {
	report := OpcodeCeilingReport{
		ProgramBytes: len(input.FinalProgram),
		Paths:        make(map[lsigresource.AuthorizationPath]OpcodePathReport),
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if algodClient == nil {
		return report, fmt.Errorf("%s: algod client is not configured", validationName(input.Name))
	}
	if len(input.FinalProgram) == 0 {
		return report, fmt.Errorf("%s: final compiled LogicSig program is empty", validationName(input.Name))
	}
	if err := input.Profile.Validate(input.Bounded); err != nil {
		return report, fmt.Errorf("%s: invalid declared opcode profile: %w", validationName(input.Name), err)
	}
	if len(input.RequiredPaths) == 0 {
		return report, fmt.Errorf("%s: no required authorization paths declared", validationName(input.Name))
	}

	required := make(map[lsigresource.AuthorizationPath]struct{}, len(input.RequiredPaths))
	for _, path := range input.RequiredPaths {
		ceiling, err := opcodeCeilingForPath(input.Profile, path)
		if err != nil {
			return report, fmt.Errorf("%s: required %s path: %w", validationName(input.Name), opcodePathName(path), err)
		}
		if _, duplicate := required[path]; duplicate {
			return report, fmt.Errorf("%s: required %s path is duplicated", validationName(input.Name), opcodePathName(path))
		}
		required[path] = struct{}{}
		report.Paths[path] = OpcodePathReport{DeclaredCeiling: ceiling}
	}

	covered := make(map[lsigresource.AuthorizationPath]bool, len(required))
	for _, vector := range input.Vectors {
		vectorName := validationName(vector.Name)
		if _, ok := required[vector.Path]; !ok {
			return report, fmt.Errorf("%s: vector %s names undeclared %s path", validationName(input.Name), vectorName, opcodePathName(vector.Path))
		}
		if vector.LSigIndex < 0 || vector.LSigIndex >= len(vector.SignedTxns) {
			return report, fmt.Errorf("%s: vector %s LogicSig index %d is outside %d transactions", validationName(input.Name), vectorName, vector.LSigIndex, len(vector.SignedTxns))
		}
		if !bytes.Equal(vector.SignedTxns[vector.LSigIndex].Lsig.Logic, input.FinalProgram) {
			return report, fmt.Errorf("%s: vector %s does not carry the final compiled program at transaction %d", validationName(input.Name), vectorName, vector.LSigIndex)
		}

		response, err := algodClient.SimulateTransaction(models.SimulateRequest{
			TxnGroups:       []models.SimulateRequestTransactionGroup{{Txns: vector.SignedTxns}},
			ExecTraceConfig: models.SimulateTraceConfig{Enable: true},
		}).Do(ctx)
		if err != nil {
			return report, fmt.Errorf("%s: vector %s simulation request failed: %w", validationName(input.Name), vectorName, err)
		}
		if len(response.TxnGroups) != 1 {
			return report, fmt.Errorf("%s: vector %s simulation returned %d transaction groups, want 1", validationName(input.Name), vectorName, len(response.TxnGroups))
		}
		group := response.TxnGroups[0]
		if group.FailureMessage != "" {
			return report, fmt.Errorf("%s: vector %s simulation failed: %s", validationName(input.Name), vectorName, group.FailureMessage)
		}
		if vector.LSigIndex >= len(group.TxnResults) {
			return report, fmt.Errorf("%s: vector %s simulation returned %d transaction results; LogicSig index is %d", validationName(input.Name), vectorName, len(group.TxnResults), vector.LSigIndex)
		}
		consumed := group.TxnResults[vector.LSigIndex].LogicSigBudgetConsumed
		// The SDK field is an omitempty scalar, so an absent value and a
		// genuine zero are indistinguishable. Neither is usable evidence.
		if consumed == 0 {
			return report, fmt.Errorf("%s: vector %s simulation did not report LogicSig opcode consumption", validationName(input.Name), vectorName)
		}
		pathReport := report.Paths[vector.Path]
		if consumed > pathReport.DeclaredCeiling {
			return report, fmt.Errorf(
				"%s: vector %s on %s path consumed %d opcodes, exceeding declared ceiling %d",
				validationName(input.Name), vectorName, opcodePathName(vector.Path), consumed, pathReport.DeclaredCeiling,
			)
		}
		if consumed > pathReport.MaximumObserved {
			pathReport.MaximumObserved = consumed
			pathReport.Vector = vector.Name
			report.Paths[vector.Path] = pathReport
		}
		covered[vector.Path] = true
	}

	for path := range required {
		if !covered[path] {
			return report, fmt.Errorf("%s: required %s path has no maximum-input simulation vector", validationName(input.Name), opcodePathName(path))
		}
	}
	return report, nil
}

func opcodeCeilingForPath(profile lsigresource.OpcodeProfile, path lsigresource.AuthorizationPath) (uint64, error) {
	var ceiling uint64
	switch path {
	case lsigresource.PathDefault:
		ceiling = profile.Default
	case lsigresource.PathSpend:
		ceiling = profile.Spend
	case lsigresource.PathSpendingRekey:
		ceiling = profile.SpendingRekey
	case lsigresource.PathAdminRekey:
		ceiling = profile.AdminRekey
	default:
		return 0, fmt.Errorf("unknown authorization path %d", path)
	}
	if ceiling == 0 {
		return 0, fmt.Errorf("authorization path has no declared opcode ceiling")
	}
	return ceiling, nil
}

func opcodePathName(path lsigresource.AuthorizationPath) string {
	switch path {
	case lsigresource.PathDefault:
		return "default"
	case lsigresource.PathSpend:
		return "spend"
	case lsigresource.PathSpendingRekey:
		return "spending_rekey"
	case lsigresource.PathAdminRekey:
		return "admin_rekey"
	default:
		return fmt.Sprintf("unknown(%d)", path)
	}
}

func validationName(name string) string {
	if name == "" {
		return "LogicSig opcode validation"
	}
	return name
}
