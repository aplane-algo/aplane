// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package apboundedadminapp owns external bounded-admin workflows.
package apboundedadminapp

import (
	"context"
	"fmt"
	"io"

	"github.com/algorand/go-algorand-sdk/v2/types"

	boundedauthorization "github.com/aplane-algo/aplane/internal/boundedadmin/authorization"
	boundedprotocol "github.com/aplane-algo/aplane/internal/boundedadmin/protocol"
	"github.com/aplane-algo/aplane/internal/engine"
)

// Operation identifies the account mutation to perform.
type Operation string

const (
	OperationRekey   Operation = "rekey"
	OperationUnrekey Operation = "unrekey"
)

// Options contains the inputs for one online bounded-admin ceremony.
type Options struct {
	Operation  Operation
	ClientData string
	Network    string
	Artifact   string
	Account    string
	Target     string
	Fee        uint64
	UseFlatFee bool
	Wait       bool
}

// Result reports the submitted bounded-admin transaction.
type Result struct {
	From               string
	To                 string
	CurrentAuthAddress string
	TxID               string
	Confirmed          bool
	Output             string
	RefreshWarning     string
}

// Prepared contains the frozen signer-approved request and display context.
type Prepared struct {
	Request            boundedprotocol.Request
	From               string
	To                 string
	CurrentAuthAddress string
}

// CompleteOptions identifies the client context used to submit a frozen ceremony.
type CompleteOptions struct {
	ClientData string
	Network    string
	Wait       bool
}

type runtime interface {
	ResolveSingle(string) (string, error)
	RefreshAuthAddressWithContext(context.Context, string) (string, error)
	PrepareRekey(context.Context, engine.RekeyParams) (*engine.TransactionPrepResult, *engine.RekeyCheckResult, error)
	PrepareExternalBoundedAdmin(context.Context, *engine.TransactionPrepResult) (*engine.BoundedAdminPreparation, error)
	SubmitCompletedBoundedAdmin(context.Context, *engine.BoundedAdminPreparation, [][]byte, []types.Transaction, bool) (*engine.SubmitResult, error)
	Close() error
}

type signer interface {
	Sign(context.Context, string, boundedprotocol.Request) (boundedprotocol.Response, error)
}

// App coordinates the networked and cold-key portions of a bounded-admin operation.
type App struct {
	runtime               runtime
	signer                signer
	validateRequest       func(boundedprotocol.Request) (*boundedauthorization.ValidatedRequest, error)
	completeAuthorization func(boundedprotocol.Request, boundedprotocol.Response) ([][]byte, []types.Transaction, error)
}

func (a *App) validate(request boundedprotocol.Request) (*boundedauthorization.ValidatedRequest, error) {
	if a.validateRequest != nil {
		return a.validateRequest(request)
	}
	return boundedauthorization.ValidateRequest(request)
}

func (a *App) assemble(request boundedprotocol.Request, response boundedprotocol.Response) ([][]byte, []types.Transaction, error) {
	if a.completeAuthorization != nil {
		return a.completeAuthorization(request, response)
	}
	return boundedauthorization.Complete(request, response)
}

// Run opens the configured client runtime, performs one bounded-admin operation, and
// closes the signer connection before returning.
func Run(ctx context.Context, options Options, stderr io.Writer) (*Result, error) {
	runtime, err := openRuntime(options.ClientData, options.Network, stderr, true)
	if err != nil {
		return nil, err
	}
	defer func() { _ = runtime.Close() }()
	return (&App{
		runtime: runtime,
		signer:  newProcessSigner(stderr),
	}).Execute(ctx, options)
}

// RunPrepare connects to the signer and produces a durable ceremony request.
func RunPrepare(ctx context.Context, options Options, stderr io.Writer) (*Prepared, error) {
	runtime, err := openRuntime(options.ClientData, options.Network, stderr, true)
	if err != nil {
		return nil, err
	}
	defer func() { _ = runtime.Close() }()
	return (&App{runtime: runtime}).Prepare(ctx, options)
}

// RunComplete opens only the configured Algod client and submits a frozen ceremony.
func RunComplete(ctx context.Context, options CompleteOptions, request boundedprotocol.Request, response boundedprotocol.Response) (*Result, error) {
	runtime, err := openRuntime(options.ClientData, options.Network, io.Discard, false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = runtime.Close() }()
	validated, err := boundedauthorization.ValidateRequest(request)
	if err != nil {
		return nil, err
	}
	target := validated.Group.Entries[request.Payload.Partial.TargetIndex].Txn
	prepared := &Prepared{
		Request:            request,
		From:               target.Sender.String(),
		To:                 target.RekeyTo.String(),
		CurrentAuthAddress: request.Payload.CurrentAuthAddress,
	}
	return (&App{runtime: runtime}).Complete(ctx, prepared, response, options.Wait)
}

// Execute performs one bounded-admin operation using the supplied runtime and signer.
func (a *App) Execute(ctx context.Context, options Options) (*Result, error) {
	if a == nil || a.runtime == nil || a.signer == nil {
		return nil, fmt.Errorf("bounded-admin application is not initialized")
	}
	if options.Artifact == "" {
		return nil, fmt.Errorf("bounded-admin key path is required")
	}
	prepared, err := a.Prepare(ctx, options)
	if err != nil {
		return nil, err
	}
	response, err := a.signer.Sign(ctx, options.Artifact, prepared.Request)
	if err != nil {
		return nil, err
	}
	return a.Complete(ctx, prepared, response, options.Wait)
}

// Prepare obtains the spending partial without accessing a bounded-admin key.
func (a *App) Prepare(ctx context.Context, options Options) (*Prepared, error) {
	if a == nil || a.runtime == nil {
		return nil, fmt.Errorf("bounded-admin application is not initialized")
	}
	if options.Account == "" {
		return nil, fmt.Errorf("account is required")
	}
	if options.Operation != OperationRekey && options.Operation != OperationUnrekey {
		return nil, fmt.Errorf("unsupported bounded-admin operation %q", options.Operation)
	}

	from, err := a.runtime.ResolveSingle(options.Account)
	if err != nil {
		return nil, fmt.Errorf("resolve bounded account: %w", err)
	}
	if from == "" {
		return nil, fmt.Errorf("bounded account resolved to an empty address")
	}

	to := from
	currentAuth := ""
	if options.Operation == OperationRekey {
		if options.Target == "" {
			return nil, fmt.Errorf("rekey target is required")
		}
		to, err = a.runtime.ResolveSingle(options.Target)
		if err != nil {
			return nil, fmt.Errorf("resolve rekey target: %w", err)
		}
		if to == "" {
			return nil, fmt.Errorf("rekey target resolved to an empty address")
		}
	} else {
		currentAuth, err = a.runtime.RefreshAuthAddressWithContext(ctx, from)
		if err != nil {
			return nil, fmt.Errorf("query current authorization address: %w", err)
		}
		if currentAuth == "" || currentAuth == from {
			return nil, fmt.Errorf("account is not rekeyed (it already signs for itself)")
		}
	}

	prep, _, err := a.runtime.PrepareRekey(ctx, engine.RekeyParams{
		From:       from,
		To:         to,
		Fee:        options.Fee,
		UseFlatFee: options.UseFlatFee,
	})
	if err != nil {
		return nil, fmt.Errorf("prepare bounded-admin transaction: %w", err)
	}
	prepared, err := a.runtime.PrepareExternalBoundedAdmin(ctx, prep)
	if err != nil {
		return nil, err
	}
	if _, err := a.validate(prepared.Request); err != nil {
		return nil, fmt.Errorf("validate bounded-admin signer partial: %w", err)
	}
	if currentAuth == "" {
		currentAuth = prepared.Request.Payload.CurrentAuthAddress
	}
	return &Prepared{Request: prepared.Request, From: from, To: to, CurrentAuthAddress: currentAuth}, nil
}

// Complete validates and submits a frozen request without contacting the signer.
func (a *App) Complete(ctx context.Context, prepared *Prepared, response boundedprotocol.Response, wait bool) (*Result, error) {
	if a == nil || a.runtime == nil {
		return nil, fmt.Errorf("bounded-admin application is not initialized")
	}
	if prepared == nil {
		return nil, fmt.Errorf("bounded-admin preparation is required")
	}
	signed, txns, err := a.assemble(prepared.Request, response)
	if err != nil {
		return nil, fmt.Errorf("complete bounded-admin authorization: %w", err)
	}
	submitted, err := a.runtime.SubmitCompletedBoundedAdmin(ctx, &engine.BoundedAdminPreparation{Request: prepared.Request}, signed, txns, wait)
	if err != nil {
		return nil, err
	}
	return &Result{
		From:               prepared.From,
		To:                 prepared.To,
		CurrentAuthAddress: prepared.CurrentAuthAddress,
		TxID:               submitted.TxID,
		Confirmed:          submitted.Confirmed,
		Output:             submitted.Output,
		RefreshWarning:     submitted.AuthRefreshWarning,
	}, nil
}
