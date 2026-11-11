// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/jsapi"
	"github.com/aplane-algo/aplane/internal/scripting"
)

// GojaScriptRuntime owns apshell's embedded JavaScript runner construction.
type GojaScriptRuntime struct {
	engine  *engine.Engine
	sweeper jsapi.Sweeper
	runner  scripting.Runner
}

// NewGojaScriptRuntime constructs the default JavaScript runtime for apshell.
func NewGojaScriptRuntime(eng *engine.Engine) *GojaScriptRuntime {
	return &GojaScriptRuntime{engine: eng}
}

// EnsureRunner returns a persistent Goja runner, creating it on first use.
func (r *GojaScriptRuntime) EnsureRunner(output func(string), pluginExecutor jsapi.PluginExecutor) scripting.Runner {
	if r.runner == nil {
		gojaRunner := scripting.NewGojaRunner(r.engine)
		if pluginExecutor != nil {
			gojaRunner.SetPluginExecutor(pluginExecutor)
		}
		if r.sweeper != nil {
			gojaRunner.SetSweeper(r.sweeper)
		}
		r.runner = gojaRunner
	}
	r.runner.SetOutput(output)
	return r.runner
}

// jsSweeper gives JavaScript's sweep() the shell's sweep workflow, so the
// function and the command are one implementation.
type jsSweeper struct{ app *App }

var _ jsapi.Sweeper = jsSweeper{}

func (s jsSweeper) Sweep(ctx context.Context, req jsapi.SweepRequest) (*jsapi.SweepResult, error) {
	if req.From == nil {
		// A nil list means "every signable account" to App.Sweep. sweep()
		// always names its sources.
		return nil, fmt.Errorf("no source account given")
	}
	assetRef := "algo"
	if req.AssetID != 0 {
		assetRef = strconv.FormatUint(req.AssetID, 10)
	}
	var leaving *uint64
	if req.LeavingSet {
		leaving = &req.Leaving
	}
	result, err := s.app.Sweep(ctx, SweepRequest{
		AssetRef:   assetRef,
		FromRaw:    req.From,
		ToRaw:      req.To,
		LeavingRaw: leaving,
		Fee:        req.Fee,
		UseFlatFee: req.UseFlatFee,
		LsigArgs:   req.LsigArgs,
		Wait:       req.Wait,
	})
	out, err := sweepResultForScript(result, err)
	if out != nil {
		out.Simulated = s.app.IsSimulateEnabled()
	}
	return out, err
}

// sweepResultForScript turns the sweep workflow's outcome into what sweep()
// returns or raises.
func sweepResultForScript(result *SweepCommandResult, err error) (*jsapi.SweepResult, error) {
	if result == nil {
		return nil, err
	}
	out := &jsapi.SweepResult{
		AssetID:   result.Asset.AssetID,
		To:        result.ToAddress,
		Succeeded: result.SuccessCount,
		Failed:    result.FailureCount,
		Items:     make([]jsapi.SweepItem, 0, len(result.Items)),
	}
	for _, item := range result.Items {
		failure := item.Error
		if item.SimulationFailure != "" {
			// The shell prints the simulation's output; a script has only
			// this field to learn the item failed, and why.
			failure = item.SimulationFailure
		}
		out.Items = append(out.Items, jsapi.SweepItem{
			From:      item.From,
			Amount:    item.Amount.Raw,
			TxID:      item.TxID,
			Confirmed: item.Confirmed,
			Skipped:   item.SkippedReason,
			Error:     failure,
		})
	}
	if err != nil {
		// Every transaction failed. A script that does not read the result
		// must not carry on as if the sweep had worked, so this is raised,
		// with each account's reason. A sweep where only some failed returns
		// its result, and the script reads `failed` and the items.
		//
		// "Failed" includes a transaction that was sent and whose
		// confirmation wait failed: it timed out, or the network dropped
		// it. Which is not known here, so its ID is in the message and the
		// script must not take the error to mean that nothing moved.
		var reasons []string
		for i, item := range out.Items {
			if item.Error == "" {
				continue
			}
			reason := fmt.Sprintf("%s: %s", item.From, item.Error)
			if item.TxID != "" && result.Items[i].SimulationFailure == "" {
				reason += fmt.Sprintf(" [sent as %s; check it before retrying]", item.TxID)
			}
			reasons = append(reasons, reason)
		}
		return nil, fmt.Errorf("%w (%s)", err, strings.Join(reasons, "; "))
	}
	return out, nil
}
