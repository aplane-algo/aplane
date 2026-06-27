// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"github.com/aplane-algo/aplane/internal/jsapi"
	"github.com/aplane-algo/aplane/internal/plugin/discovery"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	"github.com/aplane-algo/aplane/internal/scripting"
)

// PluginRuntime is the narrow application-facing plugin boundary.
type PluginRuntime interface {
	SetConfig(network, algodURL, algodToken, indexerURL string)
	DiscoverPluginsCached() ([]*discovery.Plugin, error)
	FindByCommand(command string) (*discovery.Plugin, error)
	FindByName(name string) (*discovery.Plugin, error)
	ListCommands() ([]string, error)
	ExecuteCommand(pluginName, command string, args []string, context jsonrpc.Context) (*jsonrpc.ExecuteResult, error)
	SignTransactions(pluginName string, params jsonrpc.SignTransactionsParams) (*jsonrpc.SignTransactionsResult, error)
	StopAll()
}

// ScriptRuntime is the narrow application-facing scripting boundary.
type ScriptRuntime interface {
	EnsureRunner(output func(string), pluginExecutor jsapi.PluginExecutor) scripting.Runner
}
