// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package apshellapp owns apshell application-layer use-cases.
// It sits between cmd/apshell UI concerns and the lower-level engine package.
package apshellapp

import (
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
)

// App is the in-process application facade for apshell command use-cases.
// The initial scaffold intentionally stays small; concrete command methods are
// added incrementally as command logic moves out of cmd/apshell.
type App struct {
	eng     *engine.Engine
	DataDir string
	Config  config.Config

	Plugins PluginRuntime
	Scripts ScriptRuntime
}

// New constructs the apshell application facade.
func New(eng *engine.Engine, cfg config.Config, dataDir string) *App {
	return &App{
		eng:     eng,
		DataDir: dataDir,
		Config:  cfg,
		Scripts: NewGojaScriptRuntime(eng),
	}
}
