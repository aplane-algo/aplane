// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/jsapi"
	"github.com/aplane-algo/aplane/internal/scripting"
)

// GojaScriptRuntime owns apshell's embedded JavaScript runner construction.
type GojaScriptRuntime struct {
	engine *engine.Engine
	runner scripting.Runner
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
		r.runner = gojaRunner
	}
	r.runner.SetOutput(output)
	return r.runner
}
