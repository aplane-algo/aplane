// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"os"

	"github.com/aplane-algo/aplane/internal/appresult"
)

// WriteMode reports the current write-mode state.
func (a *App) WriteMode() appresult.Toggle {
	return appresult.Toggle{Name: "write", Enabled: a.eng.GetWriteMode(), Changed: false}
}

// SetWriteMode updates write mode and ensures the output directory exists when enabling it.
func (a *App) SetWriteMode(enabled bool) (appresult.Toggle, error) {
	if enabled {
		if err := os.MkdirAll("txnjson", 0o750); err != nil {
			return appresult.Toggle{}, err
		}
	}
	a.eng.SetWriteMode(enabled)
	return appresult.Toggle{Name: "write", Enabled: a.eng.GetWriteMode(), Changed: true}, nil
}

// VerboseMode reports the current verbose-mode state.
func (a *App) VerboseMode() appresult.Toggle {
	return appresult.Toggle{Name: "verbose", Enabled: a.eng.GetVerbose(), Changed: false}
}

// SetVerboseMode updates verbose mode.
func (a *App) SetVerboseMode(enabled bool) appresult.Toggle {
	a.eng.SetVerbose(enabled)
	return appresult.Toggle{Name: "verbose", Enabled: a.eng.GetVerbose(), Changed: true}
}

// SimulateMode reports the current simulate-mode state.
func (a *App) SimulateMode() appresult.Toggle {
	return appresult.Toggle{Name: "simulate", Enabled: a.eng.GetSimulate(), Changed: false}
}

// SetSimulateMode updates simulate mode.
func (a *App) SetSimulateMode(enabled bool) appresult.Toggle {
	a.eng.SetSimulate(enabled)
	return appresult.Toggle{Name: "simulate", Enabled: a.eng.GetSimulate(), Changed: true}
}
