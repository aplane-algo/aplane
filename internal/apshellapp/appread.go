// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"fmt"
	"strconv"

	"github.com/aplane-algo/aplane/internal/appinput"
)

// AppReadRequest captures the parsed argv tail for "app read".
type AppReadRequest struct {
	Args []string
}

// AppRead executes the semantic part of "app read".
func (a *App) AppRead(ctx context.Context, req AppReadRequest) (*AppReadResult, error) {
	if len(req.Args) == 0 {
		return nil, fmt.Errorf("usage: app read <info|global|local|box|boxes>")
	}

	switch req.Args[0] {
	case "info":
		if len(req.Args) != 2 {
			return nil, fmt.Errorf("usage: app read info <app-id>")
		}
		appID, err := parseAppID(req.Args[1])
		if err != nil {
			return nil, err
		}
		info, err := a.eng.ReadAppInfo(ctx, appID)
		if err != nil {
			return nil, err
		}
		return &AppReadResult{Data: appInfoDetailsFromEngine(info)}, nil
	case "global":
		if len(req.Args) != 2 {
			return nil, fmt.Errorf("usage: app read global <app-id>")
		}
		appID, err := parseAppID(req.Args[1])
		if err != nil {
			return nil, err
		}
		state, err := a.eng.ReadAppGlobalState(ctx, appID)
		if err != nil {
			return nil, err
		}
		return &AppReadResult{Data: appGlobalStateDetailsFromEngine(state)}, nil
	case "local":
		if len(req.Args) != 3 {
			return nil, fmt.Errorf("usage: app read local <app-id> <account>")
		}
		appID, err := parseAppID(req.Args[1])
		if err != nil {
			return nil, err
		}
		address, err := a.eng.NewAddressResolver().ResolveSingle(req.Args[2])
		if err != nil {
			return nil, fmt.Errorf("failed to resolve account: %w", err)
		}
		state, err := a.eng.ReadAppLocalState(ctx, address, appID)
		if err != nil {
			return nil, err
		}
		return &AppReadResult{Data: appLocalStateDetailsFromEngine(state)}, nil
	case "box":
		if len(req.Args) != 3 {
			return nil, fmt.Errorf("usage: app read box <app-id> <box-name>")
		}
		appID, err := parseAppID(req.Args[1])
		if err != nil {
			return nil, err
		}
		boxName, err := parseBoxName(req.Args[2])
		if err != nil {
			return nil, err
		}
		box, err := a.eng.ReadAppBox(ctx, appID, boxName)
		if err != nil {
			return nil, err
		}
		return &AppReadResult{Data: appBoxDetailsFromEngine(box)}, nil
	case "boxes":
		if len(req.Args) != 2 {
			return nil, fmt.Errorf("usage: app read boxes <app-id>")
		}
		appID, err := parseAppID(req.Args[1])
		if err != nil {
			return nil, err
		}
		boxes, err := a.eng.ListAppBoxes(ctx, appID)
		if err != nil {
			return nil, err
		}
		return &AppReadResult{Data: appBoxesDetailsFromEngine(boxes)}, nil
	default:
		return nil, fmt.Errorf("unknown app read command: %s", req.Args[0])
	}
}

func parseAppID(raw string) (uint64, error) {
	appID, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid app ID: %s", raw)
	}
	return appID, nil
}

func parseBoxName(raw string) ([]byte, error) {
	name, err := appinput.ParseByteValue(raw)
	if err != nil {
		return nil, err
	}
	if len(name) == 0 {
		return nil, fmt.Errorf("box name must be non-empty")
	}
	return name, nil
}
