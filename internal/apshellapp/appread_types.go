// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import "github.com/aplane-algo/aplane/internal/engine"

func appStateSchemaDetailsFromEngine(schema engine.AppStateSchema) AppStateSchemaDetails {
	return AppStateSchemaDetails{
		NumUint:      schema.NumUint,
		NumByteSlice: schema.NumByteSlice,
	}
}

func appStateValueDetailsFromEngine(value engine.AppStateValue) AppStateValueDetails {
	return AppStateValueDetails{
		Type:        value.Type,
		Uint:        value.Uint,
		BytesBase64: value.BytesBase64,
		BytesText:   value.BytesText,
	}
}

func appStateEntryDetailsFromEngine(entry engine.AppStateEntry) AppStateEntryDetails {
	return AppStateEntryDetails{
		KeyBase64: entry.KeyBase64,
		KeyText:   entry.KeyText,
		Value:     appStateValueDetailsFromEngine(entry.Value),
	}
}

func appStateEntryDetailsListFromEngine(entries []engine.AppStateEntry) []AppStateEntryDetails {
	result := make([]AppStateEntryDetails, len(entries))
	for i, entry := range entries {
		result[i] = appStateEntryDetailsFromEngine(entry)
	}
	return result
}

func appInfoDetailsFromEngine(info *engine.AppInfoResult) *AppInfoDetails {
	if info == nil {
		return nil
	}
	return &AppInfoDetails{
		AppID:               info.AppID,
		AppAddress:          info.AppAddress,
		Creator:             info.Creator,
		CreatedAtRound:      info.CreatedAtRound,
		Deleted:             info.Deleted,
		DeletedAtRound:      info.DeletedAtRound,
		Version:             info.Version,
		ExtraProgramPages:   info.ExtraProgramPages,
		GlobalStateSchema:   appStateSchemaDetailsFromEngine(info.GlobalStateSchema),
		LocalStateSchema:    appStateSchemaDetailsFromEngine(info.LocalStateSchema),
		ApprovalProgramSize: info.ApprovalProgramSize,
		ApprovalProgramB64:  info.ApprovalProgramB64,
		ApprovalProgramHash: info.ApprovalProgramHash,
		ClearProgramSize:    info.ClearProgramSize,
		ClearProgramB64:     info.ClearProgramB64,
		ClearProgramHash:    info.ClearProgramHash,
	}
}

func appGlobalStateDetailsFromEngine(state *engine.AppGlobalStateResult) *AppGlobalStateDetails {
	if state == nil {
		return nil
	}
	return &AppGlobalStateDetails{
		AppID:             state.AppID,
		Creator:           state.Creator,
		GlobalState:       appStateEntryDetailsListFromEngine(state.GlobalState),
		GlobalStateSchema: appStateSchemaDetailsFromEngine(state.GlobalStateSchema),
		LocalStateSchema:  appStateSchemaDetailsFromEngine(state.LocalStateSchema),
	}
}

func appLocalStateDetailsFromEngine(state *engine.AppLocalStateResult) *AppLocalStateDetails {
	if state == nil {
		return nil
	}
	return &AppLocalStateDetails{
		AppID:            state.AppID,
		Account:          state.Account,
		Round:            state.Round,
		Deleted:          state.Deleted,
		OptedInAtRound:   state.OptedInAtRound,
		ClosedOutAtRound: state.ClosedOutAtRound,
		LocalState:       appStateEntryDetailsListFromEngine(state.LocalState),
		Schema:           appStateSchemaDetailsFromEngine(state.Schema),
	}
}

func appBoxDetailsFromEngine(box *engine.AppBoxResult) *AppBoxDetails {
	if box == nil {
		return nil
	}
	return &AppBoxDetails{
		AppID:       box.AppID,
		NameBase64:  box.NameBase64,
		NameText:    box.NameText,
		Round:       box.Round,
		ValueBase64: box.ValueBase64,
		ValueText:   box.ValueText,
	}
}

func appBoxesDetailsFromEngine(boxes *engine.AppBoxesResult) *AppBoxesDetails {
	if boxes == nil {
		return nil
	}
	result := &AppBoxesDetails{
		AppID: boxes.AppID,
		Boxes: make([]AppBoxNameDetails, len(boxes.Boxes)),
	}
	for i, box := range boxes.Boxes {
		result.Boxes[i] = AppBoxNameDetails{
			NameBase64: box.NameBase64,
			NameText:   box.NameText,
		}
	}
	return result
}
