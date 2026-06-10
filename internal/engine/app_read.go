// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"encoding/base64"
	"sort"
	"unicode/utf8"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
)

// AppStateSchema is a normalized application state schema.
type AppStateSchema struct {
	NumUint      uint64 `json:"num_uint"`
	NumByteSlice uint64 `json:"num_byte_slice"`
}

// AppStateValue is a normalized TEAL state value.
type AppStateValue struct {
	Type        string `json:"type"`
	Uint        uint64 `json:"uint,omitempty"`
	BytesBase64 string `json:"bytes_base64,omitempty"`
	BytesText   string `json:"bytes_text,omitempty"`
}

// AppStateEntry is a normalized global or local state entry.
type AppStateEntry struct {
	KeyBase64 string        `json:"key_base64"`
	KeyText   string        `json:"key_text,omitempty"`
	Value     AppStateValue `json:"value"`
}

// AppGlobalStateResult describes an application's global state.
type AppGlobalStateResult struct {
	AppID             uint64          `json:"app_id"`
	Creator           string          `json:"creator,omitempty"`
	GlobalState       []AppStateEntry `json:"global_state"`
	GlobalStateSchema AppStateSchema  `json:"global_state_schema"`
	LocalStateSchema  AppStateSchema  `json:"local_state_schema"`
}

// AppInfoResult describes application metadata and programs.
type AppInfoResult struct {
	AppID               uint64         `json:"app_id"`
	AppAddress          string         `json:"app_address"`
	Creator             string         `json:"creator,omitempty"`
	CreatedAtRound      uint64         `json:"created_at_round,omitempty"`
	Deleted             bool           `json:"deleted,omitempty"`
	DeletedAtRound      uint64         `json:"deleted_at_round,omitempty"`
	Version             uint64         `json:"version,omitempty"`
	ExtraProgramPages   uint64         `json:"extra_program_pages,omitempty"`
	GlobalStateSchema   AppStateSchema `json:"global_state_schema"`
	LocalStateSchema    AppStateSchema `json:"local_state_schema"`
	ApprovalProgramSize int            `json:"approval_program_size"`
	ApprovalProgramB64  string         `json:"approval_program_base64,omitempty"`
	ApprovalProgramHash string         `json:"approval_program_hash,omitempty"`
	ClearProgramSize    int            `json:"clear_state_program_size"`
	ClearProgramB64     string         `json:"clear_state_program_base64,omitempty"`
	ClearProgramHash    string         `json:"clear_state_program_hash,omitempty"`
}

// AppLocalStateResult describes an account's local state for an application.
type AppLocalStateResult struct {
	AppID            uint64          `json:"app_id"`
	Account          string          `json:"account"`
	Round            uint64          `json:"round"`
	Deleted          bool            `json:"deleted,omitempty"`
	OptedInAtRound   uint64          `json:"opted_in_at_round,omitempty"`
	ClosedOutAtRound uint64          `json:"closed_out_at_round,omitempty"`
	LocalState       []AppStateEntry `json:"local_state"`
	Schema           AppStateSchema  `json:"schema"`
}

// AppBoxName identifies an application box.
type AppBoxName struct {
	NameBase64 string `json:"name_base64"`
	NameText   string `json:"name_text,omitempty"`
}

// AppBoxResult describes an application box and its value.
type AppBoxResult struct {
	AppID       uint64 `json:"app_id"`
	NameBase64  string `json:"name_base64"`
	NameText    string `json:"name_text,omitempty"`
	Round       uint64 `json:"round"`
	ValueBase64 string `json:"value_base64"`
	ValueText   string `json:"value_text,omitempty"`
}

// AppBoxesResult lists the boxes for an application.
type AppBoxesResult struct {
	AppID uint64       `json:"app_id"`
	Boxes []AppBoxName `json:"boxes"`
}

func (e *Engine) ReadAppGlobalState(ctx context.Context, appID uint64) (*AppGlobalStateResult, error) {
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}

	app, err := e.AlgodClient.GetApplicationByID(appID).Do(ctx)
	if err != nil {
		return nil, err
	}

	return &AppGlobalStateResult{
		AppID:             app.Id,
		Creator:           app.Params.Creator,
		GlobalState:       normalizeStateEntries(app.Params.GlobalState),
		GlobalStateSchema: normalizeStateSchema(app.Params.GlobalStateSchema),
		LocalStateSchema:  normalizeStateSchema(app.Params.LocalStateSchema),
	}, nil
}

func (e *Engine) ReadAppInfo(ctx context.Context, appID uint64) (*AppInfoResult, error) {
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}

	app, err := e.AlgodClient.GetApplicationByID(appID).Do(ctx)
	if err != nil {
		return nil, err
	}

	return &AppInfoResult{
		AppID:               app.Id,
		AppAddress:          crypto.GetApplicationAddress(app.Id).String(),
		Creator:             app.Params.Creator,
		CreatedAtRound:      app.CreatedAtRound,
		Deleted:             app.Deleted,
		DeletedAtRound:      app.DeletedAtRound,
		Version:             app.Params.Version,
		ExtraProgramPages:   app.Params.ExtraProgramPages,
		GlobalStateSchema:   normalizeStateSchema(app.Params.GlobalStateSchema),
		LocalStateSchema:    normalizeStateSchema(app.Params.LocalStateSchema),
		ApprovalProgramSize: len(app.Params.ApprovalProgram),
		ApprovalProgramB64:  base64.StdEncoding.EncodeToString(app.Params.ApprovalProgram),
		ApprovalProgramHash: crypto.AddressFromProgram(app.Params.ApprovalProgram).String(),
		ClearProgramSize:    len(app.Params.ClearStateProgram),
		ClearProgramB64:     base64.StdEncoding.EncodeToString(app.Params.ClearStateProgram),
		ClearProgramHash:    crypto.AddressFromProgram(app.Params.ClearStateProgram).String(),
	}, nil
}

func (e *Engine) ReadAppLocalState(ctx context.Context, address string, appID uint64) (*AppLocalStateResult, error) {
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}

	resp, err := e.AlgodClient.AccountApplicationInformation(address, appID).Do(ctx)
	if err != nil {
		return nil, err
	}

	return &AppLocalStateResult{
		AppID:            appID,
		Account:          address,
		Round:            resp.Round,
		Deleted:          resp.AppLocalState.Deleted,
		OptedInAtRound:   resp.AppLocalState.OptedInAtRound,
		ClosedOutAtRound: resp.AppLocalState.ClosedOutAtRound,
		LocalState:       normalizeStateEntries(resp.AppLocalState.KeyValue),
		Schema:           normalizeStateSchema(resp.AppLocalState.Schema),
	}, nil
}

func (e *Engine) ReadAppBox(ctx context.Context, appID uint64, name []byte) (*AppBoxResult, error) {
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}

	box, err := e.AlgodClient.GetApplicationBoxByName(appID, name).Do(ctx)
	if err != nil {
		return nil, err
	}

	return &AppBoxResult{
		AppID:       appID,
		NameBase64:  base64.StdEncoding.EncodeToString(box.Name),
		NameText:    printableText(box.Name),
		Round:       box.Round,
		ValueBase64: base64.StdEncoding.EncodeToString(box.Value),
		ValueText:   printableText(box.Value),
	}, nil
}

func (e *Engine) ListAppBoxes(ctx context.Context, appID uint64) (*AppBoxesResult, error) {
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}

	resp, err := e.AlgodClient.GetApplicationBoxes(appID).Do(ctx)
	if err != nil {
		return nil, err
	}

	boxes := make([]AppBoxName, 0, len(resp.Boxes))
	for _, box := range resp.Boxes {
		boxes = append(boxes, AppBoxName{
			NameBase64: base64.StdEncoding.EncodeToString(box.Name),
			NameText:   printableText(box.Name),
		})
	}

	sort.Slice(boxes, func(i, j int) bool {
		return boxes[i].NameBase64 < boxes[j].NameBase64
	})

	return &AppBoxesResult{
		AppID: appID,
		Boxes: boxes,
	}, nil
}

func normalizeStateEntries(entries []models.TealKeyValue) []AppStateEntry {
	result := make([]AppStateEntry, 0, len(entries))
	for _, entry := range entries {
		item := AppStateEntry{
			KeyBase64: entry.Key,
			Value:     normalizeStateValue(entry.Value),
		}

		keyBytes, err := base64.StdEncoding.DecodeString(entry.Key)
		if err == nil {
			item.KeyText = printableText(keyBytes)
		}

		result = append(result, item)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].KeyBase64 < result[j].KeyBase64
	})

	return result
}

func normalizeStateValue(value models.TealValue) AppStateValue {
	switch value.Type {
	case 1:
		out := AppStateValue{
			Type:        "bytes",
			BytesBase64: value.Bytes,
		}
		bytesValue, err := base64.StdEncoding.DecodeString(value.Bytes)
		if err == nil {
			out.BytesText = printableText(bytesValue)
		}
		return out
	case 2:
		return AppStateValue{
			Type: "uint",
			Uint: value.Uint,
		}
	default:
		return AppStateValue{
			Type: "unknown",
			Uint: value.Uint,
		}
	}
}

func normalizeStateSchema(schema models.ApplicationStateSchema) AppStateSchema {
	return AppStateSchema{
		NumUint:      schema.NumUint,
		NumByteSlice: schema.NumByteSlice,
	}
}

func printableText(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	if !utf8.Valid(data) {
		return ""
	}
	return string(data)
}
