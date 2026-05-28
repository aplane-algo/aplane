// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/aplane-algo/aplane/internal/appresult"
	"github.com/aplane-algo/aplane/internal/keytypeux"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
)

// CommandResult is returned by commands that support dual rendering.
// RenderText writes human-friendly output; RenderJSON returns structured data for MCP.
type CommandResult interface {
	RenderText(w io.Writer, r *REPLState)
	RenderJSON() []byte
}

// JSONResult holds structured output that renders as JSON in both text and MCP modes.
type JSONResult struct {
	Data interface{}
}

// KeysResult holds the output of the "keys" command.
type KeysResult struct {
	appresult.Keys
}

// ToggleResult holds the output of toggle commands (verbose, write, simulate).
type ToggleResult struct {
	appresult.Toggle
}

func (kr *KeysResult) RenderText(w io.Writer, r *REPLState) {
	if len(kr.Keys.Keys) == 0 {
		r.println("No signable accounts found")
		return
	}
	for _, k := range kr.Keys.Keys {
		r.printf("%s [%s]%s\n", r.app().FormatAddress(k.Address, ""), r.app().FormatKeyTypeForDisplay(k.Address, k.KeyType), formatTemplateProvenanceStatusSuffix(k.TemplateProvenanceStatus))
	}
}

func formatTemplateProvenanceStatusSuffix(templateProvenanceStatus string) string {
	if provenanceLabel := keytypeux.TemplateProvenanceLabel(templateProvenanceStatus); provenanceLabel != "" {
		return " [" + provenanceLabel + "]"
	}
	return ""
}

func (tr *ToggleResult) RenderText(_ io.Writer, r *REPLState) {
	if !tr.Changed {
		state := "off"
		if tr.Enabled {
			state = "on"
		}
		r.printf("%s mode: %s\n", capitalize(tr.Name), state)
		return
	}
	if tr.Enabled {
		r.printf("✓ %s mode enabled\n", capitalize(tr.Name))
	} else {
		r.printf("✓ %s mode disabled\n", capitalize(tr.Name))
	}
}

func (tr *ToggleResult) RenderJSON() []byte {
	data, _ := json.Marshal(struct {
		Name    string `json:"name"`
		Enabled bool   `json:"enabled"`
	}{tr.Name, tr.Enabled})
	return data
}

func (jr *JSONResult) RenderText(w io.Writer, _ *REPLState) {
	data, err := json.MarshalIndent(jr.Data, "", "  ")
	if err != nil {
		_, _ = io.WriteString(w, "{}\n")
		return
	}
	_, _ = w.Write(data)
	_, _ = io.WriteString(w, "\n")
}

func (jr *JSONResult) RenderJSON() []byte {
	data, _ := json.Marshal(jr.Data)
	return data
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return string(s[0]-32) + s[1:]
}

// PluginResult holds the output of an external plugin execution.
type PluginResult struct {
	appresult.Plugin
}

func (pr *PluginResult) RenderText(_ io.Writer, r *REPLState) {
	if pr.Presentation != nil {
		renderPluginPresentation(r, pr.Presentation)
	} else if pr.Message != "" {
		r.println(pr.Message)
	}
	if len(pr.TxIDs) > 0 {
		if r.app().IsSimulateEnabled() {
			r.println("\n✓ Transaction(s) simulated successfully!")
		} else {
			r.println("\n✓ Transaction(s) submitted successfully!")
		}
		for i, txID := range pr.TxIDs {
			r.printf("  [%d] %s\n", i+1, txID)
		}
	}
	for _, step := range pr.Steps {
		if step.Message != "" {
			r.println(step.Message)
		}
		for i, txID := range step.TxIDs {
			r.printf("  [%d] %s\n", i+1, txID)
		}
	}
}

func (pr *PluginResult) RenderJSON() []byte {
	filtered := *pr
	filtered.Data = appresult.FilterPluginData(pr.Data)
	data, _ := json.Marshal(filtered)
	return data
}

func (kr *KeysResult) RenderJSON() []byte {
	type mcpKey struct {
		Address                  string `json:"address"`
		KeyType                  string `json:"key_type"`
		TemplateProvenanceStatus string `json:"template_provenance_status,omitempty"`
		TemplateProvenanceNote   string `json:"template_provenance_note,omitempty"`
	}
	result := make([]mcpKey, len(kr.Keys.Keys))
	for i, k := range kr.Keys.Keys {
		result[i] = mcpKey{
			Address:                  k.Address,
			KeyType:                  k.KeyType,
			TemplateProvenanceStatus: k.TemplateProvenanceStatus,
			TemplateProvenanceNote:   k.TemplateProvenanceNote,
		}
	}
	data, _ := json.Marshal(result)
	return data
}

func renderPluginPresentation(r *REPLState, presentation *jsonrpc.Presentation) {
	if presentation == nil {
		return
	}

	needsLeadingBlank := false
	if presentation.Title != "" {
		r.println(presentation.Title)
		needsLeadingBlank = true
	}
	if presentation.Summary != "" {
		if needsLeadingBlank {
			r.println()
		}
		r.println(presentation.Summary)
		needsLeadingBlank = true
	}

	for i, section := range presentation.Sections {
		if needsLeadingBlank || i > 0 {
			r.println()
		}
		if section.Title != "" {
			r.println(section.Title)
		}

		switch section.Kind {
		case "text":
			if section.Text != "" {
				r.println(section.Text)
			}
		case "key_value":
			renderPluginKeyValueSection(r, section.Items)
		case "table":
			renderPluginTableSection(r, section.Columns, section.Rows)
		default:
			if section.Text != "" {
				r.println(section.Text)
			}
		}
		needsLeadingBlank = true
	}
}

func renderPluginKeyValueSection(r *REPLState, items []jsonrpc.PresentationItem) {
	if len(items) == 0 {
		return
	}

	maxLabel := 0
	for _, item := range items {
		if len(item.Label) > maxLabel {
			maxLabel = len(item.Label)
		}
	}

	for _, item := range items {
		label := item.Label
		if label == "" {
			r.println(item.Value)
			continue
		}
		r.printf("%-*s  %s\n", maxLabel+1, label+":", item.Value)
	}
}

func renderPluginTableSection(r *REPLState, columns []string, rows []jsonrpc.PresentationTableRow) {
	if len(columns) == 0 {
		return
	}

	widths := make([]int, len(columns))
	for i, column := range columns {
		widths[i] = len(column)
	}
	for _, row := range rows {
		for i, cell := range row.Cells {
			if i >= len(widths) {
				break
			}
			if len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	for i, column := range columns {
		if i > 0 {
			r.print("  ")
		}
		r.printf("%-*s", widths[i], column)
	}
	r.println()

	for i := range columns {
		if i > 0 {
			r.print("  ")
		}
		r.print(strings.Repeat("-", widths[i]))
	}
	r.println()

	for _, row := range rows {
		for i := range columns {
			if i > 0 {
				r.print("  ")
			}
			cell := ""
			if i < len(row.Cells) {
				cell = row.Cells[i]
			}
			r.printf("%-*s", widths[i], cell)
		}
		r.println()
	}
}
