// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package boundary

import (
	"fmt"
	"slices"
	"strings"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
)

const allTransfers = "pay,axfer,asset_opt_in"

// Preset is a named arrangement of the grammar. Fixed holds the choices the preset
// makes; Fields names what the operator supplies. Presets are the one definition
// that both the guided screens and sample boundary files come from.
type Preset struct {
	Name        string
	Title       string
	Description string
	Fixed       map[string]string
	Fields      []string
}

// Presets returns the guided arrangements. A narrower transfer list, such as
// ALGO only, needs a boundary file: presets do not ask about it.
func Presets() []Preset {
	return []Preset{
		{
			Name:        "allowlist",
			Title:       "Allowlist",
			Description: "Pays only listed recipients. The spending key alone can rekey it.",
			Fixed: map[string]string{
				ParameterSpendEffects:   allTransfers,
				ParameterRekeyAuthority: RekeySpendingKey,
				ParameterListEncoding:   EncodingAuto,
			},
			Fields: []string{ParameterRecipients},
		},
		{
			Name:        "locked-allowlist",
			Title:       "Locked Allowlist",
			Description: "Pays only listed recipients. Rekey also needs a contract admin.",
			Fixed: map[string]string{
				ParameterSpendEffects:   allTransfers,
				ParameterRekeyAuthority: RekeyAdminKey,
				ParameterListEncoding:   EncodingAuto,
			},
			Fields: []string{ParameterRecipients, boundedmeta.AdminPublicKeyParameter},
		},
		{
			Name:        "corridor",
			Title:       "Corridor",
			Description: "A Merkle list, admin-key rekey, and a cosigner on every spend.",
			Fixed: map[string]string{
				ParameterSpendEffects:   allTransfers,
				ParameterRekeyAuthority: RekeyAdminKey,
				ParameterListEncoding:   EncodingMerkle,
			},
			Fields: []string{ParameterRecipients, boundedmeta.AdminPublicKeyParameter, ParameterCosigner},
		},
		{
			Name:        "timelock",
			Title:       "Timelock",
			Description: "Nothing can be spent or rekeyed until a chosen round.",
			Fixed: map[string]string{
				ParameterSpendEffects:   allTransfers,
				ParameterRekeyAuthority: RekeySpendingKey,
			},
			Fields: []string{ParameterUnlockRound},
		},
	}
}

// SampleValues are what an operator supplies to a preset.
type SampleValues struct {
	Recipients  []string
	AdminKey    string // path to a public .adm.json envelope
	Cosigner    string
	UnlockRound string
}

// SampleBoundaryFile renders the preset as a boundary file with the operator's
// values filled in. It writes only the fields the preset uses.
func (p Preset) SampleBoundaryFile(values SampleValues) string {
	var sb strings.Builder
	sb.WriteString("schema: " + SchemaV1 + "\n")
	sb.WriteString("spend: [" + strings.ReplaceAll(p.Fixed[ParameterSpendEffects], ",", ", ") + "]\n")
	if slices.Contains(p.Fields, ParameterRecipients) {
		sb.WriteString("recipients:\n")
		for _, recipient := range values.Recipients {
			sb.WriteString("  - " + recipient + "\n")
		}
		sb.WriteString("encoding: " + p.Fixed[ParameterListEncoding] + "\n")
	}
	sb.WriteString("rekey:\n  authority: " + p.Fixed[ParameterRekeyAuthority] + "\n")
	if p.Fixed[ParameterRekeyAuthority] == RekeyAdminKey {
		sb.WriteString(fmt.Sprintf("  admin_key: %s\n", values.AdminKey))
	}
	if slices.Contains(p.Fields, ParameterCosigner) {
		sb.WriteString("cosigner: " + values.Cosigner + "\n")
	}
	if slices.Contains(p.Fields, ParameterUnlockRound) {
		sb.WriteString("unlock_round: " + values.UnlockRound + "\n")
	}
	return sb.String()
}
