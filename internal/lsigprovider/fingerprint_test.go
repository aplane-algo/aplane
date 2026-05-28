// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package lsigprovider

import "testing"

func TestProjectParameterDefDropsDisplayFields(t *testing.T) {
	min := uint64(1)
	max := uint64(9)
	got := ProjectParameterDef(ParameterDef{
		Name:        "amount",
		Label:       "Amount",
		Description: "Display-only description",
		Type:        "uint64",
		Required:    true,
		MaxLength:   20,
		InputModes:  []InputMode{{Name: "raw", Label: "Raw"}},
		MinItems:    2,
		MaxItems:    4,
		Example:     "5",
		Placeholder: "Enter amount",
		Min:         &min,
		Max:         &max,
		Default:     "5",
	})

	if got.Name != "amount" || got.Type != "uint64" || !got.Required || got.MaxLength != 20 ||
		got.MinItems != 2 || got.MaxItems != 4 || got.Min == nil || *got.Min != min ||
		got.Max == nil || *got.Max != max || got.Default != "5" {
		t.Fatalf("ProjectParameterDef() = %#v", got)
	}
}

func TestProjectRuntimeArgDefDropsDisplayFields(t *testing.T) {
	got := ProjectRuntimeArgDef(RuntimeArgDef{
		Name:        "preimage",
		Label:       "Preimage",
		Description: "Display-only description",
		Type:        "bytes",
		Required:    true,
		ByteLength:  32,
	})

	if got.Name != "preimage" || got.Type != "bytes" || !got.Required || got.ByteLength != 32 {
		t.Fatalf("ProjectRuntimeArgDef() = %#v", got)
	}
}

func TestHashCompatibilitySpecPanicsOnInvalidSpec(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("HashCompatibilitySpec() did not panic for an unmarshable canonical spec")
		}
	}()

	HashCompatibilitySpec(struct {
		Bad func() `json:"bad"`
	}{})
}
