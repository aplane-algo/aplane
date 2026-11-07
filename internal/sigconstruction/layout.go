// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sigconstruction

import "slices"

// ComponentLayout is one component's argument slots.
type ComponentLayout struct {
	Name      string
	Primitive PrimitiveID
	Start     int
	maxSizes  []int
}

// Count returns the component's number of argument slots.
func (l ComponentLayout) Count() int { return len(l.maxSizes) }

// ArgLayout keeps component boundaries. Flattening it into LogicSig arguments is an
// encoding step, and the durable layout stores only the flattened form.
type ArgLayout struct {
	components []ComponentLayout
}

// Components returns the component layouts in order.
func (l ArgLayout) Components() []ComponentLayout {
	out := make([]ComponentLayout, len(l.components))
	for i, component := range l.components {
		out[i] = component
		out[i].maxSizes = slices.Clone(component.maxSizes)
	}
	return out
}

// Count returns the total number of argument slots.
func (l ArgLayout) Count() int {
	total := 0
	for _, component := range l.components {
		total += component.Count()
	}
	return total
}

// MaxSizes returns each slot's maximum size in argument order.
func (l ArgLayout) MaxSizes() []int {
	sizes := make([]int, 0, l.Count())
	for _, component := range l.components {
		sizes = append(sizes, component.maxSizes...)
	}
	return sizes
}
