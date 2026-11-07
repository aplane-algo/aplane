// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import "fmt"

// generateKeyTypesNotLoaded is shown when Enter lands on a type the compiled list
// offers but the signer hasn't classified yet. A list that arrives clears it.
const generateKeyTypesNotLoaded = "The signer's key types have not loaded. Try again."

// reselectKeyTypes keeps the Generate and Import cursors on the types they named
// before a new key-type list replaced the old one. The cursors are indexes, and a
// new list can be shorter or ordered differently (the compiled fallback lists every
// built-in type, the signer's only the enabled ones), so keeping the index would
// silently name another type.
//
// A Generate selection the new list doesn't offer leaves any parameter or preset
// form built on it and needs a fresh choice before Enter acts again. An Import
// selection only opens a mnemonic prompt, so it falls back to the nearest position.
func (m Model) reselectKeyTypes(generate, imp string) Model {
	if i, ok := keyTypeIndex(generate, getKeyTypeCount(), getKeyTypeByIndex); ok {
		m.forms.generateKeyType = i
		if m.forms.generateError == generateKeyTypesNotLoaded {
			m.forms.generateError = ""
		}
	} else {
		m.forms.generateKeyType = clampIndex(m.forms.generateKeyType, getKeyTypeCount())
		if generate != "" {
			m = m.loseGenerateSelection(generate)
		}
	}
	if i, ok := keyTypeIndex(imp, getImportKeyTypeCount(), getImportKeyTypeByIndex); ok {
		m.forms.importKeyType = i
	} else {
		m.forms.importKeyType = clampIndex(m.forms.importKeyType, getImportKeyTypeCount())
	}
	return m
}

// generateSelection names the type the Generate flow is built on. While the preset
// flow is open that is the type it recorded when it started, not whatever the cursor
// index names, so a list refresh partway through (the cosigner picker sends one)
// can't switch the form to another type. Elsewhere it is the cursor's type.
func (m Model) generateSelection() string {
	if m.forms.boundaryKeyType != "" {
		switch m.viewState {
		case ViewBoundaryPreset:
			return m.forms.boundaryKeyType
		case ViewGenerateParams, ViewCosignerPicker:
			if m.forms.boundaryPreset != nil {
				return m.forms.boundaryKeyType
			}
		}
	}
	return getKeyTypeByIndex(m.forms.generateKeyType)
}

// endBoundaryFlow forgets the preset flow's type, preset and file. They outlive the
// account the flow generates, so every flow that chooses a type starts here: the
// type and preset are what generateSelection, the Esc target and the preset's fixed
// values read, and a stale pair would steer a later flow to the earlier type.
func (m Model) endBoundaryFlow() Model {
	m.forms.boundaryPreset = nil
	m.forms.boundaryKeyType = ""
	m.forms.boundaryFile = ""
	m.forms.boundaryFileRequest = false
	return m
}

// loseGenerateSelection handles a Generate selection the signer no longer offers.
// A parameter or preset form for it is abandoned rather than switched to another
// type's form, and the operator has to choose again.
func (m Model) loseGenerateSelection(keyType string) Model {
	switch m.viewState {
	case ViewGenerateParams, ViewBoundaryPreset:
		m = m.endBoundaryFlow()
		m.forms.genericLSigParams = nil
		m.viewState = ViewGenerateForm
	case ViewGenerateForm:
	default:
		// Other views aren't built on the Generate cursor. Generation in flight and
		// the review screen carry the type the signer prepared.
		return m
	}
	m.forms.generateNeedsChoice = true
	m.forms.generateError = fmt.Sprintf("%s is not offered by the signer. Choose a key type.", displayKeyType(keyType))
	return m
}

func keyTypeIndex(keyType string, count int, at func(int) string) (int, bool) {
	if keyType == "" {
		return 0, false
	}
	for i := 0; i < count; i++ {
		if at(i) == keyType {
			return i, true
		}
	}
	return 0, false
}

func clampIndex(index, count int) int {
	if index >= count {
		index = count - 1
	}
	if index < 0 {
		index = 0
	}
	return index
}
