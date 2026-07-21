// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package witness

import (
	"errors"
	"testing"
)

func TestPairValidatorRegistration(t *testing.T) {
	const keyType = "aplane.witness-test.v1"
	want := errors.New("pair rejected")
	RegisterPairValidator(keyType, func(_, _ []byte) error { return want })
	RegisterPairValidator(keyType, func(_, _ []byte) error { return nil })
	if err := ValidatePair(keyType, nil, nil); !errors.Is(err, want) {
		t.Fatalf("ValidatePair() error = %v, want %v", err, want)
	}
	if err := ValidatePair("aplane.missing.v1", nil, nil); err == nil {
		t.Fatal("ValidatePair() accepted unregistered key type")
	}
}
