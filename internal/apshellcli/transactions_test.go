// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"errors"
	"testing"

	"github.com/aplane-algo/aplane/internal/apshellapp"
)

func TestCheckedValidateResultReturnsResolveError(t *testing.T) {
	want := errors.New("failed to resolve account")

	result, err := checkedValidateResult(nil, want)
	if result != nil {
		t.Fatalf("result = %#v, want nil", result)
	}
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}

func TestCheckedValidateResultAcceptsPartialResultWithError(t *testing.T) {
	want := &apshellapp.ValidateCommandResult{Input: "@set"}

	result, err := checkedValidateResult(want, errors.New("1 validation failed"))
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if result != want {
		t.Fatalf("result = %#v, want %#v", result, want)
	}
}

func TestCheckedValidateResultRejectsNilResultWithoutError(t *testing.T) {
	result, err := checkedValidateResult(nil, nil)
	if result != nil {
		t.Fatalf("result = %#v, want nil", result)
	}
	if err == nil {
		t.Fatal("err = nil, want error")
	}
}
