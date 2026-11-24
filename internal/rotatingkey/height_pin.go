//go:build !testmode

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rotatingkey

// An ordinary build compiles only at height 22, the height
// aplane.rotating-triple-slhdsa.v1 ships at: a difference either way makes
// one of these constants negative and fails compilation. The height-63
// review build requires -tags testmode (for example, GOFLAGS=-tags=testmode).
const (
	_ = uint(RotatingSlhdsaHeight - 22)
	_ = uint(22 - RotatingSlhdsaHeight)
)
