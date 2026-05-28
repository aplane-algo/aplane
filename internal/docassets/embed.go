// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package docassets

import _ "embed"

// UserJSAPI is generated at build/test time by copying docs/USER_JSAPI.md into
// internal/docassets/generated/USER_JSAPI.md via the Makefile.
//
//go:embed generated/USER_JSAPI.md
var UserJSAPI string
