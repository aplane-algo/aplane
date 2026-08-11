// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package falconparams

import (
	"testing"

	"github.com/algorand/falcon"
)

func TestUpstreamFalconSizes(t *testing.T) {
	t.Parallel()

	if PublicKeySize != falcon.PublicKeySize {
		t.Fatalf("PublicKeySize = %d, upstream = %d", PublicKeySize, falcon.PublicKeySize)
	}
	if PrivateKeySize != falcon.PrivateKeySize {
		t.Fatalf("PrivateKeySize = %d, upstream = %d", PrivateKeySize, falcon.PrivateKeySize)
	}
	if CompressedSignatureMaxSize != falcon.SignatureMaxSize {
		t.Fatalf("CompressedSignatureMaxSize = %d, upstream = %d", CompressedSignatureMaxSize, falcon.SignatureMaxSize)
	}
}
