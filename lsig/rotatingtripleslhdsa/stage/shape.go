// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package stage

import (
	_ "embed"
	"fmt"

	"github.com/aplane-algo/aplane/internal/crypto/slhdsa"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
)

// hypertree is everything about a stage that follows from the hypertree
// height: the parameter set, how the SLH-DSA signature is split into
// arguments, the frozen template and its source, and the measured cost
// model. One value per supported rotatingkey.RotatingSlhdsaHeight; selected
// picks the one the binary is built with.
type hypertree struct {
	params *slhdsa.Params
	// chunks are the SLH-DSA signature's argument sizes in order: R with
	// the FORS signature first, then the hypertree layers in as few
	// arguments as the AVM's 4096-byte value limit allows.
	chunks   []int
	teal     string
	template []byte
	// base and step are the verifier's exact accepting cost,
	// base + step * chain steps, measured against node traces.
	base, step int
}

var (
	//go:embed verifier_h20.teal
	tealH20 string
	//go:embed verifier_h63.teal
	tealH63 string
)

var hypertrees = map[int]hypertree{
	20: {
		params:   &slhdsa.Rescaled128,
		chunks:   []int{ForsChunkSize, 2 * (slhdsa.WotsSignatureSize + 10*slhdsa.N)},
		teal:     tealH20,
		template: templateH20,
		base:     26645,
		step:     41,
	},
	63: {
		params:   &slhdsa.SHA2128s,
		chunks:   []int{ForsChunkSize, 4 * (slhdsa.WotsSignatureSize + 9*slhdsa.N), 3 * (slhdsa.WotsSignatureSize + 9*slhdsa.N)},
		teal:     tealH63,
		template: templateH63,
		base:     40888,
		step:     41,
	},
}

var selected = func() hypertree {
	h, ok := hypertrees[rotatingkey.RotatingSlhdsaHeight]
	if !ok {
		panic(fmt.Sprintf("rotating slhdsa stage: no frozen shape for hypertree height %d", rotatingkey.RotatingSlhdsaHeight))
	}
	return h
}()

// Params is the SLH-DSA parameter set every stage signs and verifies
// under, selected by rotatingkey.RotatingSlhdsaHeight.
var Params = selected.params

// ChunkSizes are the sizes of the SLH-DSA signature's arguments, in order.
// The Ed25519 and Falcon signatures follow as the next two arguments.
var ChunkSizes = selected.chunks

// SLHSignatureSize is the whole SLH-DSA signature, the sum of ChunkSizes.
var SLHSignatureSize = func() int {
	n := 0
	for _, c := range ChunkSizes {
		n += c
	}
	return n
}()

// MaxArgumentBytes bounds every spend's LogicSig arguments.
var MaxArgumentBytes = SLHSignatureSize + Ed25519SignatureSize + FalconSignatureMaxSize

// template is the frozen assembly of the selected shape's TEAL source with
// placeholder constants; UnsaltedProgramSize is its size and
// SaltedProgramSize adds the three-byte intcblock tail.
var (
	template            = selected.template
	UnsaltedProgramSize = len(template)
	SaltedProgramSize   = UnsaltedProgramSize + saltTailSize
)

// tealSource returns the TEAL source of the shape built for height h with
// keys substituted; TEALSource uses the selected shape.
func tealSource(h int, keys *PublicKeys) (string, bool) {
	t, ok := hypertrees[h]
	if !ok {
		return "", false
	}
	return substitute(t.teal, keys), true
}
