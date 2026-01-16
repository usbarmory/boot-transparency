// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package tessera

import (
	"encoding/json"
	"github.com/usbarmory/boot-transparency/transparency"
)

// ProofBundle represents a Tessera proof bundle.
type ProofBundle struct {
	// Format represents the proof bundle format.
	Format transparency.EngineCode `json:"format"`

	// Statement represents the logged claims.
	Statement json.RawMessage `json:"statement"`

	// Probe represents the probing data required to request a fresh proof bundle to the public log.
	Probe Probe `json:"probe,omitempty"`

	// Proof represents the Tessera inclusion proof (underlying Tessera stores inclusion proofs as [][]byte).
	Proof []string `json:"proof,omitempty"`
}
