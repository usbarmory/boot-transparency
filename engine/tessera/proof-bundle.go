// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package tessera

import (
	"encoding/json"
)

// ProofBundle represents a Tessera proof bundle.
type ProofBundle struct {
	// Proof bundle format.
	Format uint `json:"format"`

	// Logged claims.
	Statement json.RawMessage `json:"statement"`

	// Probing data required to request a fresh proof bundle to the public log.
	Probe Probe `json:"probe,omitempty"`

	// Tessera stores inclusion proof as [][]byte.
	Proof []string `json:"proof,omitempty"`
}
