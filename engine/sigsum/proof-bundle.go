// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package sigsum

import (
	"encoding/json"
)

// Define Sigsum proof bundle structure
// Sigsum stores inclusion proof as []byte
type ProofBundle struct {
	Format    uint            `json:"format"`
	Statement json.RawMessage `json:"statement"`
	Probe     Probe           `json:"probe,omitempty"`
	Proof     string          `json:"proof,omitempty"`
}
