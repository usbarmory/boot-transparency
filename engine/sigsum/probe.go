// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package sigsum

// Define the set of inputs required to probe for an inclusion proof
// for a given leaf to a Sigsum log.
type Probe struct {
	// log origin
	Origin string `json:"origin"`
	// Sigsum uses leaf signature to identify the leaf into the log
	LeafSignature string `json:"leaf_signature"`
	// log key hash in hex format as expected in Sigsum proof bundle
	LogPublicKeyHash string `json:"log_public_key_hash"`
	// submitter key hash in hex format as expected in Sigsum proof bundle
	SubmitPublicKeyHash string `json:"submit_public_key_hash"`
	// The LeafHash is not present as it is computed hashing the statement
	// included in the proof bundle.
	// LeafHash []byte    `json:"leafHash"`
}
