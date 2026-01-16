// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package sigsum

// Probe represents the data required to request (i.e. probe) an inclusion proof
// for a given leaf to a Sigsum log.
type Probe struct {
	// Origin represents the log origin.
	Origin string `json:"origin"`

	// LeafSignature represents the leaf signature, used by Sigsum
	// to identify the leaf into the log.
	LeafSignature string `json:"leaf_signature"`

	// LogPublicKeyHash represents the log key hash in hex format as expected
	// in Sigsum proof bundle.
	LogPublicKeyHash string `json:"log_public_key_hash"`

	// SubmitPublicKeyHash represents the submitter key hash in hex format
	// as expected in Sigsum proof bundle.
	SubmitPublicKeyHash string `json:"submit_public_key_hash"`

	// LeafHash represents the leaf hash, this field is commented out as
	// the leaf hash is computed from the actual statement included in
	// the proof bundle.
	// LeafHash []byte    `json:"leafHash"`
}
