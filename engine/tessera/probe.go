// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package tessera

// Probe represents the data required to request an inclusion proof
// for a given lead to a Tessera log.
// This structure is a simplified version of the Tessera inclusionProbe
// structure.
type Probe struct {
	// Origin represents the log origin that is needed, during the probing,
	// to identify the correct log where the leaf has been logged to.
	Origin string `json:"origin"`

	// LeafIdx represents the leaf index.
	LeafIdx uint64 `json:"leafIdx"`

	// TreeSize represents the tree size.
	TreeSize uint64 `json:"treeSize"`

	// Root represents the root hash.
	Root []byte `json:"root"`

	// LeafHash represents the leaf hash, this field is commented out as
	// the leaf hash is computed from the actual statement included in
	// the proof bundle.

	// LogPublicKey represents the log public key which is needed to
	// verify that the proof has been signed by a trusted log key.
	LogPublicKey string `json:"log_public_key"`
}
