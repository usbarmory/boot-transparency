// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package tessera

// Simplified version of the Tessera inclusionProbe structure
type Probe struct {
	// Log origin is needed to probe the correct log where
	// the leaf has been logged to
	Origin string `json:"origin"`
	// Leaf index
	LeafIdx uint64 `json:"leafIdx"`
	// Tree size
	TreeSize uint64 `json:"treeSize"`
	// Root hash
	Root []byte `json:"root"`
	// the LeafHash is not present as it is computed hashing
	// the ProofBundle.Statement.
	// LeafHash []byte   `json:"leafHash"`
	// Log public key is needed to verify that the proof is
	// signed with a trusted log key
	LogPublicKey string `json:"log_public_key"`
}
