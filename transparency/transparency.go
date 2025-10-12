// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package transparency

import (
	"encoding/json"
)

// Define the transparency proof bundle which includes:
// - the statement (i.e. claims)
// - the logged statement identifier (i.e. log leaf identifier)
// - the inclusion proof
type ProofBundle struct {
	// serialized JSON of Statement struct
	Statement []byte `json:"statement"`

	// serialized inclusion proof probing data,
	// its format depends by the transparency engine
	Probe json.RawMessage `json:"probe"`

	// inclusion proof, its format depends by the transparency engine
	Proof json.RawMessage `json:"proof"`
}

// Define high-level interface for transparency layer.
//
// This interface abstracts the functionalities implemented by
// the underlying transparency engine.
type TransparencyEngine interface {
	// Request to the public log the information required to assemble a
	// proof bundle.
	// The public log is identified via its origin while the information
	// from ProofBundle allow to assemble the request for the log leaf.
	// This function does not require any previous log status (i.e. checkpoint).
	// The latest signed tree-head is fetched from the log along with the leaf
	// inclusion proof.
	// The inclusion proof is returned by updating the ProofBundle
	//
	// Return error if:
	//   - the transparency engine is configured off-line
	//   - the log key is not configured
	//   - the submitter key is not configured
	//   - the statement leaf is not present in the log
	//   - any other error is returned by the public log
	GetProof(p *ProofBundle) error

	// Parse the witness policy according with the format expected by the
	// chosen transparency engine.
	// Return error if:
	//   - the parsing of the policy fails
	ParseWitnessPolicy(wp []byte) (interface{}, error)

	// Set log and submitter keys that will be used by the transparency
	// engine to fetch, or verify, the proof.
	// Return error if:
	//    - the parsing of the public keys fails
	SetKey(logKey []string, submitKey []string) error

	// Set the witness policy for the transparency engine.
	// The function expects in input a policy as returned by ParseWitnessPolicy()
	// Return error if:
	//   - the parsing of the policy fails
	SetWitnessPolicy(wp interface{}) error

	// Verify the proof of the log.
	// Return error if:
	//    - the proof verification fails
	//    - the parsing of the proof bundle fails
	//    - public keys for log, submitter or cosigners are not set
	//    - the witness signing quorum is not reached
	VerifyProof(p *ProofBundle) error
}
