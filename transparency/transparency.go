// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package transparency

import (
	"encoding/json"
	"fmt"
)

// Supported transparency engines
const (
	Sigsum uint = iota + 0x0001
	Tessera
)

// Define the transparency proof bundle which includes:
// - the bundle format (i.e. sigsum, tessera)
// - the logged statement (i.e. claims)
// - the probing data to request the inclusion proof to the log
// - the inclusion proof
type ProofBundle struct {
	// specify which transparency engine should be used to
	// verify this proof (i.e. Sigsum, Tessera)
	Format uint `json:"format"`

	// serialized JSON of Statement struct
	Statement []byte `json:"statement"`

	// serialized inclusion proof probing data,
	// its format depends by the chosen transparency engine
	Probe json.RawMessage `json:"probe,omitempty"`

	// inclusion proof, its format depends by the chosen
	// transparency engine
	Proof json.RawMessage `json:"proof,omitempty"`
}

// Define high-level interface for transparency layer.
//
// This interface abstracts the functionalities implemented by
// the underlying transparency engine.
type Engine interface {
	// Request to the public log the information required to assemble a
	// proof bundle.
	// The public log is identified via its origin while the information
	// from ProofBundle allow to assemble the request for the log leaf.
	// The function expects as input a ProofBundle as returned by ProofParse().
	// The function does not require any previous log status (i.e. checkpoint).
	// The latest signed tree-head is fetched from the log along with the leaf
	// inclusion proof.
	// The inclusion proof is returned as []byte where its actual
	// content depends by the chosen transparency engine.
	//
	// Return error if:
	//   - the transparency engine is configured off-line
	//   - the log key is not configured
	//   - the submitter key is not configured
	//   - the statement leaf is not present in the log
	//   - any other error is returned by the public log
	GetProof(proofBundle interface{}) ([]byte, error)

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

	// Reset the witness policy for the transparency engine.
	ResetWitnessPolicy()

	// Verify the proof of the log, expects an input proof bundle
	// as returned by ParseProof().
	// Return error if:
	//    - the proof verification fails
	//    - the parsing of the proof bundle fails
	//    - public keys for log, submitter or cosigners are not set
	//    - the witness signing quorum is not reached
	VerifyProof(proofBundle interface{}) error

	// Parse the probing data, and the inclusion proof (if present)
	// of a given proof bundle in JSON format, return the proof bundle
	// as expected by the given transparency engine.
	// The function also return, as second value, a JSON marshal
	// version of the parsed proof bundle.
	// Return error if the parsing fails.
	ParseProof(jsonProofBundle []byte) (interface{}, []byte, error)
}

// Define the list of registered transparency engines
var engines = make(map[uint]*Engine)

// Register a transparency engine
func Add(e Engine, t uint) {
	engines[t] = &e
}

// Return the registered transparency engine, if present
func GetEngine(t uint) (Engine, error) {
	e := engines[t]
	if e == nil {
		return nil, fmt.Errorf("Transparency engine not registered")
	}

	return *e, nil
}
