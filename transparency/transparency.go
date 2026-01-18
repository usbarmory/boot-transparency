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

type EngineCode uint

// Supported transparency engines.
const (
	Sigsum EngineCode = iota + 0x0001
	Tessera
)

// Resolve resolves transparency engine codes into a human-readable strings.
func (e EngineCode) Resolve() string {
	name := map[EngineCode]string{
		Sigsum:  "Sigsum",
		Tessera: "Tessera",
	}

	return name[e]
}

// ProofBundle represents the transparency proof bundle.
type ProofBundle struct {
	// Format represents the transparency engine that should be used to
	// verify this proof bundle (i.e. Sigsum, Tessera).
	Format EngineCode `json:"format"`

	// Statement represents a serialized JSON of the Statement structure
	// which includes the logged claims for a given bundle.
	Statement json.RawMessage `json:"statement"`

	// Probe represents a serialized probing data, its format depends
	// by the chosen transparency engine.
	// This information is used to request the inclusion proof from the remote log.
	Probe json.RawMessage `json:"probe,omitempty"`

	// Proof represents the inclusion proof, its format depends by the chosen
	// transparency engine.
	Proof json.RawMessage `json:"proof,omitempty"`
}

// Engine represents a high-level interface for transparency layer.
//
// This interface abstracts the functionalities implemented by
// the underlying transparency engine.
type Engine interface {
	// GetProof request to the public log the data required to
	// assemble a proof bundle.
	// The public log is identified via its origin while the information
	// from ProofBundle allow to prepare the request of the correspondent log leaf.
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
	//   - any other error is returned by the public log.
	GetProof(proofBundle interface{}) ([]byte, error)

	// ParseWitnessPolicy parses the witness policy according with the format
	// expected by thecchosen transparency engine.
	//
	// Return error if:
	//   - the parsing of the policy fails.
	ParseWitnessPolicy(wp []byte) (interface{}, error)

	// SetKey sets the log and submitter keys that will be used by the
	// transparency engine to fetch, or verify, the proof.
	//
	// Return error if:
	//    - the parsing of the public keys fails.
	SetKey(logKey []string, submitKey []string) error

	// SetWitnessPolicy sets the witness policy for the transparency engine.
	// The function expects in input a policy as returned by ParseWitnessPolicy().
	//
	// Return error if:
	//   - the parsing of the policy fails.
	SetWitnessPolicy(wp interface{}) error

	// ResetWitnessPolicy resets the witness policy for the transparency engine.
	ResetWitnessPolicy()

	// VerifyProof verifies the proof of the log, expects an input proof bundle
	// as returned by ParseProof().
	//
	// Return error if:
	//    - the proof verification fails
	//    - the parsing of the proof bundle fails
	//    - public keys for log, submitter or cosigners are not set
	//    - the witness signing quorum is not reached.
	VerifyProof(proofBundle interface{}) error

	// ParseProof parses the probing data, and the inclusion proof
	// (if present) of a given proof bundle in JSON format, returns
	// the proof bundle as expected by the chosen transparency engine.
	// The function also returns, as second value, a JSON marshalled
	// version of the parsed proof bundle.
	//
	// Return error if the parsing fails.
	ParseProof(jsonProofBundle []byte) (interface{}, []byte, error)
}

// Define the list of registered transparency engines.
var engines = make(map[EngineCode]*Engine)

// Add a transparency engine.
func Add(e Engine, t EngineCode) {
	engines[t] = &e
}

// GetEngine returns the registered transparency engine, if present.
func GetEngine(t EngineCode) (e Engine, err error) {
	e = *engines[t]

	if e == nil {
		err = fmt.Errorf("transparency engine not registered")
	}
	if t == Tessera {
		err = fmt.Errorf("tessera support is incomplete")
	}

	return e, err
}
