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
		Sigsum:  "sigsum",
		Tessera: "tessera",
	}

	return name[e]
}

// EngineCodeFromString represents the mapping between a human-readable
// engine name and its correspondent EngineCode.
var EngineCodeFromString = map[string]EngineCode{
	"sigsum":  Sigsum,
	"tessera": Tessera,
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
	// SetKey sets the log and submitter keys that will be used by the
	// transparency engine to fetch, or verify, the proof.
	// The public key format depends by the underlying transparency engine,
	// refer to the SetKey() documentation of the chosen transparency engine.
	// The library allows configuring multiple log and submitter trusted keys,
	// they are expected to be separeted by a single newline byte (i.e. 0x0a)
	// within the whole key blob.
	//
	// Return error if:
	//    - the parsing of the public keys fails.
	SetKey(logKey []byte, submitKey []byte) (err error)

	// SetWitnessPolicy sets the witness policy for the transparency engine.
	// The function accepts as input the witness policy in the format expected
	// by the chosen transparency engine.
	//
	// Return error if:
	//   - the parsing of the policy fails.
	SetWitnessPolicy(witnessPolicy []byte) (err error)

	// GetProof requests to the public log the information required to
	// assemble a proof bundle.
	// The public log is identified via its origin, while the other information
	// from probe allows to prepare the request for the given log leaf.
	// The function expects as input the probing data as returned by ParseProofBundle().
	// The function does not require any previous log status (i.e. checkpoint).
	// The latest signed tree-head is fetched from the log along with the leaf
	// inclusion proof.
	// The statement argument is used to compute the logged message hash.
	// The inclusion proof is returned as []byte, its actual content depends
	// by the chosen transparency engine.
	//
	// Return error if:
	//   - the transparency engine is configured off-line
	//   - the log key is not configured
	//   - the submitter key is not configured
	//   - the statement leaf is not present in the log
	//   - any other error is returned by the public log.
	GetProof(statement []byte, probe []byte) (proof []byte, err error)

	// VerifyProof verifies an inclusion proof against the correspondent logged statement,
	// expects input values (i.e. statement and proof) as returned by ParseProofBundle().
	// Some transparency engine (e.g. Tessera) requires also the probe information to
	// verify the inclusion proof. In all cases where this parameter is not needed, as
	// for example for Sigsum engine, it can be safely be passed as nil.
	//
	// Return error if:
	//    - the proof verification fails
	//    - the parsing of the proof bundle components (i.e. statement and proof) fails
	//    - public keys for log, submitter or cosigners are not set
	//    - the witness signing quorum is not reached.
	VerifyProof(statement []byte, proof []byte, probe []byte) (err error)
}

// Define the list of registered transparency engines.
var engines = make(map[EngineCode]*Engine)

// Add adds a transparency engine.
func Add(e Engine, t EngineCode) {
	engines[t] = &e
}

// GetEngine returns the registered transparency engine, if present.
func GetEngine(t EngineCode) (e Engine, err error) {
	if engines[t] == nil {
		err = fmt.Errorf("transparency engine not registered")
		return
	}

	e = *engines[t]

	if t == Tessera {
		err = fmt.Errorf("tessera support is incomplete")
	}

	return
}

// ParseProofBundle parses a proof bundle in JSON format.
// The function returns the bundle format (i.e. EngineCode) and all its components
// as separated byte arrays (i.e. statement, inclusion proof and probing data).
// The function also returns, as fourth value, a marshalled JSON of the whole
// parsed proof bundle.
//
// Return error if the parsing fails.
func ParseProofBundle(jsonProofBundle []byte) (format EngineCode, statement []byte, proof []byte, probe []byte, bundle []byte, err error) {
	var pb ProofBundle

	if err = json.Unmarshal(jsonProofBundle, &pb); err != nil {
		return
	}

	format = EngineCode(pb.Format)

	statement, err = json.MarshalIndent(&pb.Statement, "", "\t")
	if err != nil {
		err = fmt.Errorf("failed to marshal statement, %w", err)
		return
	}

	probe, err = json.MarshalIndent(&pb.Probe, "", "\t")
	if err != nil {
		err = fmt.Errorf("failed to parse probing data, %w", err)
		return
	}

	proof, err = json.MarshalIndent(&pb.Proof, "", "\t")
	if err != nil {
		err = fmt.Errorf("failed to parse proof data, %w", err)
		return
	}

	// Return also the JSON marshal version of the bundle.
	bundle, err = json.MarshalIndent(&pb, "", "\t")
	if err != nil {
		err = fmt.Errorf("failed to marshal the proof bundle, %w", err)
	}

	return
}
