// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package transparency

// Define ProofBundle which contains the statement (i.e. logged claims), the log submitter signature,
// and the transparency proof
type ProofBundle struct {
	// serialized JSON of Statement struct
	Statement []byte

	// submitter signature of logged Statement
	// its format depends by the chosen engine
	Signature string

	// serialized transparency proof.
	// The actual content, and its format, depends by the chosen engine
	Proof []byte
}

// Define high-level interface for transparency layer.
//
// This interface abstracts the functionalities implemented by
// the underlying transparency engine.
type TransparencyEngine interface {
	// Request to the public log the information required to assemble a
	// proof bundle.
	// The public log is identified via its origin while the information
	// from ProofBundle.Statement allow to assemble the request for the log leaf.
	// This function does not require any previous log status (i.e. checkpoint).
	// The latest signed tree-head is fetched from the log along with the leaf
	// inclusion proof.
	//
	// Return error if:
	//   - the transparency engine is configured off-line
	//   - the log key is not configured
	//   - the submitter key is not configured
	//   - the statement leaf is not present in the log
	//   - any other error is returned by the public log
	GetProof(origin string, p *ProofBundle) error

	// Parse the witness policy according with the format expected by the
	// chosen transparency engine.
	// Return error if:
	//   - the parsing of the policy fails
	ParseWitnessPolicy(wp []byte) (interface{}, error)

	// Set log, submitter and cosigner keys that will be used by the transparency
	// engine to fetch, or verify, the proof.
	// Return error if:
	//    - the parsing of the public keys fails
	SetKey(logKey []string, submitKey []string, witnessKey []string) error

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
