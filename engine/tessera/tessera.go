// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package tessera

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/client"
	"github.com/usbarmory/boot-transparency/transparency"
	"golang.org/x/mod/sumdb/note"
)

// Defines the Tessera transparency engine and its configuration parameters.
type TesseraEngine struct {
	// List of trusted public keys to verify log signatures.
	logPubkey []string

	// The witness policy, the actual format should be aligned with
	// the one supported one by the chosen transparency engine.
	witnessPolicy *tessera.WitnessGroup
}

func init() {
	e := TesseraEngine{}
	transparency.Add(&e, transparency.Tessera)
}

func (e *TesseraEngine) GetProof(proofBundle interface{}) ([]byte, error) {
	var logReadBaseURL *url.URL
	var logReadCP client.CheckpointFetcherFunc
	var logReadTile client.TileFetcherFunc

	if _, ok := proofBundle.(*ProofBundle); !ok {
		return nil, fmt.Errorf("invalid·proof bundle for Tessera engine")
	}

	pb := proofBundle.(*ProofBundle)

	// Validate the correctness of the proof bundle format.
	if pb.Format != transparency.Tessera {
		return nil, fmt.Errorf("invalid bundle format %q, expected %q (transparency.Tessera)", pb.Format, transparency.Tessera)
	}

	if e.witnessPolicy == nil {
		return nil, fmt.Errorf("witness policy not configured")
	}

	if len(e.logPubkey) == 0 {
		return nil, fmt.Errorf("log public key is not set")
	}

	// Validate the trustworthiness of the log key included in the proof probe.
	lk, err := getTrustedKey(e.logPubkey, pb.Probe.LogPublicKey)

	if err != nil {
		return nil, fmt.Errorf("log public key is not trusted %q", pb.Probe.LogPublicKey)
	}

	logVerifier, err := note.NewVerifier(lk)

	if err != nil {
		return nil, fmt.Errorf("failed to load log public key, %w", err)
	}

	logReadBaseURL, err = url.Parse(pb.Probe.Origin)
	if err != nil {
		return nil, fmt.Errorf("invalid log origin, %w", err)
	}

	switch logReadBaseURL.Scheme {
	case "http", "https":
		hf, err := client.NewHTTPFetcher(logReadBaseURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create an http fetcher, %w", err)
		}
		logReadCP = hf.ReadCheckpoint
		logReadTile = hf.ReadTile
	case "file":
		ff := client.FileFetcher{Root: logReadBaseURL.Path}
		logReadCP = ff.ReadCheckpoint
		logReadTile = ff.ReadTile
	default:
		return nil, fmt.Errorf("unsupported url scheme: %s", logReadBaseURL.Scheme)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(30*time.Second))
	defer cancel()

	// Get the latest checkpoint.
	// Previous checkpoint (third argument) is passed as nil, thus the tracker function will
	// "only" fetch the latest checkpoint and will not return any consistency proof.
	//lst, err := client.NewLogStateTracker(ctx, logReadTile, nil, logVerifier, probe.Origin, client.UnilateralConsensus(logReadCP))
	//if err != nil {
	//	return fmt.Errorf("tessera client: %v", err)
	//}

	// Verify that checkpoint co-signatures are satisfying the witness policy.
	cp, rawcp, _, err := client.FetchCheckpoint(ctx, logReadCP, logVerifier, pb.Probe.Origin)
	if err != nil {
		return nil, fmt.Errorf("failed to get the latest checkpoint, %w", err)
	}

	if !e.witnessPolicy.Satisfied(rawcp) {
		return nil, fmt.Errorf("invalid checkpoint, %w", err)
	}

	// Creates the proof builder that will be used to assemble proofs
	// according with the passed (i.e. latest) checkpoint.
	pBuilder, err := client.NewProofBuilder(ctx, cp.Size, logReadTile)

	if err != nil {
		return nil, fmt.Errorf("tessera proof builder, %w", err)
	}

	// Get the inclusion proof given the latest checkpoint.
	ip, err := pBuilder.InclusionProof(ctx, pb.Probe.LeafIdx)

	if err != nil {
		return nil, fmt.Errorf("failed to get inclusion proof, %w", err)
	}

	// JSON marshalling is required to ensure the message has been logged
	// independently from its formatting (i.e. indent spaces, or tabs,
	// that would be present in human-readable statement JSON).
	statement, err := json.Marshal(pb.Statement)

	if err != nil {
		return nil, err
	}

	leafHash := rfc6962.DefaultHasher.HashLeaf(fmt.Append(nil, statement))

	// Verify the inclusion proof is valid.
	if err = proof.VerifyInclusion(rfc6962.DefaultHasher, pb.Probe.LeafIdx, cp.Size, leafHash, ip, cp.Hash); err != nil {
		return nil, fmt.Errorf("invalid inclusion proof, %w", err)
	}

	// Tessera stores inclusion proof(s) as array of byte arrays ([][]byte)
	// but p.Proof is json.RawMessage which is defined as []byte.
	builtProof, err := json.Marshal(ip)

	if err != nil {
		return nil, err
	}

	return builtProof, nil
}

func (e *TesseraEngine) ParseWitnessPolicy(wp []byte) (interface{}, error) {
	p, err := tessera.NewWitnessGroupFromPolicy(wp)

	if err != nil {
		return nil, err
	}

	return &p, err
}

func (e *TesseraEngine) SetKey(logKey []string, submitKey []string) (err error) {
	// Reset any previously stored key.
	e.logPubkey = []string{}

	// Parse and load log public key(s) that needs to be compliant with note format.
	for _, k := range logKey {
		_, err = note.NewVerifier(k)

		if err != nil {
			return
		}

		e.logPubkey = append(e.logPubkey, k)
	}

	return
}

func (e *TesseraEngine) SetWitnessPolicy(wp interface{}) (err error) {
	if _, ok := wp.(*tessera.WitnessGroup); !ok {
		return fmt.Errorf("invalid policy, type assertion to Tessera *tessera.WitnessGroup failed")
	}

	e.witnessPolicy = wp.(*tessera.WitnessGroup)

	return
}

func (e *TesseraEngine) ResetWitnessPolicy() {
	e.witnessPolicy = nil
}

func (e *TesseraEngine) VerifyProof(proofBundle interface{}) (err error) {
	if _, ok := proofBundle.(*ProofBundle); !ok {
		return fmt.Errorf("invalid proof bundle for Tessera engine")
	}

	pb := proofBundle.(*ProofBundle)

	// Validate the correctness of the proof bundle format.
	if pb.Format != transparency.Tessera {
		return fmt.Errorf("invalid bundle format %q, expected %q (transparency.Tessera)", pb.Format, transparency.Tessera)
	}

	// Load the statement and compute its checksum, which is the leaf hash
	// JSON marshal is required to ensure the message has been logged
	// independently from its formatting (i.e. indent spaces, or tabs,
	// that would be present in human-readable statement JSON).
	statement, err := json.Marshal(pb.Statement)

	if err != nil {
		return
	}

	leafHash := rfc6962.DefaultHasher.HashLeaf(statement)

	// Validate the trustworthiness of the log key included in the proof probe.
	if len(e.logPubkey) == 0 {
		return fmt.Errorf("log public key is not set")
	}

	// Convert the inclusion proof, from []string to [][]byte
	// as expected by Tessera.
	ip := inclusionProofFromJSON(pb.Proof)

	// Traverse all log keys and attempt to verify the proof.
	for _, logKey := range e.logPubkey {
		// FIXME this is not a valid check confirming that the log key
		// actually used to sign the inclusion proof is a trusted one.
		// witness group must be satisfied when verifying co-signatures
		//  on the tree head
		if logKey != pb.Probe.LogPublicKey {
			err = fmt.Errorf("unknown log public key")
			continue // Try the next trusted log key.
		}

		err = proof.VerifyInclusion(rfc6962.DefaultHasher, pb.Probe.LeafIdx, pb.Probe.TreeSize, leafHash, ip, pb.Probe.Root)

		if err != nil {
			continue // Try proof verification with the next log key, if any.
		}
	}

	return
}

func (e *TesseraEngine) ParseProof(jsonProofBundle []byte) (interface{}, []byte, error) {
	var pb ProofBundle

	if err := json.Unmarshal(jsonProofBundle, &pb); err != nil {
		return nil, nil, err
	}

	// Do not parse the statement, only focus on the inclusion proof
	// and the probing data.

	// Validate the correctness of the proof bundle format.
	if pb.Format != transparency.Tessera {
		return nil, nil, fmt.Errorf("invalid bundle format %q, expected %q (transparency.Tessera)", pb.Format, transparency.Tessera)
	}

	// The inclusion proof is not present in the bundle, nothing to parse there.
	if pb.Proof != nil {
		// Parse the inclusion proof.
		// Tessera uses [][]byte to store inclusion proof(s). However, the
		// proof is stored as []string in the proof bundle JSON.
		// Traverse the proof array to ensure it is containing only valid base64 string(s).
		for _, entry := range pb.Proof {
			d, err := base64.StdEncoding.DecodeString(entry)

			if err != nil {
				return nil, nil, fmt.Errorf("unable to parse Tessera inclusion proof, %w", err)
			}

			// Tessera inclusion proof is an array of 32 bytes arrays
			// this further check is necessary to spot-out any proof entry
			// that could have passed the base64 decoding but that is not
			// resulting in a byte array compliant with the length requirement.
			if len(d) != 32 {
				return nil, nil, fmt.Errorf("unable to parse Tessera inclusion proof, invalid base64 entry: %q", entry)
			}
		}
	}

	// Return also the JSON marshal version of the bundle.
	pbMarshal, err := json.MarshalIndent(&pb, "", "\t")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal the proof bundle, %w", err)
	}

	return &pb, pbMarshal, nil
}

// Search for a public key among a set of trusted ones.
func getTrustedKey(trusted []string, probe string) (string, error) {
	_, err := note.NewVerifier(probe)

	if err != nil {
		return "", fmt.Errorf("invalid public key %q, %w", probe, err)
	}

	for _, t := range trusted {
		_, err := note.NewVerifier(t)

		// Return immediately when encountering an invalid public key.
		if err != nil {
			return "", fmt.Errorf("invalid public key %q, %w", t, err)
		}

		if t == probe {
			return t, nil
		} else {
			continue // Try if the next trusted key matches.
		}
	}

	return "", fmt.Errorf("public key is not matching any of the trusted keys")
}

// Convert the inclusion proof from what is provided in the JSON
// proof bundle (i.e. []string) to what Tessera functions expects
// to verify the inclusion proof (i.e. [][]byte).
func inclusionProofFromJSON(pbProof []string) [][]byte {
	tesseraProof := make([][]byte, len(pbProof))

	for i, v := range pbProof {
		tesseraProof[i] = []byte(v)
	}

	return tesseraProof
}
