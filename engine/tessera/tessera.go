// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package tessera

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	m_proof "github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/client"
	"github.com/usbarmory/boot-transparency/transparency"
	"golang.org/x/mod/sumdb/note"
)

// TesseraEngine represents the Tessera transparency engine and its configuration parameters.
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

// GetProof implements transparency.GetProof() for the Tessera engine.
func (e *TesseraEngine) GetProof(statement []byte, probe []byte) (proof []byte, err error) {
	var p Probe
	var logReadBaseURL *url.URL
	var logReadCP client.CheckpointFetcherFunc
	var logReadTile client.TileFetcherFunc

	if err = json.Unmarshal(probe, &p); err != nil {
		return nil, fmt.Errorf("invalid probe data")
	}

	if e.witnessPolicy == nil {
		return nil, fmt.Errorf("witness policy not configured")
	}

	if len(e.logPubkey) == 0 {
		return nil, fmt.Errorf("log public key is not set")
	}

	// Validate the trustworthiness of the log key included in the proof probe.
	lk, err := getTrustedKey(e.logPubkey, p.LogPublicKey)

	if err != nil {
		return nil, fmt.Errorf("log public key is not trusted %q", p.LogPublicKey)
	}

	logVerifier, err := note.NewVerifier(lk)

	if err != nil {
		return nil, fmt.Errorf("failed to load log public key, %w", err)
	}

	logReadBaseURL, err = url.Parse(p.Origin)
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
	cp, rawcp, _, err := client.FetchCheckpoint(ctx, logReadCP, logVerifier, p.Origin)
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
	ip, err := pBuilder.InclusionProof(ctx, p.LeafIdx)

	if err != nil {
		return nil, fmt.Errorf("failed to get inclusion proof, %w", err)
	}

	// JSON marshalling is required to ensure the message has been logged
	// independently from its formatting (i.e. indent spaces, or tabs,
	// that would be present in human-readable statement JSON).
	leafHash := rfc6962.DefaultHasher.HashLeaf(fmt.Append(nil, statement))

	// Verify the inclusion proof is valid.
	if err = m_proof.VerifyInclusion(rfc6962.DefaultHasher, p.LeafIdx, cp.Size, leafHash, ip, cp.Hash); err != nil {
		return nil, fmt.Errorf("invalid inclusion proof, %w", err)
	}

	// Tessera stores inclusion proof(s) as array of byte arrays ([][]byte)
	// but p.Proof is json.RawMessage which is defined as []byte.
	proof, err = json.Marshal(ip)

	if err != nil {
		return nil, fmt.Errorf("failed to assemble the proof bundle, %w", err)
	}

	return
}

// SetKey implements transparency.SetKey() for the Tessera engine.
// Tessera supports Ed25519 public keys in sumdb note format:
// https://pkg.go.dev/golang.org/x/mod/sumdb/note
func (e *TesseraEngine) SetKey(logKey []byte, submitKey []byte) (err error) {
	// Reset any previously stored key.
	e.logPubkey = []string{}

	// Parse and load log public key(s).
	logKey = bytes.Trim(logKey, "\n")
	logKeys := bytes.Split(logKey, []byte("\n"))
	for _, k := range logKeys {
		lk := string(k)
		_, err = note.NewVerifier(lk)

		if err != nil {
			return
		}

		e.logPubkey = append(e.logPubkey, lk)
	}

	return
}

// SetWitnessPolicy implements transparency.SetWitnessPolicy for the Tessera engine.
func (e *TesseraEngine) SetWitnessPolicy(wp []byte) (err error) {
	if wp == nil {
		e.witnessPolicy = nil
		return
	}

	p, err := tessera.NewWitnessGroupFromPolicy(wp)
	if err != nil {
		return
	}

	e.witnessPolicy = &p
	return
}

// VerifyProof implements transparency.VerifyProof() for the Tessera engine.
func (e *TesseraEngine) VerifyProof(statement []byte, proof []byte, probe []byte) (err error) {
	var p Probe

	// Tessera, more specifically the merkle proof verification function,
	// requires the leaf index, probing root hash and tree size to verify the inclusion proof.
	if err = json.Unmarshal(probe, &p); err != nil {
		err = fmt.Errorf("invalid probe data, %w", err)
		return
	}

	// Load the statement and compute its checksum, which is the leaf hash
	// JSON marshal is required to ensure the message has been logged
	// independently from its formatting (i.e. indent spaces, or tabs,
	// that would be present in human-readable statement JSON).
	leafHash := rfc6962.DefaultHasher.HashLeaf(statement)

	// Validate the trustworthiness of the log key included in the proof probe.
	if len(e.logPubkey) == 0 {
		return fmt.Errorf("log public key is not set")
	}

	// Convert the inclusion proof, from []byte to [][]byte
	// as expected by Tessera.
	parsedProof, err := e.parseProof(proof)
	if err != nil {
		return
	}

	ip := inclusionProofFromJSON(parsedProof)

	// Traverse all log keys and attempt to verify the proof.
	for _, logKey := range e.logPubkey {
		// FIXME this is not a valid check confirming that the log key
		// actually used to sign the inclusion proof is a trusted one.
		// witness group must be satisfied when verifying co-signatures
		//  on the tree head
		if logKey != p.LogPublicKey {
			err = fmt.Errorf("unknown log public key")
			continue // Try the next trusted log key.
		}

		err = m_proof.VerifyInclusion(rfc6962.DefaultHasher, p.LeafIdx, p.TreeSize, leafHash, ip, p.Root)

		if err != nil {
			continue // Try proof verification with the next log key, if any.
		}
	}

	return
}

// parseProof implements the proof parsing for Tessera engine.
// Tessera internally stores the proof as [][]byte.
func (e *TesseraEngine) parseProof(jsonProof []byte) (proof []string, err error) {
	var pb ProofBundle

	if err = json.Unmarshal(jsonProof, &pb.Proof); err != nil {
		return
	}

	// The inclusion proof is not present in the bundle, nothing to parse there.
	if pb.Proof != nil {
		// Parse the inclusion proof.
		// Tessera uses [][]byte to store inclusion proof(s). However, the
		// proof is stored as []string in the proof bundle JSON.
		// Traverse the proof array to ensure it is containing only valid base64 string(s).
		for _, entry := range pb.Proof {
			d, err := base64.StdEncoding.DecodeString(string(entry))

			if err != nil {
				return nil, fmt.Errorf("unable to parse Tessera inclusion proof, %w", err)
			}

			// Tessera inclusion proof is an array of 32 bytes arrays
			// this further check is necessary to spot-out any proof entry
			// that could have passed the base64 decoding but that is not
			// resulting in a byte array compliant with the length requirement.
			if len(d) != 32 {
				return nil, fmt.Errorf("unable to parse Tessera inclusion proof, invalid base64 entry: %q", entry)
			}
		}
	}
	proof = pb.Proof

	return
}

// getTrustedKey search for a public key among a set of trusted ones.
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

// inclusionProofFromJSON converts the inclusion proof from what is provided
// in the JSON proof bundle (i.e. []string) to what Tessera functions expects
// to verify the inclusion proof (i.e. [][]byte).
func inclusionProofFromJSON(pbProof []string) [][]byte {
	tesseraProof := make([][]byte, len(pbProof))

	for i, v := range pbProof {
		tesseraProof[i] = []byte(v)
	}

	return tesseraProof
}
