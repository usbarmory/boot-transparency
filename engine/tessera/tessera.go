// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package tessera

import (
	"context"
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

// Defines the Tessera transparency engine and its configuration parameters
type Engine struct {
	// true if the engine does have access to the network
	Network bool
	// list of trusted public keys to verify log signatures
	logPubkey []string
	// the witness policy, the actual format should be aligned with
	// the one supported one by the chosen transparency engine
	witnessPolicy *tessera.WitnessGroup
}

// Simplified version of the Tessera inclusionProbe structure:
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

func (e *Engine) GetProof(p *transparency.ProofBundle) (err error) {
	var probe Probe
	var logReadBaseURL *url.URL
	var logReadCP client.CheckpointFetcherFunc
	var logReadTile client.TileFetcherFunc

	// parse the probe data to request the inclusion proof
	if err = json.Unmarshal(p.Probe, &probe); err != nil {
		return fmt.Errorf("unable to parse Tessera probing data to require the inclusion proof to the log: %s", err)
	}

	if !e.Network {
		return fmt.Errorf("transparency engine is off-line")
	}

	if e.witnessPolicy == nil {
		return fmt.Errorf("witness policy not configured")
	}

	if len(e.logPubkey) == 0 {
		return fmt.Errorf("log public key is not set")
	}

	// check if the log key included in the proof probe
	// corresponds to one of the trusted log public keys
	lk, err := getTrustedKey(e.logPubkey, probe.LogPublicKey)

	if err != nil {
		return fmt.Errorf("log public key is not trusted %v", probe.LogPublicKey)
	}

	logVerifier, err := note.NewVerifier(lk)

	if err != nil {
		return fmt.Errorf("failed to load log public key: %v", err)
	}

	logReadBaseURL, err = url.Parse(probe.Origin)
	if err != nil {
		return fmt.Errorf("invalid log origin: %s", err)
	}

	switch logReadBaseURL.Scheme {
	case "http", "https":
		hf, err := client.NewHTTPFetcher(logReadBaseURL, nil)
		if err != nil {
			return fmt.Errorf("failed to create an http fetcher: %v", err)
		}
		logReadCP = hf.ReadCheckpoint
		logReadTile = hf.ReadTile
	case "file":
		ff := client.FileFetcher{Root: logReadBaseURL.Path}
		logReadCP = ff.ReadCheckpoint
		logReadTile = ff.ReadTile
	default:
		return fmt.Errorf("unsupported url scheme: %s", logReadBaseURL.Scheme)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(30*time.Second))
	defer cancel()

	// get the latest checkpoint
	// previous checkpoint (third argument) is passed as nil, thus the tracker function will
	// "only" fetch the latest checkpoint and will not return any consistency proof.
	//lst, err := client.NewLogStateTracker(ctx, logReadTile, nil, logVerifier, probe.Origin, client.UnilateralConsensus(logReadCP))
	//if err != nil {
	//	return fmt.Errorf("tessera client: %v", err)
	//}

	// verify that checkpoint co-signatures are satisfying the witness policy
	cp, rawcp, _, err := client.FetchCheckpoint(ctx, logReadCP, logVerifier, probe.Origin)
	if err != nil {
		return fmt.Errorf("fecthing checkpoint: %v", err)
	}

	if !e.witnessPolicy.Satisfied(rawcp) {
		return fmt.Errorf("invalid checkpoint: %v", err)
	}

	// creates the proof builder that will be used to assemble proofs
	// according with the passed (i.e. latest) checkpoint
	pb, err := client.NewProofBuilder(ctx, cp.Size, logReadTile)

	if err != nil {
		return fmt.Errorf("tessera proof builder: %v", err)
	}

	// get the inclusion proof given the latest checkpoint
	ip, err := pb.InclusionProof(ctx, probe.LeafIdx)

	if err != nil {
		return fmt.Errorf("getting inclusion proof: %v", err)
	}

	leafHash := rfc6962.DefaultHasher.HashLeaf(fmt.Append(nil, p.Statement))

	// verify the inclusion proof is valid
	if err = proof.VerifyInclusion(rfc6962.DefaultHasher, probe.LeafIdx, cp.Size, leafHash, ip, cp.Hash); err != nil {
		return fmt.Errorf("invalid inclusion proof: %v", err)
	}

	// Tessera stores inclusion proof(s) as array of byte arrays ([][]byte)
	// but p.Proof is json.RawMessage which is defined as []byte
	p.Proof, err = json.Marshal(ip)

	return
}

func (e *Engine) ParseWitnessPolicy(wp []byte) (interface{}, error) {
	p, err := tessera.NewWitnessGroupFromPolicy(wp)

	if err != nil {
		return nil, err
	}

	return &p, err
}

func (e *Engine) SetKey(logKey []string, submitKey []string) (err error) {
	// parse and load log public key(s) that needs to be compliant with note format
	for _, k := range logKey {
		_, err = note.NewVerifier(k)

		if err != nil {
			return
		}

		e.logPubkey = append(e.logPubkey, k)
	}

	return
}

func (e *Engine) SetWitnessPolicy(wp interface{}) (err error) {
	if _, ok := wp.(*tessera.WitnessGroup); !ok {
		return fmt.Errorf("invalid policy, type assertion to Tessera *tessera.WitnessGroup failed")
	}

	e.witnessPolicy = wp.(*tessera.WitnessGroup)

	return
}

func (e *Engine) VerifyProof(p *transparency.ProofBundle) (err error) {
	var tp Probe
	var ip [][]byte

	// parse the probe data
	if err = json.Unmarshal(p.Probe, &tp); err != nil {
		return fmt.Errorf("unable to parse Tessera probe data: %s", err)
	}

	// parse the inclusion proof
	// Tessera uses [][]byte to store inclusion proof(s)
	if err = json.Unmarshal(p.Proof, &ip); err != nil {
		return fmt.Errorf("unable to parse Tessera inclusion proof: %s", err)
	}

	// load the statement and compute its checksum, which is the leaf hash
	leafHash := rfc6962.DefaultHasher.HashLeaf(p.Statement)

	// check if at least one trusted log key has been set
	if len(e.logPubkey) == 0 {
		return fmt.Errorf("log public key is not set")
	}

	// traverse all log keys and attempt to verify the proof
	for _, logKey := range e.logPubkey {
		// FIXME this is not a valid check confirming that the log key
		// actually used to sign the inclusion proof is a trusted one.
		// witness group must be satisfied when verifying co-signatures
		//  on the tree head
		if logKey != tp.LogPublicKey {
			err = fmt.Errorf("unknown log public key")
			continue // try the next trusted log key
		}

		err = proof.VerifyInclusion(rfc6962.DefaultHasher, tp.LeafIdx, tp.TreeSize, leafHash, ip, tp.Root)

		if err != nil {
			continue // try proof verification with the next log key, if any
		}
	}

	return
}

// search for a public key among a set of trusted ones.
func getTrustedKey(trusted []string, probe string) (string, error) {
	_, err := note.NewVerifier(probe)

	if err != nil {
		return "", fmt.Errorf("invalid public key %v", probe)
	}

	for _, t := range trusted {
		_, err := note.NewVerifier(t)

		// return immediately when encountering an invalid public key
		if err != nil {
			return "", fmt.Errorf("invalid public key: %v", t)
		}

		if t == probe {
			return t, nil
		} else {
			continue // try if the next trusted key matches
		}
	}

	return "", fmt.Errorf("public key is not matching any of the trusted keys")
}
