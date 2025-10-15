// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package sigsum

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/usbarmory/boot-transparency/transparency"
	"sigsum.org/sigsum-go/pkg/client"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/proof"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

// Define the Sigsum transparency engine and its configuration parameters
type SigsumEngine struct {
	// list of trusted public keys to verify log signatures
	logPubkey []string
	// list of trusted public keys to verify leaf signatures
	submitPubkey []string
	// the witness policy, the actual format should be aligned
	// with the one supported one by the chosen transparency engine
	witnessPolicy *policy.Policy
}

func init() {
	e := SigsumEngine{}
	transparency.Add(&e, transparency.Sigsum)
}

// The logic implemented for the Sigsum engine is partially replicating
// the collectProof() from sigsum-go/pkg/submit/submit.go
func (e *SigsumEngine) GetProof(proofBundle interface{}) ([]byte, error) {
	if _, ok := proofBundle.(*ProofBundle); !ok {
		return nil, fmt.Errorf("invalid·proof bundle for Sigsum engine")
	}

	pb := proofBundle.(*ProofBundle)

	// check that the format set in the bundle is correct
	if pb.Format != transparency.Sigsum {
		return nil, fmt.Errorf("invalid bundle format %d, expected %d (transparency.Sigsum)", pb.Format, transparency.Sigsum)
	}

	if e.witnessPolicy == nil {
		return nil, fmt.Errorf("witness policy not configured")
	}

	if len(e.logPubkey) == 0 {
		return nil, fmt.Errorf("trusted log public key is not set")
	}

	// check if the log key hash included in the proof probe corresponds
	// to one of the trusted log keys
	lk, err := getTrustedKeyFromHash(e.logPubkey, pb.Probe.LogPublicKeyHash)

	if err != nil {
		return nil, err
	}

	if len(e.submitPubkey) == 0 {
		return nil, fmt.Errorf("trusted submit public key is not set")
	}

	// check if the submit key hash included in the proof probe corresponds
	// to one of the trusted submit keys
	sk, err := getTrustedKeyFromHash(e.submitPubkey, pb.Probe.SubmitPublicKeyHash)

	if err != nil {
		return nil, err
	}

	if _, err := url.Parse(pb.Probe.Origin); err != nil {
		return nil, fmt.Errorf("invalid log origin: %s", err)
	}

	// HTTP client configuration
	tr := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    29 * time.Second,
		DisableCompression: true,
	}
	httpClient := &http.Client{Transport: tr}

	client := client.New(client.Config{
		UserAgent:  "boot-transparency",
		URL:        pb.Probe.Origin,
		HTTPClient: httpClient,
	})

	// By default in Sigsum, the actual logged message is a double SHA-256 of the statement
	// equivalent to: $ sha256sum statement.json | cut -d' ' -f1 | base16 -d | sha256sum
	// JSON marshalling is required to ensure the message has been logged
	// independently from its formatting (i.e. indent spaces, or tabs,
	// that would be present in human-readable statement JSON)
	statement, err := json.Marshal(pb.Statement)

	if err != nil {
		return nil, err
	}

	// need to append a newline (i.e. 0x0a) to be consistent
	// with the actual logged bytes
	statement = append(statement, "\n"...)

	// the message chksum is a sha256 of the logged message,
	// which in turn is a sha256 of the initial statement
	s := sha256.Sum256(statement)
	s = sha256.Sum256(s[:])

	msgChksum := crypto.Hash(s)

	sig, _ := crypto.SignatureFromHex(pb.Probe.LeafSignature)

	// proof.ShortLeaf is used by GetTreeHead()
	shortLeaf := proof.ShortLeaf{
		Signature: sig,
		KeyHash:   crypto.HashBytes(sk[:]),
	}

	// "complete" types.Leaf, including also the logged message checksum, is used by GetInclusionProof()
	leaf := types.Leaf{
		Checksum:  msgChksum,
		Signature: sig,
		KeyHash:   crypto.HashBytes(sk[:]),
	}

	pr := proof.SigsumProof{
		LogKeyHash: crypto.HashBytes(lk[:]),
		Leaf:       shortLeaf,
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(30*time.Second))
	defer cancel()

	if pr.TreeHead, err = client.GetTreeHead(ctx); err != nil {
		return nil, fmt.Errorf("getting latest tree head: %v", err)
	}

	if err = e.witnessPolicy.VerifyCosignedTreeHead(&pr.LogKeyHash, &pr.TreeHead); err != nil {
		return nil, fmt.Errorf("verifying tree head: %v", err)
	}

	leafHash := leaf.ToHash()
	req := requests.InclusionProof{Size: pr.TreeHead.Size, LeafHash: leafHash}

	if pr.Inclusion, err = client.GetInclusionProof(ctx, req); err != nil {
		return nil, fmt.Errorf("getting inclusion proof: %v", err)
	}

	if err = pr.Inclusion.Verify(&leafHash, &pr.TreeHead.TreeHead); err != nil {
		return nil, fmt.Errorf("invalid inclusion proof: %v", err)
	}

	// save the whole inclusion proof in ASCII format in the proof bundle
	// FIXME: the Sigsum proof format requires to prepend
	// version=2
	// log=KEYHASH
	// leaf=KEYHASH SIGNATURE
	// append results in ASCII format
	builtProof := bytes.Buffer{}
	pr.TreeHead.ToASCII(&builtProof)
	pr.Inclusion.ToASCII(&builtProof)

	// Sigsum stores inclusion proof(s) as byte array []byte
	return builtProof.Bytes(), nil
}

func (e *SigsumEngine) ParseWitnessPolicy(wp []byte) (interface{}, error) {
	p, err := policy.ParseConfig(bytes.NewReader(wp))

	if err != nil {
		return nil, err
	}

	return p, err
}

func (e *SigsumEngine) SetKey(logKey []string, submitKey []string) (err error) {
	// re-set any previously stored key
	e.logPubkey = []string{}
	e.submitPubkey = []string{}

	// parse and load log public key(s)
	for _, k := range logKey {
		_, err = key.ParsePublicKey(k)

		if err != nil {
			return
		}

		e.logPubkey = append(e.logPubkey, k)
	}

	// parse and load submit public key(s)
	for _, k := range submitKey {
		_, err = key.ParsePublicKey(k)

		if err != nil {
			return
		}

		e.submitPubkey = append(e.submitPubkey, k)
	}

	return
}

func (e *SigsumEngine) SetWitnessPolicy(wp interface{}) (err error) {
	if _, ok := wp.(*policy.Policy); !ok {
		return fmt.Errorf("invalid policy, type assertion to Sigsum *policy.Policy failed")
	}

	e.witnessPolicy = wp.(*policy.Policy)

	return
}

func (e *SigsumEngine) ResetWitnessPolicy() {
	e.witnessPolicy = nil
}

func (e *SigsumEngine) VerifyProof(proofBundle interface{}) (err error) {
	var proof proof.SigsumProof
	var lk crypto.PublicKey
	var sk crypto.PublicKey

	if _, ok := proofBundle.(*ProofBundle); !ok {
		return fmt.Errorf("invalid proof bundle for Sigsum engine")
	}

	pb := proofBundle.(*ProofBundle)

	// check that the format set in the bundle is correct
	if pb.Format != transparency.Sigsum {
		return fmt.Errorf("invalid bundle format %d, expected %d (transparency.SigsumBundle)", pb.Format, transparency.Sigsum)
	}

	// load the statement and compute its checksum, which is the logged message to verify
	// JSON marshalling is required to ensure the message has been logged
	// independently from its formatting (i.e. indent spaces, or tabs,
	// that would be present in human-readable statement JSON)
	statement, err := json.Marshal(pb.Statement)

	if err != nil {
		return
	}

	// need to append a newline (i.e. 0x0a) to be consistent
	// with the actual logged bytes
	statement = append(statement, "\n"...)

	// the logged message is a sha256 of the original statement
	msg := crypto.Hash(sha256.Sum256(statement))

	// load the proof
	asciiProof := []byte(pb.Proof)
	if err = proof.FromASCII(bytes.NewReader(asciiProof)); err != nil {
		return
	}

	// check if at least one trusted log key has been set
	if len(e.logPubkey) == 0 {
		return fmt.Errorf("log public key is not set")
	}

	// check if at least one trusted submitter key has been set
	if len(e.submitPubkey) == 0 {
		return fmt.Errorf("submitter public key is not set")
	}

	// traverse all trusted log and submitter public keys,
	// and attempt to verify the proof
	for _, logKey := range e.logPubkey {
		lk, err = key.ParsePublicKey(logKey)

		// return immediately when encountering an invalid public key
		if err != nil {
			return fmt.Errorf("invalid log public key: %s", logKey)
		}

		for _, submitKey := range e.submitPubkey {
			sk, err = key.ParsePublicKey(submitKey)

			// return immediately when encountering an invalid public key
			if err != nil {
				return fmt.Errorf("invalid submit public key: %s", submitKey)
			}

			// include quorum verification only if the witness policy is set.
			if e.witnessPolicy != nil {
				err = proof.Verify(&msg, map[crypto.Hash]crypto.PublicKey{
					crypto.HashBytes(sk[:]): sk}, e.witnessPolicy)
			} else { // verification do not include any witness quorum verification
				err = proof.VerifyNoCosignatures(&msg, map[crypto.Hash]crypto.PublicKey{
					crypto.HashBytes(sk[:]): sk}, &lk)
			}

			// return immediately if the proof verification passes
			if err == nil {
				return
			}
		}
	}

	return
}

func (e *SigsumEngine) ParseProof(jsonProofBundle []byte) (interface{}, []byte, error) {
	var pb ProofBundle
	var proof proof.SigsumProof
	var pbMarshal []byte

	if err := json.Unmarshal(jsonProofBundle, &pb); err != nil {
		return nil, nil, err
	}

	// do not parse the statement, only focus on the inclusion proof
	// and the probing data

	// check if this is a Sigsum proof bundle
	if pb.Format != transparency.Sigsum {
		return nil, nil, fmt.Errorf("invalid bundle format %d, expected %d (transparency.Sigsum)", pb.Format, transparency.Sigsum)
	}

	// try to import the proof as proof.SigsumProof, if present to confirm it
	// can be imported by sigsum
	if pb.Proof != "" {
		asciiProof := []byte(pb.Proof)
		if err := proof.FromASCII(bytes.NewReader(asciiProof)); err != nil {
			return nil, nil, err
		}
	}

	// return also the JSON marshal version of the bundle
	pbMarshal, err := json.MarshalIndent(&pb, "", "\t")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal the proof bundle: %v", err)
	}

	return &pb, pbMarshal, nil
}

// If present, return the key that corresponds to a given key hash.
// The key is searched among all the trusted keys configured for the transparency engine.
func getTrustedKeyFromHash(trustedKeys []string, hash string) (crypto.PublicKey, error) {
	var k crypto.PublicKey

	h, err := crypto.HashFromHex(hash)

	if err != nil {
		return k, fmt.Errorf("invalid public key hash %v", hash)
	}

	for _, trusted := range trustedKeys {
		k, err := key.ParsePublicKey(trusted)

		// return immediately when encountering an invalid public key
		if err != nil {
			return k, fmt.Errorf("invalid public key: %v", trusted)
		}

		if h == crypto.HashBytes(k[:]) {
			return k, nil
		} else {
			continue // try if the next trusted key matches
		}
	}

	return k, fmt.Errorf("keyhash is not matching any of the trusted keys")
}
