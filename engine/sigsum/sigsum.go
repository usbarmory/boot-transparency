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

// SigsumEngine represents the Sigsum transparency engine and its configuration parameters.
type SigsumEngine struct {
	// List of trusted public keys to verify log signatures.
	logPubkey []string

	// List of trusted public keys to verify leaf signatures.
	submitPubkey []string

	// The witness policy, the actual format should be aligned
	// with the one supported one by the chosen transparency engine.
	witnessPolicy *policy.Policy
}

func init() {
	e := SigsumEngine{}
	transparency.Add(&e, transparency.Sigsum)
}

// GetProof implements transparency.GetProof() for the Sigsum engine.
// The logic implemented for the Sigsum engine is partially replicating
// the collectProof() from sigsum-go/pkg/submit/submit.go.
func (e *SigsumEngine) GetProof(proofBundle interface{}) ([]byte, error) {
	if _, ok := proofBundle.(*ProofBundle); !ok {
		return nil, fmt.Errorf("invalid proof bundle for Sigsum engine")
	}

	pb := proofBundle.(*ProofBundle)

	// Validate the correctness of the proof bundle format.
	if pb.Format != transparency.Sigsum {
		return nil, fmt.Errorf("invalid bundle format %q, expected %q (transparency.Sigsum)", pb.Format, transparency.Sigsum)
	}

	if e.witnessPolicy == nil {
		return nil, fmt.Errorf("witness policy not configured")
	}

	if len(e.logPubkey) == 0 {
		return nil, fmt.Errorf("trusted log public key is not set")
	}

	// Validate the trustworthiness of the log key included in the proof probe.
	lk, err := getTrustedKeyFromHash(e.logPubkey, pb.Probe.LogPublicKeyHash)

	if err != nil {
		return nil, err
	}

	if len(e.submitPubkey) == 0 {
		return nil, fmt.Errorf("trusted submit public key is not set")
	}

	// Validate the trustworthiness of the submit key included in the proof probe.
	sk, err := getTrustedKeyFromHash(e.submitPubkey, pb.Probe.SubmitPublicKeyHash)

	if err != nil {
		return nil, err
	}

	if _, err := url.Parse(pb.Probe.Origin); err != nil {
		return nil, fmt.Errorf("invalid log origin, %w", err)
	}

	// HTTP client configuration.
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

	// By default in Sigsum, the logged message is a double SHA-256 of the statement:
	// $ sha256sum statement.json | cut -d' ' -f1 | base16 -d | sha256sum
	// JSON marshalling is required to ensure the message has been logged
	// independently from its formatting (i.e. indent spaces, or tabs,
	// that would be present in human-readable statement JSON).
	statement, err := json.MarshalIndent(pb.Statement, "", "\t")

	if err != nil {
		return nil, err
	}

	// The message chksum is a SHA-256 of the logged message,
	// which in turn is a SHA-256 of the initial statement.
	// This checksum should match the one shown by sigsum-monitor.
	s := sha256.Sum256(statement)
	s = sha256.Sum256(s[:])

	msgChksum := crypto.Hash(s)

	sig, _ := crypto.SignatureFromHex(pb.Probe.LeafSignature)

	// proof.ShortLeaf is used by GetTreeHead().
	shortLeaf := proof.ShortLeaf{
		Signature: sig,
		KeyHash:   crypto.HashBytes(sk[:]),
	}

	// types.Leaf: the "complete" leaf including also the logged message checksum,
	// this structure is used by GetInclusionProof().
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
		return nil, fmt.Errorf("failed to get the latest tree head, %w", err)
	}

	if err = e.witnessPolicy.VerifyCosignedTreeHead(&pr.LogKeyHash, &pr.TreeHead); err != nil {
		return nil, fmt.Errorf("failed to verify the tree head, %w", err)
	}

	leafHash := leaf.ToHash()
	req := requests.InclusionProof{Size: pr.TreeHead.Size, LeafHash: leafHash}

	if pr.Inclusion, err = client.GetInclusionProof(ctx, req); err != nil {
		return nil, fmt.Errorf("failed to get the inclusion proof, %w", err)
	}

	if err = pr.Inclusion.Verify(&leafHash, &pr.TreeHead.TreeHead); err != nil {
		return nil, fmt.Errorf("invalid inclusion proof, %w", err)
	}

	// Save the whole inclusion proof in ASCII format in the proof bundle.
	sigsumProofBundle, err := buildSigsumProofBundle(pr)
	if err != nil {
		return nil, fmt.Errorf("failed to assemble the proof bundle, %w", err)
	}

	return sigsumProofBundle, nil
}

// ParseWitnessPolicy implements transparency.ParseWitnessPolicy() for the Sigsum engine.
func (e *SigsumEngine) ParseWitnessPolicy(wp []byte) (interface{}, error) {
	p, err := policy.ParseConfig(bytes.NewReader(wp))

	if err != nil {
		return nil, err
	}

	return p, err
}

// SetKey implements transparency.SetKey() for the Sigsum engine.
func (e *SigsumEngine) SetKey(logKey []string, submitKey []string) (err error) {
	// Reset any previously stored key.
	e.logPubkey = []string{}
	e.submitPubkey = []string{}

	// Parse and load log public key(s).
	for _, k := range logKey {
		_, err = key.ParsePublicKey(k)

		if err != nil {
			return
		}

		e.logPubkey = append(e.logPubkey, k)
	}

	// Parse and load submit public key(s).
	for _, k := range submitKey {
		_, err = key.ParsePublicKey(k)

		if err != nil {
			return
		}

		e.submitPubkey = append(e.submitPubkey, k)
	}

	return
}

// SetWitnessPolicy implements transparency.SetWitnessPolicy for the Sigsum engine.
func (e *SigsumEngine) SetWitnessPolicy(wp interface{}) (err error) {
	if _, ok := wp.(*policy.Policy); !ok {
		return fmt.Errorf("invalid policy, type assertion to Sigsum *policy.Policy failed")
	}

	e.witnessPolicy = wp.(*policy.Policy)

	return
}

// ResetWitnessPolicy implements transparency.ResetWitnessPolicy() for the Sigsum engine.
func (e *SigsumEngine) ResetWitnessPolicy() {
	e.witnessPolicy = nil
}

// VerifyProof implements transparency.VerifyProof() for the Sigsum engine.
func (e *SigsumEngine) VerifyProof(proofBundle interface{}) (err error) {
	var proof proof.SigsumProof
	var lk crypto.PublicKey
	var sk crypto.PublicKey

	if _, ok := proofBundle.(*ProofBundle); !ok {
		return fmt.Errorf("invalid proof bundle for Sigsum engine")
	}

	pb := proofBundle.(*ProofBundle)

	// Validate the correctness of the proof bundle format.
	if pb.Format != transparency.Sigsum {
		return fmt.Errorf("invalid bundle format %q, expected %q (transparency.SigsumBundle)", pb.Format, transparency.Sigsum)
	}

	// Load the statement and compute its checksum, which is the logged
	// message to be verified.
	// JSON marshalling is required to ensure the message has been logged
	// independently from its formatting (i.e. indent spaces, or tabs,
	// that would be present in human-readable statement JSON).
	statement, err := json.MarshalIndent(pb.Statement, "", "\t")

	if err != nil {
		return
	}

	// The logged message is a SHA-256 of the original statement.
	// Here message content should be aligned with the output of
	// sha256sum out | cut -d' ' -f1 | base16 -d | hexdump -C
	// This is not the leaf checksum shown by sigsum-monitor,
	// indeed, this is the "actual" logged message.
	// sigsum-monitor shows a sha256sum of this.
	msg := crypto.Hash(sha256.Sum256(statement))

	// Load the proof.
	asciiProof := []byte(pb.Proof)
	if err = proof.FromASCII(bytes.NewReader(asciiProof)); err != nil {
		return
	}

	// Ensure at least one trusted submitter key has been set.
	if len(e.submitPubkey) == 0 {
		return fmt.Errorf("submitter public key is not set")
	}

	// Ensure at least one trusted log key has been set.
	// The log key is read directly from the witness policy (when present).
	if e.witnessPolicy == nil && len(e.logPubkey) == 0 {
		return fmt.Errorf("log public key is not set")
	}

	// Traverse all trusted log and submitter public keys,
	// and attempt to verify the proof.
	for _, logKey := range e.logPubkey {
		lk, err = key.ParsePublicKey(logKey)

		// Return immediately when encountering an invalid public key.
		if err != nil {
			return fmt.Errorf("invalid log public key %q", logKey)
		}

		for _, submitKey := range e.submitPubkey {
			sk, err = key.ParsePublicKey(submitKey)

			// Return immediately when encountering an invalid public key.
			if err != nil {
				return fmt.Errorf("invalid submit public key %q", submitKey)
			}

			// Include quorum verification only if the witness policy is set.
			if e.witnessPolicy != nil {
				err = proof.Verify(&msg, map[crypto.Hash]crypto.PublicKey{
					crypto.HashBytes(sk[:]): sk}, e.witnessPolicy)
			} else { // Verification do not include any witness quorum verification.
				err = proof.VerifyNoCosignatures(&msg, map[crypto.Hash]crypto.PublicKey{
					crypto.HashBytes(sk[:]): sk}, &lk)
			}

			// Return immediately if the proof verification passes.
			if err == nil {
				return
			}
		}
	}

	return
}

// ParseProof implements transparency.ParseProof() for the Sigsum engine.
func (e *SigsumEngine) ParseProof(jsonProofBundle []byte) (interface{}, []byte, error) {
	var pb ProofBundle
	var proof proof.SigsumProof
	var pbMarshal []byte

	if err := json.Unmarshal(jsonProofBundle, &pb); err != nil {
		return nil, nil, err
	}

	// Do not parse the statement, only focus on the inclusion proof
	// and the probing data.

	// Validate the correctness of the proof bundle format.
	if pb.Format != transparency.Sigsum {
		return nil, nil, fmt.Errorf("invalid bundle format %q, expected %q (transparency.Sigsum)", pb.Format, transparency.Sigsum)
	}

	// Try to import the proof as proof.SigsumProof, if present, to confirm it
	// can be handled correctly by sigsum libraries.
	if pb.Proof != "" {
		asciiProof := []byte(pb.Proof)
		if err := proof.FromASCII(bytes.NewReader(asciiProof)); err != nil {
			return nil, nil, err
		}
	}

	// Return also the JSON marshal version of the bundle.
	pbMarshal, err := json.MarshalIndent(&pb, "", "\t")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal the proof bundle, %w", err)
	}

	return &pb, pbMarshal, nil
}

// If present, return the key that corresponds to a given key hash.
// The key is searched among all the trusted keys configured for the transparency engine.
func getTrustedKeyFromHash(trustedKeys []string, hash string) (crypto.PublicKey, error) {
	var k crypto.PublicKey

	h, err := crypto.HashFromHex(hash)

	if err != nil {
		return k, fmt.Errorf("invalid public key hash %q", hash)
	}

	for _, trusted := range trustedKeys {
		k, err := key.ParsePublicKey(trusted)

		// Return immediately when encountering an invalid public key.
		if err != nil {
			return k, fmt.Errorf("invalid public key %q", trusted)
		}

		if h == crypto.HashBytes(k[:]) {
			return k, nil
		} else {
			continue // Try if the next trusted key matches.
		}
	}

	return k, fmt.Errorf("keyhash is not matching any of the trusted keys")
}

func buildSigsumProofBundle(p proof.SigsumProof) ([]byte, error) {
	b := bytes.Buffer{}
	header := fmt.Sprintf("version=2\nlog=%x\nleaf=%x %x\n\n", p.LogKeyHash, p.Leaf.KeyHash, p.Leaf.Signature)
	_, _ = b.Write([]byte(header))

	err := p.TreeHead.ToASCII(&b)
	if err != nil {
		return nil, err
	}

	_, _ = b.Write([]byte("\n"))

	err = p.Inclusion.ToASCII(&b)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}
