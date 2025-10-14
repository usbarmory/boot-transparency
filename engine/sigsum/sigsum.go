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
type Engine struct {
	// true if the engine does have access to the network
	Network bool
	// list of trusted public keys to verify log signatures
	logPubkey []string
	// list of trusted public keys to verify leaf signatures
	submitPubkey []string
	// the witness policy, the actual format should be aligned
	// with the one supported one by the chosen transparency engine
	witnessPolicy *policy.Policy
}

// Define the set of inputs required to probe for an inclusion proof
// for a given leaf.
type Probe struct {
	// log origin
	Origin string `json:"origin"`
	// Sigsum uses leaf signature to identify the leaf into the log
	LeafSignature string `json:"leaf_signature"`
	// log key hash in hex format as expected in Sigsum proof bundle
	LogPublicKeyHash string `json:"log_public_key_hash"`
	// submitter key hash in hex format as expected in Sigsum proof bundle
	SubmitPublicKeyHash string `json:"submit_public_key_hash"`
	// The LeafHash is not present as it is computed hashing the statement
	// included in the proof bundle.
	// LeafHash []byte    `json:"leafHash"`
}

// The logic implemented for the Sigsum engine is partially replicating
// the collectProof() from sigsum-go/pkg/submit/submit.go
func (e *Engine) GetProof(p *transparency.ProofBundle) (err error) {
	var probe Probe

	// check if this is a Sigsum proof
	if p.Format != transparency.SigsumBundle {
		return fmt.Errorf("invalid bundle format %d, expected %d (transparency.SigsumBundle)", p.Format, transparency.SigsumBundle)
	}

	// parse the inclusion probe data to request the proof
	if err = json.Unmarshal(p.Probe, &probe); err != nil {
		return fmt.Errorf("unable to parse Sigsum probing data: %s", err)
	}

	if !e.Network {
		return fmt.Errorf("transparency engine is off-line")
	}

	if e.witnessPolicy == nil {
		return fmt.Errorf("witness policy not configured")
	}

	if len(e.logPubkey) == 0 {
		return fmt.Errorf("trusted log public key is not set")
	}

	// check if the log key hash included in the proof probe corresponds
	// to one of the trusted log keys
	lk, err := getTrustedKeyFromHash(e.logPubkey, probe.LogPublicKeyHash)

	if err != nil {
		return
	}

	if len(e.submitPubkey) == 0 {
		return fmt.Errorf("trusted submit public key is not set")
	}

	// check if the submit key hash included in the proof probe corresponds
	// to one of the trusted submit keys
	sk, err := getTrustedKeyFromHash(e.submitPubkey, probe.SubmitPublicKeyHash)

	if err != nil {
		return
	}

	if _, err := url.Parse(probe.Origin); err != nil {
		return fmt.Errorf("invalid log origin: %s", err)
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
		URL:        probe.Origin,
		HTTPClient: httpClient,
	})

	// By default in Sigsum, the actual logged message is a double SHA-256 of the statement
	// equivalent to: $ sha256sum statement.json | cut -d' ' -f1 | base16 -d | sha256sum
	s := sha256.Sum256(p.Statement)
	s = sha256.Sum256(s[:])

	msgChksum := crypto.Hash(s)

	sig, _ := crypto.SignatureFromHex(probe.LeafSignature)

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
		return fmt.Errorf("getting latest tree head: %v", err)
	}

	if err = e.witnessPolicy.VerifyCosignedTreeHead(&pr.LogKeyHash, &pr.TreeHead); err != nil {
		return fmt.Errorf("verifying tree head: %v", err)
	}

	leafHash := leaf.ToHash()
	req := requests.InclusionProof{Size: pr.TreeHead.Size, LeafHash: leafHash}

	if pr.Inclusion, err = client.GetInclusionProof(ctx, req); err != nil {
		return fmt.Errorf("getting inclusion proof: %v", err)
	}

	if err = pr.Inclusion.Verify(&leafHash, &pr.TreeHead.TreeHead); err != nil {
		return fmt.Errorf("invalid inclusion proof: %v", err)
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
	p.Proof = builtProof.Bytes()

	return
}

func (e *Engine) ParseWitnessPolicy(wp []byte) (interface{}, error) {
	p, err := policy.ParseConfig(bytes.NewReader(wp))

	if err != nil {
		return nil, err
	}

	return p, err
}

func (e *Engine) SetKey(logKey []string, submitKey []string) (err error) {
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

func (e *Engine) SetWitnessPolicy(wp interface{}) (err error) {
	if _, ok := wp.(*policy.Policy); !ok {
		return fmt.Errorf("invalid policy, type assertion to Sigsum *policy.Policy failed")
	}

	e.witnessPolicy = wp.(*policy.Policy)

	return
}

func (e *Engine) VerifyProof(p *transparency.ProofBundle) (err error) {
	var proof proof.SigsumProof

	// load the statement and compute its checksum, which is the logged message to verify
	msg := crypto.Hash(sha256.Sum256(p.Statement))

	// check if this is a Sigsum proof
	if p.Format != transparency.SigsumBundle {
		return fmt.Errorf("invalid bundle format %d, expected %d (transparency.SigsumBundle)", p.Format, transparency.SigsumBundle)
	}

	// load the proof
	if err = proof.FromASCII(bytes.NewReader(p.Proof)); err != nil {
		return err
	}

	// check if at least one trusted log key has been set
	if len(e.logPubkey) == 0 {
		return fmt.Errorf("log public key is not set")
	}

	// check if at least one trusted submitter key has been set
	if len(e.submitPubkey) == 0 {
		return fmt.Errorf("submitter public key is not set")
	}

	// traverse all trusted log and submitter pubkeys and attempt to verify the proof
	for _, logKey := range e.logPubkey {
		lk, err := key.ParsePublicKey(logKey)

		// return immediately when encountering an invalid public key
		if err != nil {
			return fmt.Errorf("invalid log public key: %s", logKey)
		}

		for _, submitKey := range e.submitPubkey {
			sk, err := key.ParsePublicKey(submitKey)

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

			if err == nil {
				return nil // proof verified passed
			}
		}
	}

	return
}

func (e *Engine) ParseProof(p *transparency.ProofBundle) (err error) {
	var probe Probe
	var proof proof.SigsumProof

	// do not parse the statement, only focus on the inclusion proof
	// and the probing data

	// check if this is a Sigsum proof bundle
	if p.Format != transparency.SigsumBundle {
		return fmt.Errorf("invalid bundle format %d, expected %d (transparency.SigsumBundle)", p.Format, transparency.SigsumBundle)
	}

	// parse the inclusion probe data to request the proof
	if err = json.Unmarshal(p.Probe, &probe); err != nil {
		return fmt.Errorf("unable to parse Sigsum probing data: %s", err)
	}

	// the inclusion proof is not present in the bundle, nothing to parse there
	if p.Proof == nil {
		return
	}

	// parse the proof
	if err = proof.FromASCII(bytes.NewReader(p.Proof)); err != nil {
		return
	}

	return
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
