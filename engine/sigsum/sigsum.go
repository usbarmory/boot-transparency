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
	"fmt"
	"net/http"
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

// Defines the Sigsum transparency engine and its configuration parameters
type SigsumEngine struct {
	Network bool // true if the engine does have access to the network and all the
	// transparency proof verifications must be performed on-line, default is false.
	logPubkey     []crypto.PublicKey // list of public keys to verify log signatures
	submitPubkey  []crypto.PublicKey // list of public keys to verify leaf signatures
	witnessPubkey []crypto.PublicKey // list of public keys to verify cosignatures according to the witness policy, if any
	witnessPolicy *policy.Policy     // the witness policy, the actual format should be aligned with the one supported one by the chosen transparency engine
}

// The logic implemented for the Sigsum engine is partially replicating
// the collectProof() from sigsum-go/pkg/submit/submit.go
func (se *SigsumEngine) GetProof(origin string, p *transparency.ProofBundle) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(30*time.Second))
	defer cancel()

	if !se.Network {
		return fmt.Errorf("transparency engine is off-line")
	}

	if se.witnessPolicy == nil {
		return fmt.Errorf("witness policy not configured")
	}

	if len(se.logPubkey) == 0 {
		return fmt.Errorf("log public key is not set")
	}

	if len(se.submitPubkey) == 0 {
		return fmt.Errorf("submit public key is not set")
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
		URL:        origin,
		HTTPClient: httpClient,
	})

	// FIXME: should loop through all the supported log/submitter keys
	// OR
	// remove the support for multiple log/submitter keys at engine layer?
	// for _, logKey := range se.logPubkey {
	// 	for _, submitKey := range se.submitPubkey {
	logKey := se.logPubkey[0]
	submitKey := se.submitPubkey[0]

	// By default in Sigsum, the actual logged message is a double SHA-256 of the statement
	// equivalent to: $ sha256sum statement.json | cut -d' ' -f1 | base16 -d | sha256sum
	s := sha256.Sum256(p.Statement)
	s = sha256.Sum256(s[:])

	msgChksum := crypto.Hash(s)

	sig, _ := crypto.SignatureFromHex(p.Signature)

	// proof.ShortLeaf is used by GetTreeHead()
	shortLeaf := proof.ShortLeaf{
		Signature: sig,
		KeyHash:   crypto.HashBytes(submitKey[:]),
	}

	// "complete" types.Leaf, including also the logged message checksum, is used by GetInclusionProof()
	leaf := types.Leaf{
		Checksum:  msgChksum,
		Signature: sig,
		KeyHash:   crypto.HashBytes(submitKey[:]),
	}

	pr := proof.SigsumProof{
		LogKeyHash: crypto.HashBytes(logKey[:]),
		Leaf:       shortLeaf,
	}

	if pr.TreeHead, err = client.GetTreeHead(ctx); err != nil {
		return fmt.Errorf("getting latest tree head: %v", err)
	}

	// FIXME append results to proof bundle instead of printing to stdout
	head := bytes.Buffer{}
	pr.TreeHead.ToASCII(&head)
	fmt.Printf("got signed tree head: %q\n\n", head.String())

	if err = se.witnessPolicy.VerifyCosignedTreeHead(&pr.LogKeyHash, &pr.TreeHead); err != nil {
		return fmt.Errorf("verifying tree head: %v", err)
	}

	leafHash := leaf.ToHash()

	req := requests.InclusionProof{Size: pr.TreeHead.Size, LeafHash: leafHash}
	if pr.Inclusion, err = client.GetInclusionProof(ctx, req); err != nil {
		return fmt.Errorf("getting inclusion proof: %v", err)
	}

	// FIXME append results to proof bundle instead of printing to stdout
	inclusion := bytes.Buffer{}
	pr.Inclusion.ToASCII(&inclusion)
	fmt.Printf("got inclusion proof: %q\n\n", inclusion.String())

	if err = pr.Inclusion.Verify(&leafHash, &pr.TreeHead.TreeHead); err != nil {
		return fmt.Errorf("inclusion proof invalid: %v", err)
	}

	return
}

func (se *SigsumEngine) ParseWitnessPolicy(wp []byte) (interface{}, error) {
	p, err := policy.ParseConfig(bytes.NewReader(wp))

	if err != nil {
		return nil, err
	}

	return p, err
}

func (se *SigsumEngine) SetKey(logKey []string, submitKey []string, witnessKey []string) (err error) {
	var parsedKey crypto.PublicKey

	// parse and load log public key(s)
	for _, k := range logKey {
		parsedKey, err = key.ParsePublicKey(k)

		if err != nil {
			return
		}

		se.logPubkey = append(se.logPubkey, parsedKey)
	}

	// parse and load submit public key(s)
	for _, k := range submitKey {
		parsedKey, err = key.ParsePublicKey(k)

		if err != nil {
			return
		}

		se.submitPubkey = append(se.submitPubkey, parsedKey)
	}

	// parse and load witness public key(s)
	for _, k := range witnessKey {
		parsedKey, err = key.ParsePublicKey(k)

		if err != nil {
			return
		}

		se.witnessPubkey = append(se.witnessPubkey, parsedKey)
	}

	return
}

func (se *SigsumEngine) SetWitnessPolicy(wp interface{}) (err error) {
	if _, ok := wp.(*policy.Policy); !ok {
		return fmt.Errorf("invalid policy, type assertion to Sigsum *policy.Policy failed")
	}

	se.witnessPolicy = wp.(*policy.Policy)

	return
}

func (se *SigsumEngine) VerifyProof(p *transparency.ProofBundle) (err error) {
	var proof proof.SigsumProof

	// load the statement and compute its checksum, which is the logged message to verify
	msg := crypto.Hash(sha256.Sum256(p.Statement))

	// load the proof
	if err = proof.FromASCII(bytes.NewReader(p.Proof)); err != nil {
		return
	}

	// check if at least one trusted log key has been set
	if len(se.logPubkey) == 0 {
		return fmt.Errorf("log public key is not set")
	}

	// check if at least one submitter key has been set
	if len(se.submitPubkey) == 0 {
		return fmt.Errorf("submitter public key is not set")
	}

	// traverse all log and submitter pubkeys and attempt to verify the proof
	for _, logKey := range se.logPubkey {
		if proof.LogKeyHash != crypto.HashBytes(logKey[:]) {
			err = fmt.Errorf("unknown log key hash")
			continue // try proof verification with the next log key, if any
		}

		for _, submitKey := range se.submitPubkey {
			// include quorum verification only if the witness policy is set.
			if se.witnessPolicy != nil {
				err = proof.Verify(&msg, map[crypto.Hash]crypto.PublicKey{
					crypto.HashBytes(submitKey[:]): submitKey}, se.witnessPolicy)
			} else { // verification do not include any witness quorum verification
				err = proof.VerifyNoCosignatures(&msg, map[crypto.Hash]crypto.PublicKey{
					crypto.HashBytes(submitKey[:]): submitKey}, &logKey)
			}

			if err != nil {
				continue // try proof verification with the next submitter key, if any
			}
		}
	}

	return
}
