// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package policy

import (
	"encoding/json"
	"fmt"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"

	"github.com/usbarmory/boot-transparency/artifact"
	"github.com/usbarmory/boot-transparency/statement"
)

// Define a trusted signer
type Signer struct {
	// human-readable signer name
	Name string `json:"name,omitempty"`

	// signer's public key
	PubKey string `json:"pub_key"`
}

// Define a signing quorum that must be satisfied to authorize the bundle
type SigningRequirement struct {
	// list of trusted signers that are participating to the quorum
	Signers []Signer `json:"signers"`

	// requires at least n signatures out of the total number of trusted signers
	Quorum uint64 `json:"quorum"`
}

// Define the required set of properties to authorize an artifact from a given category.
type ArtifactRequirements struct {
	// define the artifact category (e.g. LinuxKernel, Initrd, Dtb, ...)
	Category uint `json:"category"`

	// serialized JSON containing the list of properties that must
	// match the claims for an artifact of this category.
	// The set of properties that are supported depends by the artifact category.
	// The JSON format should reflect the underlying structure that is defined
	// in the artifact package for the given category.
	Requirements string `json:"requirements"`
}

// Define the policy entry as a set of requirements to authorize a given bundle of artifacts.
type PolicyEntry struct {
	// artifact rules
	Artifacts []ArtifactRequirements `json:"artifacts"`

	// require at least a quorum of n signatures for the bundle
	Signatures SigningRequirement `json:"signatures,omitempty"`
}

// Parse the boot policy requirements from the serialized JSON
//
// Return error if:
//     - the parsing fails
func Parse(jsonPolicy []byte) (policy *[]PolicyEntry, err error) {
	var h artifact.Handler

	if err = json.Unmarshal(jsonPolicy, &policy); err != nil {
		return
	}

	// the policy is an array of entries (i.e. per-bundle requirements).
	// Each entry needs deeper parsing to ensure consistency between the specified
	// artifact requirements and the ones supported by the given artifact category
	for _, entry := range *policy {
		for _, a := range entry.Artifacts {
			// check if an artifact handler is registered for the given artifact category
			h, err = artifact.GetHandler(a.Category)
			if err != nil {
				return
			}

			// invoke the correspondent requirement parser for the given artifact category
			if _, err = h.ParseRequirements([]byte(a.Requirements)); err != nil {
				return
			}
		}
	}

	return
}

// Check if the claims present in a given statement are satisfying
// the policy requirements.
//
// The policy array (i.e. list of per-artifact bundle requirements) is
// traversed to verify whether there is at least one entry
// matching the claims for the artifacts bundle.
//
// The logic applied depends by the artifact category, and thus,
// it is defined in the corresponding artifact package.
//
// Return error if:
//   - the bundle does not met the policy requirements
//   - the claim parsing fails
//   - the requirement parsing fails
func Check(p *[]PolicyEntry, s *statement.Statement) (err error) {
	var h artifact.Handler

	// traverse the policy
	for _, entry := range *p {
		// reset any error got while checking the previous policy entry
		err = nil

		// if this policy entry requires a signing quorum to authorize the bundle,
		// check the number of valid signatures in the logged statement
		if entry.Signatures.Quorum > 0 {
			if err = checkSigningQuorum(&entry.Signatures, s); err != nil {
				continue // quorum not satisfied try with the next policy entry
			}
		}

		// check all the per-category requirements against the claimed
		// properties for the artifacts present in the bundle
		for _, policyArtifact := range entry.Artifacts {
			h, err = artifact.GetHandler(policyArtifact.Category)

			// return immediately if the policy requirements for this artifact
			// cannot be checked. The handler for this category, that is included
			// in the policy, is not registered
			if err != nil {
				return
			}

			matchCategory := false
			for _, statementArtifact := range s.Artifacts {
				if policyArtifact.Category == statementArtifact.Category {
					matchCategory = true
					r, err := h.ParseRequirements([]byte(policyArtifact.Requirements))

					if err != nil {
						return err
					}

					c, err := h.ParseClaims([]byte(statementArtifact.Claims))

					if err != nil {
						return err
					}

					// stop checking this bundle at the first artifact that
					// does not met the requirements
					if err = h.Check(r, c); err != nil {
						break
					}
				}
			}

			// do not continue checking this bundle
			// cannot authorize bundles that are not containing at least one artifact
			// that is compatible (i.e. same category) with the one required by this policy entry
			if !matchCategory {
				err = fmt.Errorf("the boot bundle includes a required artifact category")
				break // try with the next policy entry
			}
		}

		// return on the first policy entry that authorize the bundle
		if err == nil {
			return nil
		}
	}

	// return latest error encountered while traversing the policy array
	// that contains the per-bundle rule sets
	return
}

// check validity of the signatures present in the statement against
// the required quorum
// return error if an insufficient number of valid signatures is found
func checkSigningQuorum(p *SigningRequirement, s *statement.Statement) (err error) {
	var validSignatures uint64

	artifacts, err := json.Marshal(s.Artifacts)

	if err != nil {
		return
	}

	// total valid signatures
	validSignatures = 0

	// loop through all the trusted signers set in the policy
	for _, signer := range p.Signers {
		gotValidSignature := false
		for _, sig := range s.Signatures {
			var k crypto.PublicKey
			var s crypto.Signature

			if k, err = key.ParsePublicKey(signer.PubKey); err != nil {
				return
			}

			if s, err = crypto.SignatureFromHex(sig.Signature); err != nil {
				return
			}

			if crypto.Verify(&k, artifacts, &s) {
				gotValidSignature = true
				break
			}
		}

		// do not count twice (or more) multiple valid signature(s) present in
		// the statement that would refer to the same single trusted signer
		if gotValidSignature {
			validSignatures += 1
		}
	}

	if validSignatures < p.Quorum {
		return fmt.Errorf("insufficient number of valid signatures (%d), policy quorum of %d not reached", validSignatures, p.Quorum)
	}

	return
}
