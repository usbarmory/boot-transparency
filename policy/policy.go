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
)

// Statement signature including the signer's public key to ease the verifier
// while checking its validity.
type Signature struct {
	// Ed25519 signer public key in OpenSSH format.
	PubKey string `json:"pub_key"`

	// Ed25519 signature in hex format.
	Signature string `json:"signature"`
}

// Define Artifact structure as a claims container for a given artifact.
type Artifact struct {
	// Type of artifact (e.g. 1: LinuxKernel, 2: Initrd, 3: Dtb, ...).
	Category uint `json:"category"`

	// JSON containing the claims for a given artifact.
	// The set of claims that are supported depends by the artifact category,
	// the JSON format must reflect the underlying structure that is defined
	// in the artifact package for the given category.
	Claims json.RawMessage `json:"claims"`
}

// Define the statement that is logged to the transparency log.
type Statement struct {
	// Human-readable title for the bundle.
	Description string `json:"description,omitempty"`

	// Bundle version, using Semantic Versioning 2.0.0 (see semver.org).
	Version string `json:"version,omitempty"`

	// Artifact claims.
	Artifacts []Artifact `json:"artifacts"`

	// Statement signatures.
	Signatures []Signature `json:"signatures,omitempty"`
}

// Define a trusted signer that can be used to verify statement signatures.
type Signer struct {
	// Human-readable signer name.
	Name string `json:"name,omitempty"`

	// Signer's public key.
	PubKey string `json:"pub_key"`
}

// Define a signing quorum that must be satisfied to authorize the bundle.
type SigningRequirement struct {
	// List of trusted signers that are participating to the quorum.
	Signers []Signer `json:"signers"`

	// Require at least n signatures out of the total number of trusted signers.
	Quorum uint64 `json:"quorum"`
}

// Define the required set of properties to authorize an artifact from a given category.
type ArtifactRequirements struct {
	// Define the artifact category (e.g. LinuxKernel, Initrd, Dtb, ...).
	Category uint `json:"category"`

	// JSON containing the list of properties that must.
	// match the claims for an artifact of this category.
	// The set of properties that are supported depends by the artifact category.
	// The JSON format should reflect the underlying structure that is defined
	// in the artifact package for the given category.
	Requirements json.RawMessage `json:"requirements"`
}

// Define the policy entry as a set of requirements to authorize a given bundle of artifacts.
type PolicyEntry struct {
	// Artifact rules.
	Artifacts []ArtifactRequirements `json:"artifacts"`

	// Require at least a quorum of n signatures for the bundle.
	Signatures SigningRequirement `json:"signatures,omitempty"`
}

// Parse the logged statement which is included as serialized JSON in the proof bundle.
func ParseClaims(jsonStatement []byte) (s *Statement, err error) {
	var h artifact.Handler

	if err = json.Unmarshal(jsonStatement, &s); err != nil {
		return
	}

	for _, a := range s.Artifacts {
		// Check if an artifact handler is registered for the given artifact category.
		h, err = artifact.GetHandler(a.Category)

		if err != nil {
			return
		}

		// Invoke the correspondent claims parser for the given artifact category.
		if _, err = h.ParseClaims(a.Claims); err != nil {
			return
		}
	}

	return
}

// Parse the boot policy requirements from the serialized JSON.
//
// Return error if:
//   - the parsing fails.
func ParseRequirements(jsonPolicy []byte) (policy *[]PolicyEntry, err error) {
	var h artifact.Handler

	if err = json.Unmarshal(jsonPolicy, &policy); err != nil {
		return
	}

	// the policy is an array of entries (i.e. per-bundle requirements).
	// Each entry needs deeper parsing to ensure consistency between the specified
	// artifact requirements and the ones supported by the given artifact category.
	for _, entry := range *policy {
		for _, a := range entry.Artifacts {
			// Check if an artifact handler is registered for the given artifact category.
			h, err = artifact.GetHandler(a.Category)
			if err != nil {
				return
			}

			// Invoke the correspondent requirement parser for the given artifact category.
			if _, err = h.ParseRequirements(a.Requirements); err != nil {
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
//   - the requirement parsing fails.
func Check(p *[]PolicyEntry, s *Statement) (err error) {
	var h artifact.Handler

	// Traverse the policy.
	for _, entry := range *p {
		// Reset any error got while checking the previous policy entry.
		err = nil

		// If this policy entry requires a signing quorum to authorize the bundle,
		// check the number of valid signatures in the logged statement.
		if entry.Signatures.Quorum > 0 {
			err = isSigningQuorumSatisfied(&entry.Signatures, s)
			if err != nil {
				continue // Quorum not satisfied try with the next policy entry.
			}
		}

		// Check all the per-category requirements against the claimed
		// properties for the artifacts present in the bundle.
		for _, policyArtifact := range entry.Artifacts {
			// This means that the latest checked artifact did not met the requirements.
			if err != nil {
				break // Try with the next policy entry.
			}

			h, err = artifact.GetHandler(policyArtifact.Category)

			// Return immediately if the policy requirements for this artifact
			// cannot be checked. The handler for this category, that is included
			// in the policy, is not registered.
			if err != nil {
				return
			}

			matchCategory := false
			for _, statementArtifact := range s.Artifacts {
				if policyArtifact.Category == statementArtifact.Category {
					matchCategory = true
					r, parseError := h.ParseRequirements([]byte(policyArtifact.Requirements))

					if parseError != nil {
						return parseError
					}

					c, parseError := h.ParseClaims([]byte(statementArtifact.Claims))

					if parseError != nil {
						return parseError
					}

					// Stop checking this bundle at the first artifact that
					// does not met the requirements.
					err = h.Check(r, c)
					if err != nil {
						break
					}
				}
			}

			// Do not continue checking this bundle.
			// It cannot authorize bundles that are not containing at least one artifact
			// that is compatible (i.e. same category) with the one required by this policy entry.
			if !matchCategory {
				err = fmt.Errorf("the boot bundle does not include a required artifact category")
				break // Try with the next policy entry.
			}
		}

		// Return on the first policy entry that authorize the bundle.
		if err == nil {
			return
		}
	}

	// Return latest error encountered while traversing the policy array
	// that contains the per-bundle rule sets.
	return
}

// Check validity of the signatures present in the statement against
// the required quorum.
//
// Return error if an insufficient number of valid signatures is found.
func isSigningQuorumSatisfied(p *SigningRequirement, s *Statement) (err error) {
	var validSignatures uint64

	artifacts, err := json.Marshal(s.Artifacts)

	if err != nil {
		return
	}

	// Total valid signatures.
	validSignatures = 0

	// Loop through all the trusted signers set in the policy.
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

		// Do not count twice (or more) multiple valid signature(s) present in
		// the statement that would refer to the same single trusted signer.
		if gotValidSignature {
			validSignatures += 1
		}
	}

	if validSignatures < p.Quorum {
		return fmt.Errorf("insufficient number of valid signatures (%d), policy quorum of %d not reached", validSignatures, p.Quorum)
	}

	return
}
