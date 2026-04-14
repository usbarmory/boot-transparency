// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package policy

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"

	"github.com/usbarmory/boot-transparency/artifact"
)

// ErrValidate represent a policy validation error.
var ErrValidate = errors.New("policy validation error")

// ErrParseRequirements represents a policy requirements parsing error.
var ErrParseRequirements = errors.New("requirements parsing error")

// ErrParseStatement represents a statement parsing error.
var ErrParseStatement = errors.New("statement parsing error")

// ErrHashMismatch represents an hash mismatch error.
var ErrHashMismatch = errors.New("hash mismatch")

// ErrInvalidBootEntry represents an invalid boot entry error.
var ErrInvalidBootEntry = errors.New("invalid boot entry")

// Signature represents a Statement signature including the signer's public key
// to ease the verifier while checking its validity.
type Signature struct {
	// PubKey represents the Ed25519 signer public key in OpenSSH format.
	PubKey string `json:"pub_key"`

	// Signature represents the Ed25519 signature in hex format.
	Signature string `json:"signature"`
}

// Artifact represents the artifact structure containing the claims for a given artifact.
type Artifact struct {
	// Category represents the type of artifact (e.g. 1: LinuxKernel, 2: Initrd, 3: Dtb, ...).
	Category uint `json:"category"`

	// Claims represents a JSON containing the claims for a given artifact.
	// The set of claims that are supported depends by the artifact category,
	// the JSON format must reflect the underlying structure that is defined
	// in the artifact package for the given category.
	Claims json.RawMessage `json:"claims"`
}

// StatementHeader represents the statement header.
type StatementHeader struct {
	// Description represents a human-readable description/title for the bundle.
	Description string `json:"description,omitempty"`

	// Revision represents the bundle version, using Semantic Versioning 2.0.0 (see semver.org).
	Revision string `json:"revision,omitempty"`

	// PlatformID represents an (optional) platform identifier.
	PlatformID string `json:"platform_id,omitempty"`
}

// Statements represents the entire statement that is logged to the transparency log.
type Statement struct {
	// Header represents the Statement header.
	Header StatementHeader `json:"header"`

	// Artifacts represents the artifact claims.
	Artifacts []Artifact `json:"artifacts"`

	// Signatures represents the Statement signatures
	// (Header and Artifacts fields are both included in the signed data).
	Signatures []Signature `json:"signatures,omitempty"`
}

// Signer represents a trusted signer that can be used to verify statement signatures.
type Signer struct {
	// Name represents a human-readable signer name.
	Name string `json:"name,omitempty"`

	// PubKey represents a signer's public key.
	PubKey string `json:"pub_key"`
}

// SigningRequirement represents a signing quorum that must be satisfied to authorize the bundle.
type SigningRequirement struct {
	// Signers represents the list of trusted signers that are participating to the quorum.
	Signers []Signer `json:"signers"`

	// Quorum represents the required quorum:
	// require at least n signatures out of the total number of trusted signers.
	Quorum uint64 `json:"quorum"`
}

// ArtifactRequirements represents a set of properties that are required to authorize
// an artifact from a given category.
type ArtifactRequirements struct {
	// Category represents the artifact category (e.g. LinuxKernel, Initrd, Dtb, ...).
	Category uint `json:"category"`

	// Requirements represents a JSON containing the list of properties that must.
	// match the claims for an artifact of this category.
	// The set of properties that are supported depends by the artifact category.
	// The JSON format should reflect the underlying structure that is defined
	// in the artifact package for the given category.
	Requirements json.RawMessage `json:"requirements"`
}

// PolicyEntry represents a policy entry, which is as a set of requirements
// to authorize a given bundle of artifacts.
type PolicyEntry struct {
	// Artifacts represents the list of per-artifact category rules.
	Artifacts []ArtifactRequirements `json:"artifacts"`

	// Signatures represents the required signing quorum:
	// requires at least a quorum of n signatures to be present in the bundle.
	Signatures SigningRequirement `json:"signatures,omitempty"`
}

// BootArtifact represents the artifact that has been loaded by the software
// compoment which is requiring the boot-transparency validation (e.g. the bootloader,
// or the user-space updating tool, importing this library).
type BootArtifact struct {
	// Category represents the artifact category (e.g. LinuxKernel, Initrd, Dtb, ...).
	Category uint

	// Data represents the bytes of the artifact.
	Data []byte

	// Metadata represents ancillary information on the loading process for
	// the given artifact.
	// Such information cannot be specified in the statement claims as they
	// are dependant by the specific loader configuration environment (e.g.
	// `cmdline` for LinuxKernel artifacts). These metadata allows implementing
	// policy authorization logics based on combinations of the statement claims
	// and these informations passed by the loader.
	Metadata map[string]string

	// hash represents the computed checksum of the artifact.
	hash []byte
}

// BootEntry represents a boot entry as a set of boot artifacts.
type BootEntry struct {
	// Artifacts represents a set of [BootArtifact]
	Artifacts []BootArtifact
}

// ParseStatement parses the logged statement which is included as serialized
// JSON in the proof bundle.
func ParseStatement(jsonStatement []byte) (s *Statement, err error) {
	var h artifact.Handler

	if err = json.Unmarshal(jsonStatement, &s); err != nil {
		return nil, fmt.Errorf("%w, %w", ErrParseStatement, err)
	}

	for _, a := range s.Artifacts {
		// Check if an artifact handler is registered for the given artifact category.
		h, err = artifact.GetHandler(a.Category)

		if err != nil {
			return nil, fmt.Errorf("%w, %w", ErrParseStatement, err)
		}

		// Invoke the correspondent claims parser for the given artifact category.
		if _, err = h.ParseClaims(a.Claims); err != nil {
			return nil, fmt.Errorf("%w, %w", ErrParseStatement, err)
		}
	}

	return
}

// ParseRequirements parses the boot policy requirements from the serialized JSON.
func ParseRequirements(jsonPolicy []byte) (policy *[]PolicyEntry, err error) {
	var h artifact.Handler

	if err = json.Unmarshal(jsonPolicy, &policy); err != nil {
		return nil, fmt.Errorf("%w, %w", ErrParseRequirements, err)
	}

	// the policy is an array of entries (i.e. per-bundle requirements).
	// Each entry needs deeper parsing to ensure consistency between the specified
	// artifact requirements and the ones supported by the given artifact category.
	for _, entry := range *policy {
		for _, a := range entry.Artifacts {
			// Check if an artifact handler is registered for the given artifact category.
			h, err = artifact.GetHandler(a.Category)
			if err != nil {
				return nil, fmt.Errorf("%w, %w", ErrParseRequirements, err)
			}

			// Invoke the correspondent requirement parser for the given artifact category.
			if _, err = h.ParseRequirements(a.Requirements); err != nil {
				return nil, fmt.Errorf("%w, %w", ErrParseRequirements, err)
			}
		}
	}

	return
}

// Validate validates a given [BootEntry].
// The set of loaded artifacts is required to validate the actual correspondency
// between the claimed file hashes and the ones loaded in memory that are
// being authorized.
// The statement claims are validated against the policy requirements.
// The policy array (i.e. list of per-artifact bundle requirements) is
// traversed to verify whether there is at least one entry
// matching the claims for the artifacts bundle.
//
// The logic applied depends by the artifact category, and thus,
// it is defined in the corresponding artifact package.
//
// Return ErrValidate error if:
//   - the bundle does not met the policy requirements
//   - the claim parsing fails
//   - the requirement parsing fails.
func (be *BootEntry) Validate(p *[]PolicyEntry, s *Statement) (err error) {
	var h artifact.Handler

	// Before start traversing the policy, the validateStatementHashes guarantees
	// that the claims included in the statement are referring to the same files
	// included in the boot entry that is being authorized.
	if err = be.validateStatementHashes(s); err != nil {
		return fmt.Errorf("%w, %w", ErrValidate, err)
	}

	// Traverse the policy.
	for _, entry := range *p {
		// Reset any error got while checking the previous policy entry.
		err = nil

		// If this policy entry requires a signing quorum to authorize the bundle,
		// check the number of valid signatures in the logged statement.
		if entry.Signatures.Quorum > 0 {
			err = isSigningQuorumSatisfied(&entry.Signatures, s)
			if err != nil {
				err = fmt.Errorf("signing quorum validation failed, %w", err)
				continue // Quorum not satisfied try with the next policy entry.
			}
		}

		// Validate all the per-category requirements against the claimed
		// properties for the artifacts present in the bundle.
		for _, policyArtifact := range entry.Artifacts {
			// This means that the latest validated artifact did not met the requirements.
			if err != nil {
				break // Try with the next policy entry.
			}

			h, err = artifact.GetHandler(policyArtifact.Category)

			// Return immediately if the policy requirements for this artifact
			// cannot be validated. The handler for this category, that is included
			// in the policy, is not registered.
			if err != nil {
				return fmt.Errorf("%w, %w", ErrValidate, err)
			}

			matchCategory := false
			for _, statementArtifact := range s.Artifacts {
				if policyArtifact.Category == statementArtifact.Category {
					matchCategory = true

					r, parseError := h.ParseRequirements([]byte(policyArtifact.Requirements))
					if parseError != nil {
						return fmt.Errorf("%w, %w", ErrValidate, parseError)
					}

					c, parseError := h.ParseClaims([]byte(statementArtifact.Claims))
					if parseError != nil {
						return fmt.Errorf("%w, %w", ErrValidate, parseError)
					}

					// Stop validating this bundle at the first artifact that
					// does not met the requirements.
					err = h.Validate(r, c)
					if err != nil {
						break
					}
				}
			}

			// Do not continue validation for this bundle.
			// It cannot authorize bundles that are not containing at least one artifact
			// that is compatible (i.e. same category) with the one required by this policy entry.
			if !matchCategory {
				err = fmt.Errorf("the boot bundle does not include any required artifact, category %d", policyArtifact.Category)
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
	if err != nil {
		err = fmt.Errorf("%w, %w", ErrValidate, err)
	}

	return
}

// isSigningQuorumSatisfied validates the presence of a sufficient number of valid signatures in the statement,
// according with the specified quorum.
//
// Return error if an insufficient number of valid signatures is found.
func isSigningQuorumSatisfied(p *SigningRequirement, s *Statement) (err error) {
	var validSignatures uint64

	header, err := json.Marshal(s.Header)
	if err != nil {
		return
	}

	artifacts, err := json.Marshal(s.Artifacts)
	if err != nil {
		return
	}

	// Header and Artifacts are both included in the signed data.
	parts := [][]byte{header, artifacts}
	signedData := bytes.Join(parts, nil)

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

			if crypto.Verify(&k, signedData, &s) {
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
		return fmt.Errorf("insufficient valid signatures, %d/%d", validSignatures, p.Quorum)
	}

	return
}

func (be BootEntry) validateStatementHashes(s *Statement) (err error) {
	for _, a := range be.Artifacts {
		if err = a.validateStatementHash(s); err != nil {
			return err
		}
	}

	return
}

// Validate the matching between loaded artifact hash and the one included
// in the proof bundle.
// This step is vital to ensure the correspondence between the artifacts
// loaded in memory during the boot and the claims that will be validated.
func (a BootArtifact) validateStatementHash(s *Statement) (err error) {
	var h artifact.Handler
	var found bool

	if len(a.Data) == 0 {
		return fmt.Errorf("%w missing data bytes for artifact category %d", ErrInvalidBootEntry, a.Category)
	}

	for _, claimedArtifact := range s.Artifacts {
		// The claims are referring to a different artifact
		// category, try with next block of claims in the statement.
		if a.Category != claimedArtifact.Category {
			continue
		}

		if h, err = artifact.GetHandler(a.Category); err != nil {
			return
		}

		// boot-transparency expect to parse requirements in JSON format.
		requirements, _ := json.Marshal(map[string]string{"file_hash": hex.EncodeToString(a.Hash())})

		r, err := h.ParseRequirements([]byte(requirements))
		if err != nil {
			return err
		}

		c, err := h.ParseClaims([]byte(claimedArtifact.Claims))
		if err != nil {
			return err
		}

		// The validation logic is safe in the sense that error is returned
		// if a file hash requested by the boot loader is not present in the
		// statement for a given artifact category.
		if err = h.Validate(r, c); err != nil {
			return fmt.Errorf("%w for artifact category %d, hash %q", ErrHashMismatch, a.Category, hex.EncodeToString(a.Hash()))
		}

		found = true
		break
	}

	if !found {
		return fmt.Errorf("one or more artifacts are not present in the proof bundle")
	}

	return
}

// Hash returns the checksum of the boot artifact computed
// by the library hasher. The hasher can be configured via the
// artifact.SetHasher function.
func (a BootArtifact) Hash() []byte {
	// Do not re-compute the checksum of an artifact if it
	// has been already calculated.
	if len(a.hash) == artifact.HashSize() {
		return a.hash
	}

	a.hash = artifact.Sum(a.Data)
	return a.hash
}
