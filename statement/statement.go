// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package statement

import (
	"encoding/json"

	"github.com/usbarmory/boot-transparency/artifact"
)

// Signature including the signer's public key to ease the verifier while
// checking its validity
type Signature struct {
	// Ed25519 signer public key in OpenSSH format
	PubKey string `json:"pub_key"`

	// Ed25519 signature in hex format
	Signature string `json:"signature"`
}

// Define Artifact structure as a container for claims for a given artifact
type Artifact struct {
	// type of artifact (e.g. 1: LinuxKernel, 2: Initrd, 3: Dtb, ...)
	Category uint `json:"category"`

	// JSON containing the claims for a given artifact
	// The set of claims that are supported depends by the artifact category,
	// the JSON format must reflect the underlying structure that is defined
	// in the artifact package for the given category.
	Claims json.RawMessage `json:"claims"`
}

// Define the statement that will be logged when releasing a new bundle of artifacts
type Statement struct {
	// human-readable title for the bundle
	Description string `json:"description,omitempty"`

	// bundle version, using Semantic Versioning 2.0.0 (see semver.org)
	Version string `json:"version,omitempty"`

	// artifact claims
	Artifacts []Artifact `json:"artifacts"`

	// statement signatures
	Signatures []Signature `json:"signatures,omitempty"`
}

// Parse the logged statement which is included as serialized JSON in the proof bundle
func Parse(jsonStatement []byte) (s *Statement, err error) {
	var h artifact.Handler

	if err = json.Unmarshal(jsonStatement, &s); err != nil {
		return
	}

	for _, a := range s.Artifacts {
		// check if an artifact handler is registered for the given artifact category
		h, err = artifact.GetHandler(a.Category)

		if err != nil {
			return
		}

		// invoke the correspondent claims parser for the given artifact category
		if _, err = h.ParseClaims(a.Claims); err != nil {
			return
		}
	}

	return
}
