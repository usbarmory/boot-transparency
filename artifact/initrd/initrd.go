// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package initrd

import (
	"encoding/json"
	"fmt"

	"github.com/usbarmory/boot-transparency/artifact"
)

// Define the Initrd handler
type Initrd struct{}

// Register the handler for the Initrd category
func init() {
	h := Initrd{}
	artifact.Add(&h, artifact.Initrd)
}

// Parse requirements for the Initrd category
func (h *Initrd) ParseRequirements(jsonRequirements []byte) (interface{}, error) {
	var r Requirements

	if err := json.Unmarshal(jsonRequirements, &r); err != nil {
		return nil, err
	}

	return &r, nil
}

// Parse claims for the Initrd category
func (h *Initrd) ParseClaims(jsonClaims []byte) (interface{}, error) {
	var c Claims

	if err := json.Unmarshal(jsonClaims, &c); err != nil {
		return nil, err
	}

	return &c, nil
}

// Check matching between requirements and claims for the Initrd category
func (h *Initrd) Check(require interface{}, claim interface{}) (err error) {
	if _, ok := require.(*Requirements); !ok {
		return fmt.Errorf("invalid·policy requirements for Initrd")
	}

	if _, ok := claim.(*Claims); !ok {
		return fmt.Errorf("invalid·claims for Initrd")
	}

	r := require.(*Requirements)
	c := claim.(*Claims)

	// check all the supported policy requirements for Initrd
	if err = artifact.CheckMinVersion(r.MinVersion, c.Version); err != nil {
		return
	}

	if err = artifact.CheckMaxVersion(r.MaxVersion, c.Version); err != nil {
		return
	}

	if r.Architecture != "" && r.Architecture != c.Architecture {
		return fmt.Errorf("architecture %q does·not·met·requirement", c.Architecture)
	}

	if c.Tainted && !r.Tainted {
		return fmt.Errorf("tainted requirement not met")
	}

	if err = artifact.CheckArrayInclusion(r.License, c.License); err != nil {
		return fmt.Errorf("license requirement not met: %q", err)
	}

	if err = artifact.CheckMinTimestamp(r.MinTimestamp, c.Timestamp); err != nil {
		return
	}

	if err = artifact.CheckStringMatch(r.Metadata, c.Metadata); err != nil {
		return fmt.Errorf("metadata matching requirement not met")
	}

	for _, requireMetadata := range r.MetadataInclude {
		if err = artifact.CheckStringInclude(requireMetadata, c.Metadata); err != nil {
			return fmt.Errorf("metadata inclusion requirement not met: %q", err)
		}
	}

	for _, requireMetadata := range r.MetadataNotInclude {
		if err = artifact.CheckStringNotInclude(requireMetadata, c.Metadata); err != nil {
			return fmt.Errorf("metadata non-inclusion requirement not met: %q", err)
		}
	}

	return
}
