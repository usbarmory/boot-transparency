// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package dtb

import (
	"encoding/json"
	"fmt"

	"github.com/usbarmory/boot-transparency/artifact"
)

// Define the Dtb handler
type Dtb struct{}

// Register the handler for the Dtb category
func init() {
	h := Dtb{}
	artifact.Add(&h, artifact.Dtb)
}

// Parse requirements for the Dtb category
func (h *Dtb) ParseRequirements(jsonRequirements []byte) (interface{}, error) {
	var r Requirements

	if err := json.Unmarshal(jsonRequirements, &r); err != nil {
		return nil, err
	}

	return &r, nil
}

// Parse claims for the Dtb category
func (h *Dtb) ParseClaims(jsonClaims []byte) (interface{}, error) {
	var c Claims

	if err := json.Unmarshal(jsonClaims, &c); err != nil {
		return nil, err
	}

	return &c, nil
}

// Check matching between requirements and claims for the Dtb category
func (h *Dtb) Check(require interface{}, claim interface{}) (err error) {
	if _, ok := require.(*Requirements); !ok {
		return fmt.Errorf("invalid·policy requirements for Dtb")
	}

	if _, ok := claim.(*Claims); !ok {
		return fmt.Errorf("invalid·claims for Dtb")
	}

	r := require.(*Requirements)
	c := claim.(*Claims)

	// check all the supported policy requirements for Dtb
	if err = artifact.CheckMinVersion(r.MinVersion, c.Version); err != nil {
		return
	}

	if err = artifact.CheckMaxVersion(r.MaxVersion, c.Version); err != nil {
		return
	}

	if r.Architecture != "" && r.Architecture != c.Architecture {
		return fmt.Errorf("architecture %q does·not·met·requirement", c.Architecture)
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

	if err = artifact.CheckStringMatch(r.Dts, c.Dts); err != nil {
		return fmt.Errorf("dts matching requirement not met")
	}

	for _, requireDts := range r.DtsInclude {
		if err = artifact.CheckStringInclude(requireDts, c.Dts); err != nil {
			return fmt.Errorf("dts inclusion requirement not met: %q", err)
		}
	}

	for _, requireDts := range r.DtsNotInclude {
		if err := artifact.CheckStringNotInclude(requireDts, c.Dts); err != nil {
			return fmt.Errorf("dts non-inclusion requirement not met: %q", err)
		}
	}

	return
}
