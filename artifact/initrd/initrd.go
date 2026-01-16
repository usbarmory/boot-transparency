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

// Initrd represents the Initrd handler.
type Initrd struct{}

// Register the handler for the Initrd category.
func init() {
	h := Initrd{}
	artifact.Add(&h, artifact.Initrd)
}

// ParseRequirements parses requirements for the Initrd category.
func (h *Initrd) ParseRequirements(jsonRequirements []byte) (interface{}, error) {
	var r Requirements

	if err := json.Unmarshal(jsonRequirements, &r); err != nil {
		return nil, err
	}

	return &r, nil
}

// ParseClaims parses claims for the Initrd category.
func (h *Initrd) ParseClaims(jsonClaims []byte) (interface{}, error) {
	var c Claims

	if err := json.Unmarshal(jsonClaims, &c); err != nil {
		return nil, err
	}

	return &c, nil
}

// Validate validates matching between requirements and claims for the Initrd category.
func (h *Initrd) Validate(require interface{}, claim interface{}) (err error) {
	if _, ok := require.(*Requirements); !ok {
		return fmt.Errorf("invalid policy requirements for Initrd")
	}

	if _, ok := claim.(*Claims); !ok {
		return fmt.Errorf("invalid claims for Initrd")
	}

	r := require.(*Requirements)
	c := claim.(*Claims)

	// Go through all the supported policy requirements for Initrd.
	if err = artifact.ValidateHash(r.FileHash, c.FileHash); err != nil {
		return
	}

	if err = artifact.ValidateMinVersion(r.MinVersion, c.Version); err != nil {
		return
	}

	if err = artifact.ValidateMaxVersion(r.MaxVersion, c.Version); err != nil {
		return
	}

	if r.Architecture != "" && r.Architecture != c.Architecture {
		return fmt.Errorf("architecture %q does not met requirement", c.Architecture)
	}

	if c.Tainted && !r.Tainted {
		return fmt.Errorf("tainted requirement not met")
	}

	if r.Reproducible && !c.Reproducible {
		return fmt.Errorf("reproducible requirement not met")
	}

	if err = artifact.ValidateArrayInclusion(r.License, c.License); err != nil {
		return fmt.Errorf("license requirement not met, %w", err)
	}

	if err = artifact.ValidateMap(r.BuildArgs, c.BuildArgs); err != nil {
		return fmt.Errorf("build args requirement %q not met", r.BuildArgs)
	}

	if err = artifact.ValidateMinTimestamp(r.MinTimestamp, c.Timestamp); err != nil {
		return
	}

	if err = artifact.ValidateMap(r.Metadata, c.Metadata); err != nil {
		return fmt.Errorf("metadata requirement %q not met", r.Metadata)
	}

	return
}
