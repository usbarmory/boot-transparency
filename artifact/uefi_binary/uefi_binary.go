// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package uefi_binary

import (
	"encoding/json"
	"fmt"

	"github.com/usbarmory/boot-transparency/artifact"
)

// Define the UEFIBinary handler.
type UEFIBinary struct{}

// Register the handler for the UEFIBinary category.
func init() {
	h := UEFIBinary{}
	artifact.Add(&h, artifact.UEFIBinary)
}

// Parse requirements for the UEFIBinary category.
func (h *UEFIBinary) ParseRequirements(jsonRequirements []byte) (interface{}, error) {
	var r Requirements

	if err := json.Unmarshal(jsonRequirements, &r); err != nil {
		return nil, err
	}

	return &r, nil
}

// Parse claims for the UEFIBinary category.
func (h *UEFIBinary) ParseClaims(jsonClaims []byte) (interface{}, error) {
	var c Claims

	if err := json.Unmarshal(jsonClaims, &c); err != nil {
		return nil, err
	}

	return &c, nil
}

// Check matching between requirements and claims for the UEFIBinary category.
func (h *UEFIBinary) Check(require interface{}, claim interface{}) (err error) {
	if _, ok := require.(*Requirements); !ok {
		return fmt.Errorf("invalid policy requirements for UEFIBinary")
	}

	if _, ok := claim.(*Claims); !ok {
		return fmt.Errorf("invalid claims for UEFIBinary")
	}

	r := require.(*Requirements)
	c := claim.(*Claims)

	// Check all the supported policy requirements for UEFIBinary.
	if err = artifact.CheckHash(r.FileHash, c.FileHash); err != nil {
		return
	}

	if err = artifact.CheckMinVersion(r.MinVersion, c.Version); err != nil {
		return
	}

	if err = artifact.CheckMaxVersion(r.MaxVersion, c.Version); err != nil {
		return
	}

	if r.Architecture != "" && r.Architecture != c.Architecture {
		return fmt.Errorf("architecture %q does not met requirement", c.Architecture)
	}

	if r.Reproducible && !c.Reproducible {
		return fmt.Errorf("reproducible requirement not met")
	}

	if err = artifact.CheckArrayInclusion(r.License, c.License); err != nil {
		return fmt.Errorf("license requirement not met, %w", err)
	}

	if err = artifact.CheckMap(r.BuildArgs, c.BuildArgs); err != nil {
		return fmt.Errorf("build args requirement %q not met", r.BuildArgs)
	}

	if err = artifact.CheckStringEqual(r.ToolChain, c.ToolChain); err != nil {
		return fmt.Errorf("toolchain requirement not met")
	}

	if err = artifact.CheckMinTimestamp(r.MinTimestamp, c.Timestamp); err != nil {
		return
	}

	if err = artifact.CheckMap(r.Metadata, c.Metadata); err != nil {
		return fmt.Errorf("metadata requirement %q not met", r.Metadata)
	}

	return
}
