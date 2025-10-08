// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package uefi_bios

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/usbarmory/boot-transparency/artifact"
)

// Define UEFI BIOS handler
type UEFIBIOS struct{}

// Register the handler for the UEFIBIOS category
func init() {
	h := UEFIBIOS{}
	artifact.Add(&h, artifact.UEFIBIOS)
}

// Parse requirements for the UEFIBIOS category
func (h *UEFIBIOS) ParseRequirements(jsonRequirements []byte) (interface{}, error) {
	var r Requirements

	if err := json.Unmarshal(jsonRequirements, &r); err != nil {
		return nil, err
	}

	return &r, nil
}

// Parse claims for the UEFIBIOS category
func (h *UEFIBIOS) ParseClaims(jsonClaims []byte) (interface{}, error) {
	var c Claims

	if err := json.Unmarshal(jsonClaims, &c); err != nil {
		return nil, err
	}

	return &c, nil
}

// Check matching between requirements and claims for the UEFIBIOS category
func (h *UEFIBIOS) Check(require interface{}, claim interface{}) (err error) {
	if _, ok := require.(*Requirements); !ok {
		return fmt.Errorf("invalid·policy requirements for UEFIBIOS")
	}

	if _, ok := claim.(*Claims); !ok {
		return fmt.Errorf("invalid·claims for UEFIBIOS")
	}

	r := require.(*Requirements)
	c := claim.(*Claims)

	// check all the supported policy requirements for UEFIBIOS
	if err = artifact.CheckMinVersion(r.MinUEFIRevision, c.UEFIRevision); err != nil {
		return
	}

	if err = artifact.CheckMaxVersion(r.MaxUEFIRevision, c.UEFIRevision); err != nil {
		return
	}

	if !artifact.CheckElementInclusion(r.FirmwareVendor, c.FirmwareVendor) {
		return fmt.Errorf("firmware vendor %q does not met requirements", c.FirmwareVendor)
	}

	if r.MinFirmwareRevision != "" {
		requireFirmwareRevision, err := strconv.ParseUint(strings.Trim(r.MinFirmwareRevision, "0x"), 16, 16)
		if err != nil {
			return fmt.Errorf("invalid min firmware revision requirement: %q", r.MinFirmwareRevision)
		}
		claimFirmwareRevision, err := strconv.ParseUint(strings.Trim(c.FirmwareRevision, "0x"), 16, 16)
		if err != nil {
			return fmt.Errorf("invalid firmware revision claim: %q", c.FirmwareRevision)
		}

		if claimFirmwareRevision < requireFirmwareRevision {
			return fmt.Errorf("revision %q does not met min firmware revision requirement", claimFirmwareRevision)
		}
	}

	if r.MaxFirmwareRevision != "" {
		requireFirmwareRevision, err := strconv.ParseUint(r.MaxFirmwareRevision, 16, 16)
		if err != nil {
			return fmt.Errorf("invalid max firmware revision requirement: %q", r.MaxFirmwareRevision)
		}
		claimFirmwareRevision, err := strconv.ParseUint(c.FirmwareRevision, 16, 16)
		if err != nil {
			return fmt.Errorf("invalid firmware revision claim: %q", c.FirmwareRevision)
		}

		if claimFirmwareRevision > requireFirmwareRevision {
			return fmt.Errorf("revision %q does not met max firmware revision requirement", claimFirmwareRevision)
		}
	}

	return
}
