// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package windows_bootmgr

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"

	"github.com/usbarmory/boot-transparency/artifact"
)

// WindowsBootMgr represents the WindowsBootMgr handler.
type WindowsBootMgr struct{}

// Register the handler for the WindowsBootMgr category.
func init() {
	h := WindowsBootMgr{}
	artifact.Add(&h, artifact.WindowsBootMgr)
}

// ParseRequirements parses requirements for the WindowsBootMgr category.
func (h *WindowsBootMgr) ParseRequirements(jsonRequirements []byte) (interface{}, error) {
	var r Requirements

	if err := json.Unmarshal(jsonRequirements, &r); err != nil {
		return nil, err
	}

	return &r, nil
}

// ParseClaims parses claims for the WindowsBootMgr category.
func (h *WindowsBootMgr) ParseClaims(jsonClaims []byte) (interface{}, error) {
	var c Claims

	if err := json.Unmarshal(jsonClaims, &c); err != nil {
		return nil, err
	}

	return &c, nil
}

// Validate validates matching between requirements and claims for the WindowsBootMgr category.
func (h *WindowsBootMgr) Validate(require interface{}, claim interface{}) (err error) {
	if _, ok := require.(*Requirements); !ok {
		return fmt.Errorf("invalid policy requirements for WindowsBootMgr")
	}

	if _, ok := claim.(*Claims); !ok {
		return fmt.Errorf("invalid claims for WindowsBootMgr")
	}

	r := require.(*Requirements)
	c := claim.(*Claims)

	// Go through all the supported policy requirements for WindowsBootMgr.
	if err = artifact.ValidateHash(r.FileHash, c.FileHash); err != nil {
		return
	}

	if err = artifact.ValidateHash(r.Authenticode, c.Authenticode); err != nil {
		return
	}

	if err = validateMinVersion(r.MinVersion, c.Version); err != nil {
		return
	}

	if err = validateMaxVersion(r.MaxVersion, c.Version); err != nil {
		return
	}

	if r.Architecture != "" && r.Architecture != c.Architecture {
		return fmt.Errorf("architecture %q does not met requirement", c.Architecture)
	}

	if !artifact.ValidateElementInclusion(r.CompanyName, c.CompanyName) {
		return fmt.Errorf("company name requirement not met")
	}

	if !artifact.ValidateElementInclusion(r.SigningAuthority, c.SigningAuthority) {
		return fmt.Errorf("signing authority requirement not met")
	}

	if err = artifact.ValidateMinVersion(r.MinSVN, c.SVN); err != nil {
		return fmt.Errorf("minimum SVN (Secure Version Number) requirement not met")
	}

	if c.Revoked && !r.Revoked {
		return fmt.Errorf("revoked requirement not met")
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

	if err = artifact.ValidateStringEqual(r.ToolChain, c.ToolChain); err != nil {
		return fmt.Errorf("toolchain requirement not met")
	}

	if err = artifact.ValidateMinTimestamp(r.MinTimestamp, c.Timestamp); err != nil {
		return
	}

	if err = artifact.ValidateMap(r.Metadata, c.Metadata); err != nil {
		return fmt.Errorf("metadata requirement %q not met", r.Metadata)
	}

	return
}

// Validate the minimum versioning requirement supporting two formats:
// 1. try using the Windows versioning (e.g. 20H2)
// 2. if 1. fails, try using the semantic versioning
// if both 1. and 2. fails return error.
func validateMinVersion(require string, claim string) (err error) {
	if require == "" {
		return
	}

	// 1. Check if the Windows versioning is being used (e.g. 20H2).
	re := regexp.MustCompile(`^(\d{2})H(\d+)$`)
	requireMatches := re.FindStringSubmatch(require)
	claimMatches := re.FindStringSubmatch(claim)

	if len(requireMatches) == 3 {
		if len(claimMatches) != 3 {
			return fmt.Errorf("invalid claimed version")
		}

		requireMajor, err := strconv.ParseUint(requireMatches[1], 16, 16)
		if err != nil {
			return fmt.Errorf("invalid requirement for minimum version")
		}

		requireMinor, err := strconv.ParseUint(requireMatches[2], 16, 16)
		if err != nil {
			return fmt.Errorf("invalid requirement for minimum version")
		}

		claimMajor, err := strconv.ParseUint(claimMatches[1], 16, 16)
		if err != nil {
			return fmt.Errorf("invalid claimed version")
		}

		claimMinor, err := strconv.ParseUint(claimMatches[2], 16, 16)
		if err != nil {
			return fmt.Errorf("invalid claimed version")
		}

		if claimMajor < requireMajor {
			return fmt.Errorf("minimum version requirement not met")
		}

		if claimMajor == requireMajor && claimMinor < requireMinor {
			return fmt.Errorf("minimum version requirement not met")
		}
	}

	// 2. Otherwise try to use semantic versioning check.
	if err = artifact.ValidateMinVersion(require, claim); err != nil {
		return
	}

	return
}

// Validate the maximum versioning requirement supporting two formats:
// 1. try using the Windows versioning (e.g. 20H2)
// 2. if 1. fails, try using the semantic versioning
// if both 1. and 2. fails return error.
func validateMaxVersion(require string, claim string) (err error) {
	if require == "" {
		return
	}

	// 1. Check if the Windows versioning is being used (e.g. 20H2).
	re := regexp.MustCompile(`^(\d{2})H(\d+)$`)
	requireMatches := re.FindStringSubmatch(require)
	claimMatches := re.FindStringSubmatch(claim)

	if len(requireMatches) == 3 {
		if len(claimMatches) != 3 {
			return fmt.Errorf("invalid claimed version")
		}

		requireMajor, err := strconv.ParseUint(requireMatches[1], 16, 16)
		if err != nil {
			return fmt.Errorf("invalid requirement for maximum version")
		}

		requireMinor, err := strconv.ParseUint(requireMatches[2], 16, 16)
		if err != nil {
			return fmt.Errorf("invalid requirement for maximum version")
		}

		claimMajor, err := strconv.ParseUint(claimMatches[1], 16, 16)
		if err != nil {
			return fmt.Errorf("invalid claimed version")
		}

		claimMinor, err := strconv.ParseUint(claimMatches[2], 16, 16)
		if err != nil {
			return fmt.Errorf("invalid claimed version")
		}

		if claimMajor > requireMajor {
			return fmt.Errorf("maximum version requirement not met")
		}

		if claimMajor == requireMajor && claimMinor > requireMinor {
			return fmt.Errorf("maximum version requirement not met")
		}
	}

	// 2. Otherwise try to use semantic versioning check.
	if err = artifact.ValidateMaxVersion(require, claim); err != nil {
		return
	}

	return
}
