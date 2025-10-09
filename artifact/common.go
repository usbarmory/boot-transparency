// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package artifact

import (
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

// Compare claimed file hash to ensure hash requirement is met
func CheckHash(requireHash string, claimHash string) (err error) {
	// nothing to check
	if requireHash == "" {
		return
	}

	r, err := hex.DecodeString(requireHash)
	if err != nil {
		return fmt.Errorf("invalid hash requirement: %q", err)
	}

	c, err := hex.DecodeString(claimHash)
	if err != nil {
		return fmt.Errorf("invalid hash claim: %q", err)
	}

	if len(r) != sha512.Size {
		return fmt.Errorf("invalid requirement hash length: %q", requireHash)
	}

	if len(c) != sha512.Size {
		return fmt.Errorf("invalid claim hash length: %q", claimHash)
	}

	if subtle.ConstantTimeCompare([]byte(r), []byte(c)) != 1 {
		return fmt.Errorf("hash %q does not met requirements", claimHash)
	}

	return
}

// Compare semantic versions to ensure minimum version requirement is met
func CheckMinVersion(requireVersion string, claimVersion string) (err error) {
	// nothing to check
	if requireVersion == "" {
		return
	}

	if !semver.IsValid(requireVersion) {
		return fmt.Errorf("invalid min version requirement: %q", requireVersion)
	}
	if !semver.IsValid(claimVersion) {
		return fmt.Errorf("invalid version claim: %q", claimVersion)
	}
	if semver.Compare(claimVersion, requireVersion) < 0 {
		return fmt.Errorf("version %q does not met min version requirement", claimVersion)
	}

	return
}

// Compare semantic versions to ensure maximum version requirement is met
func CheckMaxVersion(requireVersion string, claimVersion string) (err error) {
	// nothing to check
	if requireVersion == "" {
		return
	}

	if !semver.IsValid(requireVersion) {
		return fmt.Errorf("invalid max version requirement: %q", requireVersion)
	}
	if !semver.IsValid(claimVersion) {
		return fmt.Errorf("invalid version claim: %q", claimVersion)
	}
	if semver.Compare(claimVersion, requireVersion) > 0 {
		return fmt.Errorf("version %q does not met max version requirement", claimVersion)
	}

	return
}

// Check the inclusion of an array of claimed strings within the required one
func CheckArrayInclusion(require []string, claim []string) (err error) {
	if len(require) == 0 {
		return
	}

	for _, c := range claim {
		if !CheckElementInclusion(require, c) {
			return fmt.Errorf("%q not allowed", c)
		}
	}

	return
}

// Check the inclusion of a claimed string within an array of required ones
func CheckElementInclusion(slice []string, element string) bool {
	for _, v := range slice {
		if v == element {
			return true
		}
	}

	return false
}

// Check the claimed timestamp to ensure the min timestamp requirement is met
func CheckMinTimestamp(requireMinTimestamp string, claimTimestamp string) (err error) {
	if requireMinTimestamp == "" {
		return
	}

	r, err := time.Parse(time.RFC3339, requireMinTimestamp)
	if err != nil {
		return fmt.Errorf("invalid min timestamp requirement: %q", requireMinTimestamp)
	}

	c, err := time.Parse(time.RFC3339, claimTimestamp)
	if err != nil {
		return fmt.Errorf("invalid timestamp claim: %q", claimTimestamp)
	}

	if r.After(c) {
		return fmt.Errorf("timestamp %q does not met min timestamp requirement", claimTimestamp)
	}

	return
}

// Check if string matching requirement is met
func CheckStringMatch(require string, claim string) (err error) {
	if require == "" {
		return
	}

	if require != claim {
		return fmt.Errorf("claimed string does not match requirement")
	}

	return
}

// Check if string inclusion requirement is met
func CheckStringInclude(require string, claim string) (err error) {
	if require == "" {
		return
	}

	if !strings.Contains(claim, require) {
		return fmt.Errorf("claimed string is not included in the requirement")
	}

	return
}

// Check if string non-inclusion requirement is met
func CheckStringNotInclude(require string, claim string) (err error) {
	if require == "" {
		return
	}

	if strings.Contains(claim, require) {
		return fmt.Errorf("claimed string is included in the requirement")
	}

	return
}
