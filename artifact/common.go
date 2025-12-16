// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package artifact

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

// ValidateHash compares claimed file hash to ensure hash requirement is met.
func ValidateHash(requireHash string, claimHash string) (err error) {
	if requireHash == "" {
		return
	}

	r, err := hex.DecodeString(requireHash)
	if err != nil {
		return fmt.Errorf("invalid hash requirement, %w", err)
	}

	c, err := hex.DecodeString(claimHash)
	if err != nil {
		return fmt.Errorf("invalid hash claim, %w", err)
	}

	if len(r) != sha256.Size {
		return fmt.Errorf("invalid requirement hash length %q", requireHash)
	}

	if len(c) != sha256.Size {
		return fmt.Errorf("invalid claim hash length %q", claimHash)
	}

	if len(r) != len(c) {
		return fmt.Errorf("require and claim hashes must have the same length")
	}

	if subtle.ConstantTimeCompare([]byte(r), []byte(c)) != 1 {
		return fmt.Errorf("hash %q does not met requirements", claimHash)
	}

	return
}

// ValidateMinVersion compare semantic versions to ensure minimum version requirement is met.
func ValidateMinVersion(requireVersion string, claimVersion string) (err error) {
	if requireVersion == "" {
		return
	}

	if !semver.IsValid(requireVersion) {
		return fmt.Errorf("invalid min version requirement %q", requireVersion)
	}
	if !semver.IsValid(claimVersion) {
		return fmt.Errorf("invalid version claim %q", claimVersion)
	}
	if semver.Compare(claimVersion, requireVersion) < 0 {
		return fmt.Errorf("version %q does not met min version requirement", claimVersion)
	}

	return
}

// ValidateMaxVersion compares semantic versions to ensure maximum version requirement is met.
func ValidateMaxVersion(requireVersion string, claimVersion string) (err error) {
	if requireVersion == "" {
		return
	}

	if !semver.IsValid(requireVersion) {
		return fmt.Errorf("invalid max version requirement %q", requireVersion)
	}
	if !semver.IsValid(claimVersion) {
		return fmt.Errorf("invalid version claim %q", claimVersion)
	}
	if semver.Compare(claimVersion, requireVersion) > 0 {
		return fmt.Errorf("version %q does not met max version requirement", claimVersion)
	}

	return
}

// ValidateMap traverse a given map[string]string to ensure all the required keys
// are matching (i.e. regular expression matching) the correpondent claims.
func ValidateMap(require map[string]string, claim map[string]string) (err error) {
	if len(require) != 0 {
		for key, regexp := range require {
			c, found := claim[key]
			if !found {
				return fmt.Errorf("required key not present in the claims")
			}

			if err = ValidateStringMatch(c, regexp); err != nil {
				return
			}
		}
	}

	return
}

// ValidateArrayInclusion validates inclusion of an array of claimed strings within the required one.
func ValidateArrayInclusion(require []string, claim []string) (err error) {
	if len(require) == 0 {
		return
	}

	for _, c := range claim {
		if !ValidateElementInclusion(require, c) {
			return fmt.Errorf("%q not allowed", c)
		}
	}

	return
}

// ValidateElementInclusion validates inclusion of a claimed string within an array of required ones.
func ValidateElementInclusion(slice []string, element string) bool {
	for _, v := range slice {
		if v == element {
			return true
		}
	}

	return false
}

// ValidateMinTimestamp validates the claimed timestamp to ensure the min timestamp requirement is met.
func ValidateMinTimestamp(requireMinTimestamp string, claimTimestamp string) (err error) {
	if requireMinTimestamp == "" {
		return
	}

	r, err := time.Parse(time.RFC3339, requireMinTimestamp)
	if err != nil {
		return fmt.Errorf("invalid min timestamp requirement, %w", err)
	}

	c, err := time.Parse(time.RFC3339, claimTimestamp)
	if err != nil {
		return fmt.Errorf("invalid timestamp claim, %w", err)
	}

	if r.After(c) {
		return fmt.Errorf("timestamp %q does not met min timestamp requirement", claimTimestamp)
	}

	return
}

// ValidateStringMatch validates if string is matching a regexp requirement.
func ValidateStringMatch(require string, claim string) (err error) {
	if require == "" {
		return
	}

	r, err := regexp.Compile(require)

	if err != nil {
		return fmt.Errorf("invalid regular expression")
	}

	if !r.MatchString(claim) {
		return fmt.Errorf("claimed string does not match required regexp")
	}

	return
}

// ValidateStringEqual validates if string matching equal requirement is met.
func ValidateStringEqual(require string, claim string) (err error) {
	if require == "" {
		return
	}

	if require != claim {
		return fmt.Errorf("claimed string is not equal to the requirement")
	}

	return
}

// ValidateStringInclude validates if string inclusion requirement is met.
func ValidateStringInclude(require string, claim string) (err error) {
	if require == "" {
		return
	}

	if !strings.Contains(claim, require) {
		return fmt.Errorf("claimed string is not included in the requirement")
	}

	return
}

// ValidateStringNotInclude validates if string non-inclusion requirement is met.
func ValidateStringNotInclude(require string, claim string) (err error) {
	if require == "" {
		return
	}

	if strings.Contains(claim, require) {
		return fmt.Errorf("claimed string is included in the requirement")
	}

	return
}
