// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package dtb

// Supported policy requirements for Dtb artifact.
type Requirements struct {
	// Required SHA-512 hash of the artifact.
	FileHash string `json:"file_hash,omitempty"`

	// Required minimum version, expressed using Semantic Versioning 2.0.0 (see semver.org).
	MinVersion string `json:"min_version,omitempty"`

	// Maximum allowed version, expressed using Semantic Versioning 2.0.0 (see semver.org).
	MaxVersion string `json:"max_version,omitempty"`

	// Allowed architecture, the architecture vocabulary is the one defined by the EFI specification (i.e. IA32, x64, IA64, ARM, AA64, ...).
	Architecture string `json:"architecture,omitempty"`

	// List of allowed licenses.
	// Where applicable licenses should be expressed as SPDX short-form IDs
	// (e.g.MIT, GPL-2.0-or-later, BSD-2-Clause):
	// https://spdx.github.io/spdx-spec/v2.3/SPDX-license-list/ .
	License []string `json:"license,omitempty"`

	// Allow only artifacts that have been built with certain building arguments.
	// The matching rules are expressed via map[string]string where the keys are
	// the build arguments, and the values are the regular expressions that are tested
	// via regexp.MatchString() against the correspondent keys.
	// If a given key is "only" specified in the requirements, but it is not present in the
	// claims, the test will fail as the matching rule cannot be tested.
	BuildArgs map[string]string `json:"build_args,omitempty"`

	// Allow only artifacts where the claimed timestamp is more recent than the one specified here
	// in RFC3339 format (e.g. "1985-04-12T23:20:50.52Z").
	MinTimestamp string `json:"min_timestamp,omitempty"`

	// Allow only artifacts that are claiming a given set of metadata.
	// The matching rules are expressed via map[string]string where the keys are
	// the build arguments, and the values are the regular expressions that are tested
	// via regexp.MatchString() against the correspondent keys.
	// If a given key is "only" specified in the requirements, but it is not present in the
	// claims, the test will fail as the matching rule cannot be tested.
	Metadata map[string]string `json:"metadata,omitempty"`
}
