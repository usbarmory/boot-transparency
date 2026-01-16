// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package linux_kernel

// Requirements represents the supported policy requirements for LinuxKernel artifact.
type Requirements struct {
	// FileHash represents the required hash of the artifact (currently only SHA-256 is supported).
	FileHash string `json:"file_hash,omitempty"`

	// MinVersion represents the required minimum version, expressed using Semantic Versioning 2.0.0 (see semver.org).
	MinVersion string `json:"min_version,omitempty"`

	// MaxVersion represents the maximum allowed version, expressed using Semantic Versioning 2.0.0 (see semver.org).
	MaxVersion string `json:"max_version,omitempty"`

	// Architecture represents the allowed artifact architecture using the vocabulary defined
	// by the EFI specification (i.e. IA32, x64, IA64, ARM, AA64, ...).
	Architecture string `json:"architecture,omitempty"`

	// Tainted represents the required tainted condition.
	// If set to false, this allows to authorize only non-tainted kernels.
	Tainted bool `json:"tainted,omitempty"`

	// Reproducible represents the reproducibility of the artifact binary.
	// This allows to authorize only artifacts built via a reproducible process.
	Reproducible bool `json:"reproducible,omitempty"`

	// License represents the list of allowed licenses that can be associated
	// to this artifact.
	// Where applicable licenses should be expressed as SPDX short-form IDs
	// (e.g.MIT, GPL-2.0-or-later, BSD-2-Clause):
	// https://spdx.github.io/spdx-spec/v2.3/SPDX-license-list/ .
	License []string `json:"license,omitempty"`

	// BuildArgs represents the allowed build arguments for the artifact.
	// This allows to authorize only artifacts that have been built with certain
	// building arguments.
	// The matching rules are expressed via map[string]string where the keys are
	// the build arguments, and the values are the regular expressions that are tested
	// via regexp.MatchString() against the correspondent keys.
	// If a given key is specified in the requirements, but it is not present in the
	// claims, the test will fail as the matching rule cannot be tested.
	BuildArgs map[string]string `json:"build_args,omitempty"`

	// ToolChain represents the information on the toolchain used to build the artifact.
	// Allow only artifacts that have been built with a certain toolchain.
	// The requirement is a regular expression that is tested via regexp.MatchString()
	// against the claimed tool_chain string.
	ToolChain string `json:"tool_chain,omitempty"`

	// MinTimestamp represents the required minimum timestamp in RFC3339 format
	// (e.g. "1985-04-12T23:20:50.52Z").
	MinTimestamp string `json:"min_timestamp,omitempty"`

	// Metadata represents the required ancillary information on the artifact.
	// This allows to authorize only artifacts that are claiming a given set of metadata.
	// The matching rules are expressed via map[string]string where the keys are
	// the build arguments, and the values are the regular expressions that are tested
	// via regexp.MatchString() against the correspondent keys.
	// If a given key is specified in the requirements, but it is not present in the
	// claims, the test will fail as the matching rule cannot be tested.
	Metadata map[string]string `json:"metadata,omitempty"`
}
