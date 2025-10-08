// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package windows_bootmgr

// Supported claims for WindowsBootMgr artifact
type Claims struct {
	// filename of the artifact
	FileName string `json:"file_name"`

	// SHA-512 hash of the artifact
	Hash string `json:"hash"`

	// artifact version
	Version string `json:"version,omitempty"`
}
