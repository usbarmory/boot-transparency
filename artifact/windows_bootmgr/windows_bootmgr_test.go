// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package windows_bootmgr

import (
	"testing"

	"github.com/usbarmory/boot-transparency/artifact"
)

func TestWindowsBootMgrParseRequirements(t *testing.T) {
	r := []byte(`{"min_version": "24H2", "architecture":"amd64", "revoked": true, "min_timestamp": "2025-01-01T23:20:50.52Z", "companyName": ["Microsoft"], "signingAuthority": ["CN = Microsoft Windows Production PCA 2011"]}`)

	h, err := artifact.GetHandler(artifact.WindowsBootMgr)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.ParseRequirements(r); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsBootMgrParseClaims(t *testing.T) {
	c := []byte(`{"filename": "bootmgfw.efi", "flatHash": "86E5B25AA8072895E72E3D5F4BEACCC1488A434FB10BABE17FB9010DA4ED93BC", "authenticodeHash": "07B6D3AA86D0A8D5F46BDD5886D8F20FA2DD9377898D1139BD74B41F5E7AE44B", "companyName": "Microsoft", "signingAuthority": "CN = Microsoft Windows Production PCA 2011"}`)

	h, err := artifact.GetHandler(artifact.WindowsBootMgr)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.ParseClaims(c); err != nil {
		t.Fatal(err)
	}
}

func TestNegativeWindowsBootMgrParseClaims(t *testing.T) {
	c := []byte(`{"filename":·"bootmgfw.efi", "flatHash": [ "86E5B25AA8072895E72E3D5F4BEACCC1488A434FB10BABE17FB9010DA4ED93BC" ],"architecture":"amd64"}`)

	h, err := artifact.GetHandler(artifact.WindowsBootMgr)
	if err != nil {
		t.Fatal(err)
	}

	// Error expected: "flatHash" cannot be an array.
	if _, err := h.ParseClaims(c); err == nil {
		t.Fatal(err)
	}
}

func TestWindowsBootMgrCheck(t *testing.T) {
	r := []byte(`{"flatHash": "86E5B25AA8072895E72E3D5F4BEACCC1488A434FB10BABE17FB9010DA4ED93BC", "revoked": true, "companyName":["Microsoft"], "signingAuthority": ["CN = Microsoft Windows Production PCA 2011"]}`)

	c := []byte(`{"filename": "bootmgfw.efi", "flatHash": "86E5B25AA8072895E72E3D5F4BEACCC1488A434FB10BABE17FB9010DA4ED93BC", "authenticodeHash": "07B6D3AA86D0A8D5F46BDD5886D8F20FA2DD9377898D1139BD74B41F5E7AE44B", "revoked": true, "reproducible": false, "companyName": "Microsoft", "signingAuthority": "CN = Microsoft Windows Production PCA 2011"}`)

	h, err := artifact.GetHandler(artifact.WindowsBootMgr)
	if err != nil {
		t.Fatal(err)
	}

	parsedRequirements, err := h.ParseRequirements(r)
	if err != nil {
		t.Fatal(err)
	}

	parsedClaims, err := h.ParseClaims(c)
	if err != nil {
		t.Fatal(err)
	}

	if err = h.Check(parsedRequirements, parsedClaims); err != nil {
		t.Fatal(err)
	}
}

func TestNegativeWindowsBootMgrCheck(t *testing.T) {
	r := []byte(`{"revoked": false, "companyName":["Microsoft"], "signingAuthority": ["CN = Microsoft Windows Production PCA 2011"]}`)

	c := []byte(`{"filename": "bootmgfw.efi", "flatHash": "86E5B25AA8072895E72E3D5F4BEACCC1488A434FB10BABE17FB9010DA4ED93BC", "authenticodeHash": "07B6D3AA86D0A8D5F46BDD5886D8F20FA2DD9377898D1139BD74B41F5E7AE44B", "revoked": true, "reproducible": false, "companyName": "Microsoft", "signingAuthority": "CN = Microsoft Windows Production PCA 2011"}`)

	h, err := artifact.GetHandler(artifact.WindowsBootMgr)
	if err != nil {
		t.Fatal(err)
	}

	parsedRequirements, err := h.ParseRequirements(r)
	if err != nil {
		t.Fatal(err)
	}

	parsedClaims, err := h.ParseClaims(c)
	if err != nil {
		t.Fatal(err)
	}

	// Error expected: the claimed boot manager is "revoked", which does not match the requirements.
	if err = h.Check(parsedRequirements, parsedClaims); err == nil {
		t.Fatal(err)
	}
}
