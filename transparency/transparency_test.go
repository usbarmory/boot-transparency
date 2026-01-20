// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package transparency

import (
	"os"
	"testing"
)

var validSigsumProofBundle []byte
var validTesseraProofBundle []byte

func TestLoadTestData(t *testing.T) {
	var err error

	validSigsumProofBundle, err = os.ReadFile("../testdata/sigsum/proof-bundle.json")

	if err != nil {
		t.Fatal(err)
	}

	validTesseraProofBundle, err = os.ReadFile("../testdata/tessera/proof-bundle.json")

	if err != nil {
		t.Fatal(err)
	}
}

func TestParseProofBundle(t *testing.T) {
	if _, _, _, _, _, err := ParseProofBundle(validSigsumProofBundle); err != nil {
		t.Fatal(err)
	}

	if _, _, _, _, _, err := ParseProofBundle(validTesseraProofBundle); err != nil {
		t.Fatal(err)
	}
}
