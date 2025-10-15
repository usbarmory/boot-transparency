// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package tessera

import (
	"os"
	"strings"
	"testing"

	"github.com/usbarmory/boot-transparency/transparency"
)

var validProofBundle []byte
var validWitnessPolicy []byte

func TestLoadTestData(t *testing.T) {
	var err error

	validProofBundle, err = os.ReadFile("../../testdata/tessera/proof_bundle.json")

	if err != nil {
		t.Errorf("failed to load test proof bundle: %s", err)
	}

	validWitnessPolicy, err = os.ReadFile("../../testdata/tessera/witness_policy.txt")

	if err != nil {
		t.Errorf("failed to load test witness policy: %s", err)
	}
}

func TestTesseraEngineSetKey(t *testing.T) {
	logKey := []string{"PeterNeumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW"}
	// Tessera does not use the submit key in the verification process
	submitKey := []string{}

	e, err := transparency.GetEngine(transparency.Tessera)
	if err != nil {
		t.Fatal(err)
	}

	err = e.SetKey(logKey, submitKey)

	if err != nil {
		t.Fatal(err)
	}
}

func TestNegativeTesseraEngineSetKey(t *testing.T) {
	// invalid vkey: malformed verifier id
	logKey := []string{"PeterNeumann+c74f203+ARpc2QcUPDhMQegwxbzKqiBfsVkmqq/LDE4izWy10TW"}
	// Tessera does not use the submit key in the verification process
	submitKey := []string{}

	e, err := transparency.GetEngine(transparency.Tessera)
	if err != nil {
		t.Fatal(err)
	}

	err = e.SetKey(logKey, submitKey)

	if err == nil {
		t.Fatal(err)
	}
}

func TestTesseraEngineParseWitnessPolicy(t *testing.T) {
	e, err := transparency.GetEngine(transparency.Tessera)
	if err != nil {
		t.Fatal(err)
	}

	p, err := e.ParseWitnessPolicy(validWitnessPolicy)

	if err != nil {
		t.Fatal(err)
	}

	err = e.SetWitnessPolicy(p)

	if err != nil {
		t.Fatal(err)
	}
}

func TestTesseraEngineNegativeNoCosignaturesVerifyProof(t *testing.T) {
	// test support for multiple keys configured in the transparency engine:
	// in this example only the last keys are the correct ones for verifying
	// the test statement proof
	logKey := []string{"PeterNeumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW"}

	e, err := transparency.GetEngine(transparency.Tessera)
	if err != nil {
		t.Fatal(err)
	}

	err = e.SetKey(logKey, []string{})
	if err != nil {
		t.Fatal(err)
	}

	pb, _, err := e.ParseProof(validProofBundle)
	if err != nil {
		t.Fatal(err)
	}

	err = e.VerifyProof(pb)

	// error expected here as the log public key will not pass log signature verification
	if err != nil && !strings.Contains(err.Error(), "does not match expected root") {
		t.Fatal(err)
	}
}
