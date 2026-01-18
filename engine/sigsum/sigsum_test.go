// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package sigsum

import (
	"os"
	"testing"

	"github.com/usbarmory/boot-transparency/transparency"
)

var validProofBundle []byte
var validWitnessPolicy []byte

func TestLoadTestData(t *testing.T) {
	var err error

	validProofBundle, err = os.ReadFile("../../testdata/sigsum/proof-bundle.json")

	if err != nil {
		t.Errorf("failed to load test proof bundle: %s", err)
	}

	validWitnessPolicy, err = os.ReadFile("../../testdata/sigsum/trust_policy")

	if err != nil {
		t.Errorf("failed to load test witness policy: %s", err)
	}
}

func TestSigsumEngineSetKey(t *testing.T) {
	logKey := []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKwmwKhVrEUaZTlHjhoWA4jwJLOF8TY+/NpHAXAHbAHl"}
	submitKey := []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMdLcxVjCAQUHbD4jCfFP+f8v1nmyjWkq6rXiexrK8II"}

	e, err := transparency.GetEngine(transparency.Sigsum)
	if err != nil {
		t.Fatal(err)
	}

	err = e.SetKey(logKey, submitKey)

	if err != nil {
		t.Fatal(err)
	}
}

func TestSigsumEngineParseWitnessPolicy(t *testing.T) {
	policy := []byte(`
# example config
log aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa http://sigsum.example.org

witness A1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1
witness A2 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2
witness A3 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa3
witness B1 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1
witness B2 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2
witness B3 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb3

group A-group 1 A1 A2 A3
group B-group 2 B1 B2 B3
group G any A-group B-group

quorum G
`)

	e, err := transparency.GetEngine(transparency.Sigsum)
	if err != nil {
		t.Fatal(err)
	}

	p, err := e.ParseWitnessPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}

	err = e.SetWitnessPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSigsumEngineParseProof(t *testing.T) {
	e, err := transparency.GetEngine(transparency.Sigsum)

	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := e.ParseProof(validProofBundle); err != nil {
		t.Fatal(err)
	}
}

func TestSigsumEngineNoCosignaturesVerifyProof(t *testing.T) {
	// Test support for multiple keys configured in the transparency engine:
	// in this example only the last keys are the correct ones for verifying
	// the test statement proof.
	logKey := []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKwmwKhVrEUaZTlHjhoWA4jwJLOF8TY+/NpHAXAHbAHl",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN6kw3w2BWjlKLdrtnv4IaN+zg8/RpKGA98AbbTwjpdQ",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZEryq9QPSJWgA7yjUPnVkSqzAaScd/E+W22QXCCl/m"}
	submitKey := []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMCMTGNMNe1HP2us/dR5dBpyrSPDgPQ9mX5j9iqbLIS+",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqym9S/tFn6B/Eri5hGJiEV8BpGumEPcm65uxC+FG6K"}

	e, err := transparency.GetEngine(transparency.Sigsum)

	if err != nil {
		t.Fatal(err)
	}

	err = e.SetKey(logKey, submitKey)
	if err != nil {
		t.Fatal(err)
	}

	// Reset the witness policy to induce the engine to verify the proof using
	// the no-cosignature verification.
	e.ResetWitnessPolicy()

	pb, _, err := e.ParseProof(validProofBundle)
	if err != nil {
		t.Fatal(err)
	}

	err = e.VerifyProof(pb)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSigsumEngineCosignaturesVerifyProof(t *testing.T) {
	e, err := transparency.GetEngine(transparency.Sigsum)

	if err != nil {
		t.Fatal(err)
	}

	logKey := []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZEryq9QPSJWgA7yjUPnVkSqzAaScd/E+W22QXCCl/m"}
	submitKey := []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqym9S/tFn6B/Eri5hGJiEV8BpGumEPcm65uxC+FG6K"}

	err = e.SetKey(logKey, submitKey)
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

	pb, _, err := e.ParseProof(validProofBundle)
	if err != nil {
		t.Fatal(err)
	}

	err = e.VerifyProof(pb)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSigsumEngineCosignaturesVerifyProofInvalidLogKey(t *testing.T) {
	e, err := transparency.GetEngine(transparency.Sigsum)

	if err != nil {
		t.Fatal(err)
	}

	// Invalid log key (i.e. the only allowed key is not matching the log keyhash in the proof).
	logKey := []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKwmwKhVrEUaZTlHjhoWA4jwJLOF8TY+/NpHAXAHbAHl"}
	submitKey := []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqym9S/tFn6B/Eri5hGJiEV8BpGumEPcm65uxC+FG6K"}

	err = e.SetKey(logKey, submitKey)
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

	pb, _, err := e.ParseProof(validProofBundle)
	if err != nil {
		t.Fatal(err)
	}

	err = e.VerifyProof(pb)
	// Error expected: VerifyProof must return the log keyhash mismatch error.
	if err != nil && err.Error() != "unknown log key hash" {
		t.Fatal(err)
	}
}

func TestSigsumEngineCosignaturesVerifyProofInvalidSubmitKey(t *testing.T) {
	e, err := transparency.GetEngine(transparency.Sigsum)

	if err != nil {
		t.Fatal(err)
	}

	logKey := []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZEryq9QPSJWgA7yjUPnVkSqzAaScd/E+W22QXCCl/m"}
	submitKey := []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMdLcxVjCAQUHbD4jCfFP+f8v1nmyjWkq6rXiexrK8II"}

	err = e.SetKey(logKey, submitKey)
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

	pb, _, err := e.ParseProof(validProofBundle)
	if err != nil {
		t.Fatal(err)
	}

	err = e.VerifyProof(pb)
	// Error expected: VerifyProof must return the leaf key hash (i.e. submitter's key) mismatch error.
	if err != nil && err.Error() != "unknown leaf key hash" {
		t.Fatal(err)
	}
}

func TestSigsumEngineGetProof(t *testing.T) {
	e, err := transparency.GetEngine(transparency.Sigsum)

	if err != nil {
		t.Fatal(err)
	}

	logKey := []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZEryq9QPSJWgA7yjUPnVkSqzAaScd/E+W22QXCCl/m"}
	submitKey := []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqym9S/tFn6B/Eri5hGJiEV8BpGumEPcm65uxC+FG6K"}

	err = e.SetKey(logKey, submitKey)
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

	pb, _, err := e.ParseProof(validProofBundle)
	if err != nil {
		t.Fatal(err)
	}

	pr, err := e.GetProof(pb, false)
	if err != nil {
		t.Fatal(err)
	}

	freshBundle := pb.(*ProofBundle)
	freshBundle.Proof = string(pr)

	if err = e.VerifyProof(freshBundle); err != nil {
		t.Fatal(err)
	}
}

func TestSigsumEngineGetProofUpdateOriginalProofBundle(t *testing.T) {
	e, err := transparency.GetEngine(transparency.Sigsum)

	if err != nil {
		t.Fatal(err)
	}

	logKey := []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZEryq9QPSJWgA7yjUPnVkSqzAaScd/E+W22QXCCl/m"}
	submitKey := []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqym9S/tFn6B/Eri5hGJiEV8BpGumEPcm65uxC+FG6K"}

	err = e.SetKey(logKey, submitKey)
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

	pb, _, err := e.ParseProof(validProofBundle)
	if err != nil {
		t.Fatal(err)
	}

	if _, err = e.GetProof(pb, true); err != nil {
		t.Fatal(err)
	}

	if err = e.VerifyProof(pb); err != nil {
		t.Fatal(err)
	}
}
