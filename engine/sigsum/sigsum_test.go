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
		t.Fatal(err)
	}

	validWitnessPolicy, err = os.ReadFile("../../testdata/sigsum/trust_policy")
	if err != nil {
		t.Fatal(err)
	}
}

func TestSigsumEngineSetKey(t *testing.T) {
	logKey := [][]byte{
		[]byte(`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKwmwKhVrEUaZTlHjhoWA4jwJLOF8TY+/NpHAXAHbAHl`),
	}
	submitKey := [][]byte{
		[]byte(`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMdLcxVjCAQUHbD4jCfFP+f8v1nmyjWkq6rXiexrK8II`),
	}

	e, err := transparency.GetEngine(transparency.Sigsum)
	if err != nil {
		t.Fatal(err)
	}

	if err = e.SetKey(logKey, submitKey); err != nil {
		t.Fatal(err)
	}
}

func TestSigsumEngineSetWitnessPolicy(t *testing.T) {
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

	if err = e.SetWitnessPolicy(policy); err != nil {
		t.Fatal(err)
	}
}

func TestSigsumEngineNoCosignaturesVerifyProof(t *testing.T) {
	// Test support for multiple keys configured in the transparency engine:
	// in this example only the last keys are the correct ones for verifying
	// the test statement proof.
	logKey := [][]byte{
		[]byte(`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKwmwKhVrEUaZTlHjhoWA4jwJLOF8TY+/NpHAXAHbAHl`),
		[]byte(`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN6kw3w2BWjlKLdrtnv4IaN+zg8/RpKGA98AbbTwjpdQ`),
		[]byte(`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZEryq9QPSJWgA7yjUPnVkSqzAaScd/E+W22QXCCl/m`),
	}
	submitKey := [][]byte{
		[]byte(`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMCMTGNMNe1HP2us/dR5dBpyrSPDgPQ9mX5j9iqbLIS+`),
		[]byte(`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqym9S/tFn6B/Eri5hGJiEV8BpGumEPcm65uxC+FG6K`),
	}

	e, err := transparency.GetEngine(transparency.Sigsum)
	if err != nil {
		t.Fatal(err)
	}

	if err = e.SetKey(logKey, submitKey); err != nil {
		t.Fatal(err)
	}

	// Reset the witness policy to induce the engine to verify the proof using
	// the no-cosignature verification.
	if err = e.SetWitnessPolicy(nil); err != nil {
		t.Fatal(err)
	}

	format, statement, proof, _, _, err := transparency.ParseProofBundle(validProofBundle)
	if err != nil {
		t.Fatal(err)
	}

	if format != transparency.Sigsum {
		t.Errorf("not a valid Sigsum proof bundle")
	}

	if err = e.VerifyProof(statement, proof, nil); err != nil {
		t.Fatal(err)
	}
}

func TestSigsumEngineCosignaturesVerifyProof(t *testing.T) {
	e, err := transparency.GetEngine(transparency.Sigsum)
	if err != nil {
		t.Fatal(err)
	}

	logKey := [][]byte{
		[]byte(`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZEryq9QPSJWgA7yjUPnVkSqzAaScd/E+W22QXCCl/m`),
	}
	submitKey := [][]byte{
		[]byte(`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqym9S/tFn6B/Eri5hGJiEV8BpGumEPcm65uxC+FG6K`),
	}

	if err = e.SetKey(logKey, submitKey); err != nil {
		t.Fatal(err)
	}

	if err = e.SetWitnessPolicy(validWitnessPolicy); err != nil {
		t.Fatal(err)
	}

	format, statement, proof, _, _, err := transparency.ParseProofBundle(validProofBundle)
	if err != nil {
		t.Fatal(err)
	}

	if format != transparency.Sigsum {
		t.Errorf("not a valid Sigsum proof bundle")
	}

	if err = e.VerifyProof(statement, proof, nil); err != nil {
		t.Fatal(err)
	}
}

func TestSigsumEngineCosignaturesVerifyProofInvalidLogKey(t *testing.T) {
	e, err := transparency.GetEngine(transparency.Sigsum)
	if err != nil {
		t.Fatal(err)
	}

	// Invalid log key (i.e. the only allowed key is not matching the log keyhash in the proof).
	logKey := [][]byte{
		[]byte(`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKwmwKhVrEUaZTlHjhoWA4jwJLOF8TY+/NpHAXAHbAHl`),
	}
	submitKey := [][]byte{
		[]byte(`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqym9S/tFn6B/Eri5hGJiEV8BpGumEPcm65uxC+FG6K`),
	}

	if err = e.SetKey(logKey, submitKey); err != nil {
		t.Fatal(err)
	}

	if err = e.SetWitnessPolicy(validWitnessPolicy); err != nil {
		t.Fatal(err)
	}

	format, statement, proof, _, _, err := transparency.ParseProofBundle(validProofBundle)
	if err != nil {
		t.Fatal(err)
	}

	if format != transparency.Sigsum {
		t.Errorf("not a valid Sigsum proof bundle")
	}

	err = e.VerifyProof(statement, proof, nil)
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

	logKey := [][]byte{
		[]byte(`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZEryq9QPSJWgA7yjUPnVkSqzAaScd/E+W22QXCCl/m`),
	}
	submitKey := [][]byte{
		[]byte(`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMdLcxVjCAQUHbD4jCfFP+f8v1nmyjWkq6rXiexrK8II`),
	}

	if err = e.SetKey(logKey, submitKey); err != nil {
		t.Fatal(err)
	}

	if err = e.SetWitnessPolicy(validWitnessPolicy); err != nil {
		t.Fatal(err)
	}

	format, statement, proof, _, _, err := transparency.ParseProofBundle(validProofBundle)
	if err != nil {
		t.Fatal(err)
	}

	if format != transparency.Sigsum {
		t.Errorf("not a valid Sigsum proof bundle")
	}

	// Error expected: VerifyProof must return the leaf key hash (i.e. submitter's key) mismatch error.
	if err = e.VerifyProof(statement, proof, nil); err != nil && err.Error() != "unknown leaf key hash" {
		t.Fatal(err)
	}
}

func TestSigsumEngineGetProof(t *testing.T) {
	e, err := transparency.GetEngine(transparency.Sigsum)
	if err != nil {
		t.Fatal(err)
	}

	logKey := [][]byte{
		[]byte(`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZEryq9QPSJWgA7yjUPnVkSqzAaScd/E+W22QXCCl/m`),
	}
	submitKey := [][]byte{
		[]byte(`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqym9S/tFn6B/Eri5hGJiEV8BpGumEPcm65uxC+FG6K`),
	}

	if err = e.SetKey(logKey, submitKey); err != nil {
		t.Fatal(err)
	}

	if err = e.SetWitnessPolicy(validWitnessPolicy); err != nil {
		t.Fatal(err)
	}

	format, statement, _, probe, _, err := transparency.ParseProofBundle(validProofBundle)
	if err != nil {
		t.Fatal(err)
	}

	if format != transparency.Sigsum {
		t.Errorf("not a valid Sigsum proof bundle")
	}

	proof, err := e.GetProof(statement, probe)
	if err != nil {
		t.Fatal(err)
	}

	if err = e.VerifyProof(statement, proof, nil); err != nil {
		t.Fatal(err)
	}
}
