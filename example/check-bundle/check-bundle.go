// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io/fs"
	"log"
	"os"

	// Load a specific transparency engine among the supported ones
	"github.com/usbarmory/boot-transparency/engine/sigsum"
	// Load the support for the policy and transparency layers from boot-transparency
	"github.com/usbarmory/boot-transparency/policy"
	"github.com/usbarmory/boot-transparency/transparency"
)

const (
	// Boot-transparency
	bootPolicyPath    = "policy/policy.json"
	witnessPolicyPath = "sigsum/witness_policy.txt"
	proofBundlePath   = "sigsum/bt-proof-bundle.json"
	submitKeyPath     = "keys/submit-key.pub"
	logKeyPath        = "keys/log-key.pub"
)

func bootTransparencyOfflineCheck(fsys fs.FS, bootPolicyPath string, witnessPolicyPath string, submitKeyPath string, logKeyPath string, proofBundlePath string) (err error) {
	bootPolicy, err := fs.ReadFile(fsys, bootPolicyPath)
	if err != nil {
		return fmt.Errorf("cannot read boot policy, %v", err)
	}

	witnessPolicy, err := fs.ReadFile(fsys, witnessPolicyPath)
	if err != nil {
		return fmt.Errorf("cannot read witness policy, %v", err)
	}

	submitKey, err := fs.ReadFile(fsys, submitKeyPath)
	if err != nil {
		return fmt.Errorf("cannot read log submitter key, %v", err)
	}

	logKey, err := fs.ReadFile(fsys, logKeyPath)
	if err != nil {
		return fmt.Errorf("cannot read log key, %v", err)
	}

	proofBundle, err := fs.ReadFile(fsys, proofBundlePath)
	if err != nil {
		return fmt.Errorf("cannot read proof bundle, %v", err)
	}

	// Select Sigsum as transparency engine.
	te, err := transparency.GetEngine(transparency.Sigsum)
	if err != nil {
		return fmt.Errorf("unable to configure the transparency engine, %w", err)
	}

	// Set public keys.
	err = te.SetKey([]string{string(logKey)}, []string{string(submitKey)})
	if err != nil {
		return err
	}

	// Parse witness policy.
	wp, err := te.ParseWitnessPolicy(witnessPolicy)
	if err != nil {
		return err
	}

	// Set witness policy.
	err = te.SetWitnessPolicy(wp)
	if err != nil {
		return err
	}

	// Parse the proof bundle, which is expected to contain
	// the logged statement and its inclusion proof.
	pb, _, err := te.ParseProof(proofBundle)
	if err != nil {
		return err
	}

	// Inclusion proof verification, including the co-signing quorum verification
	// as defined in the witness policy.
	err = te.VerifyProof(pb)
	if err != nil {
		return err
	}

	// Parse the boot policy requirements.
	r, err := policy.ParseRequirements(bootPolicy)
	if err != nil {
		return err
	}

	// Convert to the proof bundle type expected by the selected engine.
	b := pb.(*sigsum.ProofBundle)

	// Parse the statement included in the proof bundle.
	c, err := policy.ParseClaims(b.Statement)
	if err != nil {
		return err
	}

	// Check if the logged claims are matching the policy requirements.
	if err = policy.Check(r, c); err != nil {
		// The boot bundle is NOT authorized for boot.
		return err
	}

	// All boot-transparency checks passed.
	return
}

func bootTransparencyOnlineCheck(fsys fs.FS, bootPolicyPath string, witnessPolicyPath string, submitKeyPath string, logKeyPath string, proofBundlePath string) (err error) {
	bootPolicy, err := fs.ReadFile(fsys, bootPolicyPath)
	if err != nil {
		return fmt.Errorf("cannot read boot policy, %v", err)
	}

	witnessPolicy, err := fs.ReadFile(fsys, witnessPolicyPath)
	if err != nil {
		return fmt.Errorf("cannot read witness policy, %v", err)
	}

	submitKey, err := fs.ReadFile(fsys, submitKeyPath)
	if err != nil {
		return fmt.Errorf("cannot read log submitter key, %v", err)
	}

	logKey, err := fs.ReadFile(fsys, logKeyPath)
	if err != nil {
		return fmt.Errorf("cannot read log key, %v", err)
	}

	proofBundle, err := fs.ReadFile(fsys, proofBundlePath)
	if err != nil {
		return fmt.Errorf("cannot read proof bundle, %v", err)
	}

	// Select Sigsum as transparency engine.
	te, err := transparency.GetEngine(transparency.Sigsum)
	if err != nil {
		return fmt.Errorf("unable to configure the transparency engine, %w", err)
	}

	// Set public keys.
	err = te.SetKey([]string{string(logKey)}, []string{string(submitKey)})
	if err != nil {
		return err
	}

	// Parse witness policy.
	wp, err := te.ParseWitnessPolicy(witnessPolicy)
	if err != nil {
		return err
	}

	// Set witness policy.
	err = te.SetWitnessPolicy(wp)
	if err != nil {
		return err
	}

	// Parse the proof bundle, which is expected to contain
	// the logged statement and probe data to request the inclusion proof.
	pb, _, err := te.ParseProof(proofBundle)
	if err != nil {
		return err
	}

	// Probe the log to obtain a fresh inclusion proof.
	pr, err := te.GetProof(pb)
	if err != nil {
		return err
	}

	freshBundle := pb.(*sigsum.ProofBundle)
	freshBundle.Proof = string(pr)

	// Inclusion proof verification,
	// use the fresh inclusion proof obtained from the log, include
	// verification of the co-signing quorum as defined in the witness policy.
	err = te.VerifyProof(freshBundle)
	if err != nil {
		return err
	}

	// Parse the boot policy requirements.
	r, err := policy.ParseRequirements(bootPolicy)
	if err != nil {
		return err
	}

	// Convert to the proof bundle type expected by the selected engine.
	b := pb.(*sigsum.ProofBundle)

	// Parse the statement included in the proof bundle.
	c, err := policy.ParseClaims(b.Statement)
	if err != nil {
		return err
	}

	// Check if the logged claims are matching the policy requirements.
	if err = policy.Check(r, c); err != nil {
		// The boot bundle is NOT authorized for boot.
		return err
	}

	// All boot-transparency checks passed.
	return
}

func main() {
	rootPath := "../../testdata/"
	root := os.DirFS(rootPath)

	// Boot-transparency
	if err := bootTransparencyOfflineCheck(root, bootPolicyPath, witnessPolicyPath, submitKeyPath, logKeyPath, proofBundlePath); err != nil {
		log.Fatalf("boot-transparency off-line check failed\n%v", err)
	} else {
		log.Printf("boot-transparency off-line check passed\n")
	}

	if err := bootTransparencyOnlineCheck(root, bootPolicyPath, witnessPolicyPath, submitKeyPath, logKeyPath, proofBundlePath); err != nil {
		log.Fatalf("boot-transparency on-line check failed\n%v", err)
	} else {
		log.Printf("boot-transparency on-line check passed\n")
	}
}
