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

	"github.com/usbarmory/boot-transparency/artifact"
	_ "github.com/usbarmory/boot-transparency/engine/sigsum"
	"github.com/usbarmory/boot-transparency/policy"
	"github.com/usbarmory/boot-transparency/transparency"
)

const (
	// Boot-transparency assets.
	bootPolicyPath    = "policy/policy.json"
	witnessPolicyPath = "sigsum/trust_policy"
	proofBundlePath   = "sigsum/proof-bundle.json"
	submitKeyPath     = "keys/submit-key.pub"
	logKeyPath        = "keys/log-key.pub"

	// Boot entry artifacts.
	kernelPath = "boot_entry/test-vmlinuz-6.14.0-29-generic"
	initrdPath = "boot_entry/test-initrd.img-6.14.0-29-generic"
)

func btValidate(fsys fs.FS, bootPolicyPath string, witnessPolicyPath string, submitKeyPath string, logKeyPath string, proofBundlePath string, kernelPath string, initrdPath string, online bool) (err error) {
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
	err = te.SetKey(logKey, submitKey)
	if err != nil {
		return err
	}

	// Set witness policy.
	err = te.SetWitnessPolicy(witnessPolicy)
	if err != nil {
		return err
	}

	// Parse the proof bundle, which is expected to contain
	// the logged statement and its inclusion proof.
	format, statement, proof, probe, _, err := transparency.ParseProofBundle(proofBundle)
	if err != nil {
		return err
	}

	if format != transparency.Sigsum {
		return fmt.Errorf("not a valid Sigsum proof bundle")
	}

	// If online, the inclusion proof verification is performed using
	// the proof fetched from the log.
	if online {
		proof, err = te.GetProof(statement, probe)
		if err != nil {
			return err
		}
	}

	// Inclusion proof verification, including the co-signing quorum verification
	// as defined in the witness policy.
	err = te.VerifyProof(statement, proof, nil)
	if err != nil {
		return err
	}

	// Parse the boot policy requirements.
	r, err := policy.ParseRequirements(bootPolicy)
	if err != nil {
		return err
	}

	// Parse the statement included in the proof bundle.
	c, err := policy.ParseStatement(statement)
	if err != nil {
		return err
	}

	// Load all the boot entry files from the filesystem.
	kernel, err := fs.ReadFile(fsys, kernelPath)
	if err != nil {
		return fmt.Errorf("cannot read kernel, %v", err)
	}

	initrd, err := fs.ReadFile(fsys, initrdPath)
	if err != nil {
		return fmt.Errorf("cannot read initrd, %v", err)
	}

	// Assemble the boot entry.
	b := policy.BootEntry{
		policy.BootArtifact{
			Category: artifact.LinuxKernel,
			Data:     kernel,
		},
		policy.BootArtifact{
			Category: artifact.Initrd,
			Data:     initrd,
		},
	}

	// Validate the matching bewteen the logged claims and the policy requirements.
	if err = policy.Validate(r, c, &b); err != nil {
		// The boot bundle is NOT authorized for boot.
		return err
	}

	// All boot-transparency validations passed.
	return
}

func main() {
	rootPath := "../../testdata/"
	root := os.DirFS(rootPath)

	if err := btValidate(root, bootPolicyPath, witnessPolicyPath, submitKeyPath, logKeyPath, proofBundlePath, kernelPath, initrdPath, false); err != nil {
		log.Fatalf("boot-transparency off-line validation failed\n%v", err)
	} else {
		log.Printf("boot-transparency off-line validation passed\n")
	}

	if err := btValidate(root, bootPolicyPath, witnessPolicyPath, submitKeyPath, logKeyPath, proofBundlePath, kernelPath, initrdPath, true); err != nil {
		log.Fatalf("boot-transparency on-line validation failed\n%v", err)
	} else {
		log.Printf("boot-transparency on-line validation passed\n")
	}
}
