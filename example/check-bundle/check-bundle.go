// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"

	"github.com/usbarmory/boot-transparency/artifact"
	"github.com/usbarmory/boot-transparency/engine/sigsum"
	"github.com/usbarmory/boot-transparency/policy"
	"github.com/usbarmory/boot-transparency/transparency"
)

const (
	// Boot-transparency
	bootPolicyPath    = "policy/policy.json"
	witnessPolicyPath = "sigsum/trust_policy"
	proofBundlePath   = "sigsum/proof-bundle.json"
	submitKeyPath     = "keys/submit-key.pub"
	logKeyPath        = "keys/log-key.pub"
)

type BtArtifact struct {
	Category     uint
	Requirements []byte
}

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
	c, err := policy.ParseStatement(b.Statement)
	if err != nil {
		return err
	}

	// Check if the hash of artifacts loaded during the booting process are matching
	// the ones referenced in the proof bundle.
	requiredLinuxKernel, _ := json.Marshal(map[string]string{
		"file_hash": "8ba6bc3d9ccfe9c17ad7482d6c0160150c7d1da4b4a4f464744ce069291d6174ea9949574002f022e18585df04f57c192431794f36f40659930bd5c0b470eb59"})

	requiredInitrd, _ := json.Marshal(map[string]string{
		"file_hash": "9f5db8bc106c426a6654aa53ada75db307adb6dcb59291aa0a874898bc197b3dad8d2ebef985936bba94e9ae34b52a79e8f9045346cde2326baf4feba73ab66c"})

	btArtifacts := []BtArtifact{
		{Category: artifact.LinuxKernel, Requirements: requiredLinuxKernel},
		{Category: artifact.Initrd, Requirements: requiredInitrd},
	}

	if err = validateArtifacts(c, btArtifacts); err != nil {
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
	c, err := policy.ParseStatement(b.Statement)
	if err != nil {
		return err
	}

	// Check if the hash of artifacts loaded during the booting process are matching
	// the ones referenced in the proof bundle.
	requiredLinuxKernel, _ := json.Marshal(map[string]string{
		"file_hash": "8ba6bc3d9ccfe9c17ad7482d6c0160150c7d1da4b4a4f464744ce069291d6174ea9949574002f022e18585df04f57c192431794f36f40659930bd5c0b470eb59"})

	requiredInitrd, _ := json.Marshal(map[string]string{
		"file_hash": "9f5db8bc106c426a6654aa53ada75db307adb6dcb59291aa0a874898bc197b3dad8d2ebef985936bba94e9ae34b52a79e8f9045346cde2326baf4feba73ab66c"})

	btArtifacts := []BtArtifact{
		{Category: artifact.LinuxKernel, Requirements: requiredLinuxKernel},
		{Category: artifact.Initrd, Requirements: requiredInitrd},
	}

	if err = validateArtifacts(c, btArtifacts); err != nil {
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

// Check the matching of the boot artifacts with the ones included into a given proof bundle.
// This step is vital to ensure the correspondency between the artifacts actually
// loaded during the boot and the claims that will be validated by the  boot-transparency
// policy function.
func validateArtifacts(s *policy.Statement, btArtifacts []BtArtifact) (err error) {
	var h artifact.Handler

	for _, bootArtifact := range btArtifacts {
		found := false

		for _, a := range s.Artifacts {
			if bootArtifact.Category == a.Category {
				h, err = artifact.GetHandler(a.Category)
				if err != nil {
					return
				}

				r, err := h.ParseRequirements([]byte(bootArtifact.Requirements))
				if err != nil {
					return err
				}

				c, err := h.ParseClaims([]byte(a.Claims))
				if err != nil {
					return err
				}

				err = h.Check(r, c)
				if err != nil {
					return fmt.Errorf("loaded boot artifacts do not correspond to the proof bundle ones, file hash mistmatch.")
				}

				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("loaded boot artifacts do not correspond to the proof bundle ones, one or more artifacts are not present in the proof bundle.")
		}
	}

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
