// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	// Boot-transparency
	bootPolicyPath    = "policy/policy.json"
	witnessPolicyPath = "sigsum/trust_policy"
	proofBundlePath   = "sigsum/proof-bundle.json"
	submitKeyPath     = "keys/submit-key.pub"
	logKeyPath        = "keys/log-key.pub"
)

// Artifact represents a boot artifact.
type Artifact struct {
	// Category represents the artifact category as defined
	// in the boot-transparency library.
	Category uint

	// Hash represents the SHA-256 hash of the artifact.
	Hash string
}

// BootEntry represent a boot entry as a set of artifacts.
type BootEntry []Artifact

// Validate the matching between loaded artifact hashes and
// the ones included in the proof bundle.
// This step is vital to ensure the correspondence between the artifacts
// loaded in memory during the boot and the claims that will be validated
// by the boot-transparency policy function.
func (b BootEntry) validateProofHashes(s *policy.Statement) (err error) {
	for _, a := range b {
		if err = a.validateProofHash(s); err != nil {
			return err
		}
	}

	return
}

func (a Artifact) validateProofHash(s *policy.Statement) (err error) {
	var h artifact.Handler
	var found bool

	if err = a.validHash(); err != nil {
		return
	}

	for _, claimedArtifact := range s.Artifacts {
		// The claims are referring to a different artifact
		// category, try with next block of claims in the statement.
		if a.Category != claimedArtifact.Category {
			continue
		}

		if h, err = artifact.GetHandler(a.Category); err != nil {
			return
		}

		// boot-transparency expect to parse requirements in JSON format.
		requirements, _ := json.Marshal(map[string]string{"file_hash": a.Hash})

		r, err := h.ParseRequirements([]byte(requirements))
		if err != nil {
			return err
		}

		c, err := h.ParseClaims([]byte(claimedArtifact.Claims))
		if err != nil {
			return err
		}

		// The validation logic is safe in the sense that error is returned
		// if a file hash requested by the boot loader is not present in the
		// statement for a given artifact category.
		if err = h.Validate(r, c); err != nil {
			return fmt.Errorf("loaded boot artifacts do not correspond to the proof bundle ones, file hash mismatch")
		}

		found = true
		break
	}

	if !found {
		return fmt.Errorf("loaded boot artifacts do not correspond to the proof bundle ones, one or more artifacts are not present in the proof bundle")
	}

	return
}

func (a Artifact) validHash() (err error) {
	h, err := hex.DecodeString(a.Hash)

	if err != nil || len(h) != sha256.Size {
		return fmt.Errorf("invalid artifact hash")
	}

	return
}

func btValidate(fsys fs.FS, bootPolicyPath string, witnessPolicyPath string, submitKeyPath string, logKeyPath string, proofBundlePath string, online bool) (err error) {
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
	err = te.SetKey([][]byte{logKey}, [][]byte{submitKey})
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

	// Ensure the artifacts loaded during the booting process are matching
	// the ones referenced in the proof bundle (i.e. file hash matching).
	b := BootEntry{
		Artifact{
			Category: artifact.LinuxKernel,
			Hash:     "4551848b4ab43cb4321c4d6ba98e1d215f950cee21bfd82c8c82ab64e34ec9a6",
		},
		Artifact{
			Category: artifact.Initrd,
			Hash:     "337630b74e55eae241f460faadf5a2f9a2157d6de2853d4106c35769e4acf538",
		},
	}

	if err = b.validateProofHashes(c); err != nil {
		return err
	}

	// Validate the matching bewteen the logged claims and the policy requirements.
	if err = policy.Validate(r, c); err != nil {
		// The boot bundle is NOT authorized for boot.
		return err
	}

	// All boot-transparency validations passed.
	return
}

func main() {
	rootPath := "../../testdata/"
	root := os.DirFS(rootPath)

	if err := btValidate(root, bootPolicyPath, witnessPolicyPath, submitKeyPath, logKeyPath, proofBundlePath, false); err != nil {
		log.Fatalf("boot-transparency off-line validation failed\n%v", err)
	} else {
		log.Printf("boot-transparency off-line validation passed\n")
	}

	if err := btValidate(root, bootPolicyPath, witnessPolicyPath, submitKeyPath, logKeyPath, proofBundlePath, true); err != nil {
		log.Fatalf("boot-transparency on-line validation failed\n%v", err)
	} else {
		log.Printf("boot-transparency on-line validation passed\n")
	}
}
