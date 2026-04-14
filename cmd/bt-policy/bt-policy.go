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
	"io"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/pborman/getopt/v2"
	"github.com/usbarmory/boot-transparency/policy"
)

type ValidateSettings struct {
	policyFile          string
	signedStatementFile string
	bootEntryFiles      string
}

type ParseSettings struct {
	policyFile string
}

func (s *ValidateSettings) parse(args []string) {
	const usage = `
Validate a given signed statement against a boot-transparency policy,
the result is printed to stdout.
`
	help := false

	set := getopt.New()
	set.SetProgram(args[0] + " " + args[1])

	set.FlagLong(&s.policyFile, "policy-file", 'p', "Boot-transparency policy file", "policy file").Mandatory()
	set.FlagLong(&s.signedStatementFile, "signed-statement", 's', "Signed statement file", "signed statement file").Mandatory()
	set.FlagLong(&s.bootEntryFiles, "boot-entry-files", 'b', "Boot artifacts files passed as a comma separated list of category:path items", "boot artifact files").Mandatory()
	set.FlagLong(&help, "help", 'h', "Show usage message and exit")

	err := set.Getopt(args[1:], nil)

	// Handle help before checking for errors on other arguments.
	if help {
		fmt.Print(usage[1:] + "\n")
		set.PrintUsage(os.Stdout)
		os.Exit(0)
	}

	if err != nil {
		set.PrintUsage(log.Writer())
		os.Exit(1)
	}
}

func (s *ParseSettings) parse(args []string) {
	const usage = `
Parse a boot-transparecy policy,
the result is printed to stdout.
`
	help := false
	set := getopt.New()
	set.SetProgram(args[0] + " " + args[1])

	set.FlagLong(&s.policyFile, "policy-file", 'p', "Boot-transparency policy file", "policy-file").Mandatory()
	set.FlagLong(&help, "help", 'h', "Show usage message and exit")

	err := set.Getopt(args[1:], nil)

	// Handle help before checking for errors on other arguments.
	if help {
		fmt.Print(usage[1:] + "\n")
		set.PrintUsage(os.Stdout)
		os.Exit(0)
	}

	if err != nil {
		set.PrintUsage(log.Writer())
		os.Exit(1)
	}
}

func readStatement(fileName string) (*policy.Statement, error) {
	var s *policy.Statement

	f, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}

	bytes, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	s, err = policy.ParseStatement(bytes)
	if err != nil {
		return nil, err
	}

	return s, nil
}

func readPolicy(fileName string) (*[]policy.PolicyEntry, error) {
	var p *[]policy.PolicyEntry

	f, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}

	bytes, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	p, err = policy.ParseRequirements(bytes)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func loadBootEntry(files string) (*policy.BootEntry, error) {
	bootEntry := policy.BootEntry{}

	for _, file := range strings.Split(files, ",") {
		bootArtifact := policy.BootArtifact{}

		artifact := strings.Split(file, ":")
		if len(artifact) != 2 {
			return nil, fmt.Errorf("invalid boot entry, must be a comma separated list of artifacts passed as category:filename")
		}

		category, err := strconv.ParseUint(artifact[0], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid boot entry, must be a comma separated list of artifacts passed as category:filename")
		}

		bootArtifact.Category = uint(category)

		f, err := os.Open(artifact[1])
		if err != nil {
			return nil, fmt.Errorf("invalid boot entry, %w", err)
		}

		if bootArtifact.Data, err = io.ReadAll(f); err != nil {
			return nil, fmt.Errorf("invalid boot entry, %w", err)
		}

		bootEntry.Artifacts = append(bootEntry.Artifacts, bootArtifact)
	}

	return &bootEntry, nil
}

func main() {
	const usage = `
Parse or validate a boot transparency policy.

Usage: bt-policy [--help]
   or: bt-policy parse [--help|options]
   or: bt-policy validate [--help|options]
`

	log.SetFlags(0)
	if len(os.Args) < 2 {
		log.Fatal(usage[1:])
	}

	switch os.Args[1] {
	default:
		log.Fatal(usage[1])
	case "-h", "--help":
		fmt.Print(usage[1:])
	case "parse":
		var settings ParseSettings
		settings.parse(os.Args)

		if policy, err := readPolicy(settings.policyFile); err != nil {
			log.Fatalf("cannot read policy, %v", err)
		} else {
			if parsedPolicy, err := json.MarshalIndent(policy, "", "\t"); err == nil {
				log.Println(string(parsedPolicy))
			}
		}
	case "validate":
		var settings ValidateSettings
		settings.parse(os.Args)

		s, err := readStatement(settings.signedStatementFile)
		if err != nil {
			log.Fatalf("cannot read statement, %v", err)
		}

		p, err := readPolicy(settings.policyFile)
		if err != nil {
			log.Fatalf("cannot read policy, %v", err)
		}

		be, err := loadBootEntry(settings.bootEntryFiles)
		if err != nil {
			log.Fatalf("cannot load boot entry, %v", err)
		}

		if err = be.Validate(p, s); err != nil {
			log.Fatal(err)
		} else {
			log.Printf("signed statement is matching the policy")
		}
	}

	os.Exit(0)
}
