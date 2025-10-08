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

	"github.com/pborman/getopt/v2"
	"github.com/usbarmory/boot-transparency/policy"
	"github.com/usbarmory/boot-transparency/statement"
)

type CheckSettings struct {
	policyFile          string
	signedStatementFile string
}

type ParseSettings struct {
	policyFile string
}

func (s *CheckSettings) parse(args []string) {
	const usage = `
Check a given signed statement against a boot-transparency policy,
the result is printed to stdout.
`
	help := false

	set := getopt.New()
	set.SetProgram(args[0] + " " + args[1])

	set.FlagLong(&s.policyFile, "policy-file", 'p', "Signed statement file", "policy-file").Mandatory()
	set.FlagLong(&s.signedStatementFile, "signed-statement", 's', "Signed statement file", "signed-statement-file").Mandatory()
	set.FlagLong(&help, "help", 'h', "Show usage message and exit")

	err := set.Getopt(args[1:], nil)

	// handle help before checking for errors on other arguments
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

	// handle help before checking for errors on other arguments
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

func readStatement(fileName string) (*statement.Statement, error) {
	var s *statement.Statement

	f, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}

	bytes, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	s, err = statement.Parse(bytes)
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

	p, err = policy.Parse(bytes)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func main() {
	const usage = `
Parse or check a boot transparency policy.

Usage: bt-policy [--help]
   or: bt-policy parse [--help|options]
   or: bt-policy check [--help|options]
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
			log.Fatalf("read policy %q failed: %v", settings.policyFile, err)
		} else {
			if parsedPolicy, err := json.MarshalIndent(policy, "", "\t"); err == nil {
                                log.Println(string(parsedPolicy))
			}
		}
	case "check":
		var settings CheckSettings
		settings.parse(os.Args)

		s, err := readStatement(settings.signedStatementFile)
		if err != nil {
			log.Fatalf("statement read from %q failed: %v", settings.signedStatementFile, err)
		}

		p, err := readPolicy(settings.policyFile)
		if err != nil {
			log.Fatalf("read policy %q failed: %v", settings.policyFile, err)
		}

		if err = policy.Check(p, s); err != nil {
			log.Fatal(err)
		} else {
			log.Printf("signed statement is matching the policy")
		}
	}

	os.Exit(0)
}
