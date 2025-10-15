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

	"github.com/pborman/getopt/v2"
	_ "github.com/usbarmory/boot-transparency/engine/sigsum"
	_ "github.com/usbarmory/boot-transparency/engine/tessera"
	_ "github.com/usbarmory/boot-transparency/policy"
	"github.com/usbarmory/boot-transparency/statement"
	"github.com/usbarmory/boot-transparency/transparency"
)

type CreateSettings struct {
	transparencyEngine  string
	inclusionProofFile  string
	signedStatementFile string
	probeFile           string
	proofBundleFile     string
}

type ParseSettings struct {
	proofBundleFile string
}

func (s *CreateSettings) parse(args []string) {
	const usage = `
Create a boot-transparency proof bundle from a given set of
signed statement, probe data and inclusion proof files.
The output is written to stdout.
`
	help := false

	set := getopt.New()
	set.SetProgram(args[0] + " " + args[1])

	set.FlagLong(&s.transparencyEngine, "engine", 'e', "Transparency engine (i.e. 1: Sigsum or 2: Tessera)", "transparency-engine").Mandatory()
	set.FlagLong(&s.inclusionProofFile, "inclusion-proof", 'i', "Inclusion proof file", "inclusion-proof-file").Mandatory()
	set.FlagLong(&s.probeFile, "probe", 'p', "Proof probe file, contains data to request the inclusion proof to the log", "probe-file").Mandatory()
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
Parse a boot-transparecy proof bundle,
the result is printed to stdout.
`
	help := false
	set := getopt.New()
	set.SetProgram(args[0] + " " + args[1])

	set.FlagLong(&s.proofBundleFile, "bundle", 'p', "Boot-transparency proof bundle file", "bundle-file").Mandatory()
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

func readFile(fileName string) (bytes []byte, err error) {
	f, err := os.Open(fileName)
	if err != nil {
		return
	}

	bytes, err = io.ReadAll(f)
	if err != nil {
		return
	}

	return
}

func main() {
	const usage = `
Parse or create a boot transparency proof bundle.

Usage: bt-proof [--help]
   or: bt-proof parse [--help|options]
   or: bt-proof create [--help|options]
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
		var pb transparency.ProofBundle

		if jsonProofBundle, err := readFile(settings.proofBundleFile); err != nil {
			log.Fatalf("read proof bundle %q failed: %v", settings.proofBundleFile, err)
		} else {
			if err := json.Unmarshal(jsonProofBundle, &pb); err != nil {
				log.Fatalf("invalid proof bundle: %v", err)
			}

			e, err := transparency.GetEngine(pb.Format)
			if err != nil {
				log.Fatalf("unsupported bundle format: %v", err)
			}

			// use the marshal version of the parsed proof bundle
			// (i.e. []byte output returned as second value by the parsing function)
			_, parsed, err := e.ParseProof(jsonProofBundle)
			if err != nil {
				log.Fatalf("invalid proof bundle: %v", err)
			}

			// print result to stdout
			fmt.Printf(string(parsed))
		}
	case "create":
		var settings CreateSettings

		settings.parse(os.Args)

		s, err := readFile(settings.signedStatementFile)
		if err != nil {
			log.Fatalf("read statement %q failed: %v", settings.signedStatementFile, err)
		}

		_, err = statement.Parse(s)
		if err != nil {
			log.Fatalf("parse statement %q failed: %v", settings.signedStatementFile, err)
		}

		ip, err := readFile(settings.inclusionProofFile)
		if err != nil {
			log.Fatalf("read inclusion proof %q failed: %v", settings.inclusionProofFile, err)
		}

		p, err := readFile(settings.probeFile)
		if err != nil {
			log.Fatalf("read probe %q failed: %v", settings.probeFile, err)
		}

		format, err := strconv.ParseUint(settings.transparencyEngine, 10, 64)
		if err != nil {
			log.Fatalf("invalid transparency engine: %s", settings.transparencyEngine)
		}

		// for Sigsum the inclusion proof need to be marshal to JSON string
		if uint(format) == transparency.Sigsum {
			ip, err = json.Marshal(string(ip))
			if err != nil {
				log.Fatalf("failed to marshal inclusion proof %v", err)
			}
		}

		// assemble a preliminary proof bundle
		pb := transparency.ProofBundle{
			Format:    uint(format),
			Statement: s,
			Probe:     p,
			Proof:     ip,
		}

		jsonProofBundle, err := json.MarshalIndent(&pb, "", "\t")
		if err != nil {
			log.Fatalf("failed to marshal the proof bundle: %v", err)
		}

		// parse the preliminary bundle to ensure it is consistent
		// with the transparency engine format
		e, err := transparency.GetEngine(pb.Format)
		if err != nil {
			log.Fatalf("unsupported bundle format: %v", err)
		}

		// use the marshal version of the parsed proof bundle
		// (i.e. []byte output returned as second value by the parsing function)
		_, parsed, err := e.ParseProof(jsonProofBundle)
		if err != nil {
			log.Fatalf("invalid proof bundle: %v", err)
		}

		// print result to stdout
		fmt.Printf(string(parsed))
	}

	os.Exit(0)
}
