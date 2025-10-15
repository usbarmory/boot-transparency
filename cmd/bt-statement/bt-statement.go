// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/pborman/getopt/v2"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"

	_ "github.com/usbarmory/boot-transparency/artifact/initrd"
	_ "github.com/usbarmory/boot-transparency/artifact/linux_kernel"
	_ "github.com/usbarmory/boot-transparency/artifact/uefi_bios"
	"github.com/usbarmory/boot-transparency/statement"
)

type VerifySettings struct {
	publicKeyFile       string
	signedStatementFile string
}

type SignSettings struct {
	privateKeyFile      string
	statementFile       string
	signedStatementFile string
}

type ParseSettings struct {
	statementFile string
}

func (s *VerifySettings) parse(args []string) {
	const usage = `
Verify an Ed25519 signature with a given signed statement.
The signed statement, and the public key are provided as input files,
the verification result is printed to stdout.
`
	help := false

	set := getopt.New()
	set.SetProgram(args[0] + " " + args[1])

	set.FlagLong(&s.signedStatementFile, "signed-statement", 's', "Signed statement file", "signed-statement-file").Mandatory()
	set.FlagLong(&s.publicKeyFile, "public-key", 'p', "Public key(s) in OpenSSH format to verify a signed bundle of artifacts", "public-key-file").Mandatory()
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

func (s *SignSettings) parse(args []string) {
	const usage = `
Append an Ed25519 signature to a given statement.
The statement, and the private key are provided as input files,
the signed statement is saved to an output file.
`
	help := false
	set := getopt.New()
	set.SetProgram(args[0] + " " + args[1])

	set.FlagLong(&s.statementFile, "statement", 'c', "Statement file", "statement-file").Mandatory()
	set.FlagLong(&s.privateKeyFile, "private-key", 'k', "Private key(s) in OpenSSH format to sign a bundle of artifacts", "private-key-file").Mandatory()
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
Parse a boot-transparency statement.
The statement is provided as input file in JSON format according to boot transparency specifications,
the result of the parsing is printed to stdout.
`
	help := false
	set := getopt.New()
	set.SetProgram(args[0] + " " + args[1])

	set.FlagLong(&s.statementFile, "statement", 'c', "Statement file", "statement-file").Mandatory()
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

func writeSignedStatementFile(outputFile string, outputStatement *statement.Statement, signature *crypto.Signature, publicKey crypto.PublicKey) error {
	if len(outputFile) > 0 {
		var err error
		var signedS []byte

		f, err := os.OpenFile(outputFile,
			os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		defer closeFile(f)

		s := statement.Signature{}
		s.Signature = fmt.Sprintf("%x", signature[:])

		// Ed25519 public keys following SSH format
		prefix := []byte{'\v', 's', 's', 'h', '-', 'e', 'd', '2', '5', '5', '1', '9', 0, 0, 0}
		plainKey := strings.Join([]string{string(prefix[:]), string(publicKey[:])}, " ")
		encodedKey := base64.StdEncoding.EncodeToString([]byte(plainKey))
		s.PubKey = strings.Join([]string{"ssh-ed25519 AAAA", encodedKey}, "")

		// append the new signature, do not overwrite any existing one already present in the statement
		outputStatement.Signatures = append(outputStatement.Signatures, s)

		if signedS, err = json.MarshalIndent(outputStatement, "", "\t"); err != nil {
			return err
		}

		if _, err = f.Write(signedS); err != nil {
			return err
		}
	}

	return nil
}

func closeFile(f *os.File) {
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
}

func main() {
	const usage = `
Parse, sign, or verify, a statement associated to an artifact bundle.

Usage: bt-statement [--help]
   or: bt-statement parse [--help|options]
   or: bt-statement sign [--help|options]
   or: bt-statement verify [--help|options]
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

		if statement, err := readStatement(settings.statementFile); err != nil {
			log.Fatalf("read statement %q failed: %v", settings.statementFile, err)
		} else {
			if parsedStatement, err := json.MarshalIndent(statement, "", "\t"); err == nil {
				log.Println(string(parsedStatement))
			}
		}
	case "sign":
		var settings SignSettings
		settings.parse(os.Args)

		signer, err := key.ReadPrivateKeyFile(settings.privateKeyFile)
		if err != nil {
			log.Fatal(err)
		}

		statement, err := readStatement(settings.statementFile)
		if err != nil {
			log.Fatalf("statement read from %q failed: %v", settings.statementFile, err)
		}

		// Sign only the artifacts section of the bundle statement
		artifacts, err := json.Marshal(statement.Artifacts)
		if err != nil {
			log.Fatalf("statement sign failed: %v", err)
		}
		signature, err := signer.Sign(artifacts)
		if err != nil {
			log.Fatalf("statement sign failed: %v", err)
		}

		// Append the new signature, and the public key associated to the signer key, to the output file
		if err = writeSignedStatementFile(settings.signedStatementFile, statement, &signature, signer.Public()); err != nil {
			log.Fatalf("statement sign failed: %v", err)
		}

		log.Printf("signed statement written to: %q", settings.signedStatementFile)
	case "verify":
		var settings VerifySettings
		settings.parse(os.Args)

		publicKey, err := key.ReadPublicKeyFile(settings.publicKeyFile)
		if err != nil {
			log.Fatal(err)
		}

		statement, err := readStatement(settings.signedStatementFile)
		if err != nil {
			log.Fatalf("read statement %q failed: %v", settings.signedStatementFile, err)
		}
		artifacts, err := json.Marshal(statement.Artifacts)
		if err != nil {
			log.Fatalf("signature verification failed: %v", err)
		}

		// the signed statement can contain multiple signatures
		foundValidSignature := false
		for _, sig := range statement.Signatures {
			s, err := crypto.SignatureFromHex(sig.Signature)
			if err != nil {
				log.Fatalf("signature verification failed: %v", err)
			}

			if crypto.Verify(&publicKey, artifacts, &s) {
				log.Printf("signature is valid")
				foundValidSignature = true
				break
			}
		}

		if !foundValidSignature {
			log.Fatalf("signature is NOT valid")
		}
	}

	os.Exit(0)
}
