package main

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
)

type PublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type RSAPublicKey struct {
	N *big.Int
	E int
}

var (
	file    = flag.String("file", "", "A PEM-encoded public key or certificate file.")
	verbose = flag.Bool("verbose", false, "Show more information.")
)

func main() {
	flag.Parse()

	var contents []byte
	var err error
	if *file == "" {
		contents, err = ioutil.ReadAll(os.Stdin)
	} else {
		contents, err = ioutil.ReadFile(*file)
	}
	if err != nil {
		log.Fatal(err)
	}

	block, _ := pem.Decode(contents)
	if block == nil {
		log.Fatal("Not a PEM block.")
	}

	var keybytes []byte
	switch block.Type {
	case "PUBLIC KEY", "RSA PUBLIC KEY":
		keybytes = block.Bytes
	case "CERTIFICATE":
		certs, err := x509.ParseCertificates(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		if len(certs) < 1 {
			log.Fatal("No certificates.")
		}
		keybytes = certs[0].RawSubjectPublicKeyInfo
	default:
		log.Fatalf("Unknown block type: %q.", block.Type)
	}

	hasher := sha256.New()
	hasher.Write(keybytes)
	fmt.Printf("sha256/%v\n", base64.StdEncoding.EncodeToString(hasher.Sum(nil)))

	if *verbose {
		var spki PublicKeyInfo
		asn1.Unmarshal(keybytes, &spki)
		fmt.Printf("AlgID: %v\n", spki.Algorithm.Algorithm)
		var pubkey RSAPublicKey
		asn1.Unmarshal(spki.PublicKey.Bytes, &pubkey)
		fmt.Printf("N: %v\n", pubkey.N)
		fmt.Printf("E: %v\n", pubkey.E)
	}
}
