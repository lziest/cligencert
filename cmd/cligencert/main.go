package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/lziest/cligencert"
)

func main() {
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	fs.Usage = func() {
		fmt.Println(
			`Just run this program to get a certificate issued interactively.
Do what it says and nobody will get hurt...
`)
	}
	fs.Parse(os.Args[1:])
	r := cligencert.Runner{
		CertReqGen: cligencert.CSRGeneratorChoice(
			[]cligencert.CertificateRequestGenerator{
				&cligencert.DefaultCertificateConverter{},
				&cligencert.CSRInfoAsker{},
			}),
		KeyGen:  &cligencert.DefaultKeyGenerator{},
		ConfGen: &cligencert.ConfAsker{},
		Signer:  &cligencert.Signer{},
		KeyEnc:  &cligencert.PGPEncryptor{},
	}
	r.Run()
}
