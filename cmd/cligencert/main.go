package main

import (
	"github.com/lziest/cligencert"
)

func main() {
	r := cligencert.Runner{
		CertReqGen: cligencert.CSRGeneratorChoice(
			[]cligencert.CertificateRequestGenerator{
				&cligencert.DefaultCertificateConverter{},
				&cligencert.CSRInfoAsker{},
			}),
		KeyGen:  &cligencert.DefaultKeyGenerator{},
		ConfGen: &cligencert.ConfAsker{},
		Signer:  &cligencert.Signer{},
	}
	r.Run()
}
