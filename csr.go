package cligencert

import (
	"errors"
	"strconv"
	"strings"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
)

type DefaultCertificateConverter struct {
}

func (c *DefaultCertificateConverter) Desc() string {
	return "Use an existing certificate to derive a fresh key and csr"
}

func (c *DefaultCertificateConverter) GenerateRequest() (*csr.CertificateRequest, error) {
	Say("Please paste in your certificate (leading and trailing spaces are fine)")
	Say("I will keep reading until I see -----END CERTIFICATE-----")
	var certPEM string
	for {
		str := Getline()
		certPEM = certPEM + str + "\n"
		if str == "-----END CERTIFICATE-----" {
			break
		}
	}

	cert, err := helpers.ParseCertificatePEM([]byte(certPEM))
	if err != nil {
		return nil, err
	}
	return csr.ExtractCertificateRequest(cert), nil
}

type CSRInfoAsker struct {
}

func (c *CSRInfoAsker) Desc() string {
	return "Type in csr info such as key type, certificate subject, SANs etc."
}
func (i *CSRInfoAsker) GenerateRequest() (*csr.CertificateRequest, error) {
	cr := csr.New()
	Say("RSA or ECDSA? default ECDSA")
	str := Getline()
	keyreq := csr.NewBasicKeyRequest()
	switch strings.ToLower(str) {
	case "rsa":
		keyreq.A = "rsa"
	case "ecdsa":
		keyreq.A = "ecdsa"
	default:
		Say("Can't understand, use ECDSA")

	}

	Say("key size? default 2048 for RSA, 256 for ECDSA")
	str = Getline()
	if str == "" {
		if keyreq.Algo() == "rsa" {
			keyreq.S = 2048
		}
		if keyreq.Algo() == "ecdsa" {
			keyreq.S = 256
		}
	} else {
		size, err := strconv.Atoi(str)
		if err != nil {
			Say("fail to understand the size as a number, bail out:", err)
			return nil, err
		}
		keyreq.S = size
	}

	cr.KeyRequest = keyreq

	Say("Certificate Common Name?")
	str = Getline()
	cr.CN = str

	Say("Certificate Subject Information")
	name := csr.Name{}
	Say("Country?")
	str = Getline()
	name.C = str
	Say("State/Province?")
	str = Getline()
	name.ST = str
	Say("Locality (City/Town)?")
	str = Getline()
	name.L = str
	Say("Organization/Company?")
	str = Getline()
	name.O = str
	Say("Organization Unit Name?")
	str = Getline()
	name.OU = str
	cr.Names = []csr.Name{name}

	Say("Hostnames for the certificate, i.e. SANs?\nGive me a comma spaced list, IPs and domains are acceptable")
	str = Getline()
	hosts := strings.Split(str, ",")
	for i, h := range hosts {
		hosts[i] = strings.TrimSpace(h)
	}
	cr.Hosts = hosts

	return cr, nil
}

type CSRGeneratorChoice []CertificateRequestGenerator

func (c CSRGeneratorChoice) Desc() string {
	return "a choice between different csr generators"
}

func (c CSRGeneratorChoice) GenerateRequest() (*csr.CertificateRequest, error) {
	if len(c) == 0 {
		return nil, errors.New("can't have zero choices")
	}

	for i, g := range []CertificateRequestGenerator(c) {
		Say("choice [", i, "]: ", g.Desc())
	}
	choice := Getline()
	i, err := strconv.Atoi(choice)
	if err != nil {
		Say("can't understand your choice")
		return nil, err
	}

	if i >= len(c) {
		return nil, errors.New("Bad choice")
	}
	g := c[i]
	return g.GenerateRequest()
}

type DefaultKeyGenerator struct {
}

func (g *DefaultKeyGenerator) Desc() string {
	return "generate key and csr"
}

func (g *DefaultKeyGenerator) GenerateKeyCSR(req *csr.CertificateRequest) (csrPEM, key []byte, err error) {
	Say("Excellent, I now know csr info. I'm generating key and csr...")
	csrPEM, key, err = csr.ParseRequest(req)
	if err != nil {
		return nil, nil, err
	}
	return csrPEM, key, nil
}
