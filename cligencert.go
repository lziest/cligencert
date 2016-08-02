package cligencert

import (
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
)

type CertificateRequestGenerator interface {
	GenerateRequest() *csr.CertificateRequest
}

type KeyGenerator interface {
	GenerateKeyCSR(req *csr.CertificateRequest) (csr []byte, key []byte, err error)
}

type Encryptor interface {
	Encrypt(key []byte) ([]byte, error)
}

type SigningConfGenerator interface {
	Conf() config.Signing
}
type CSRSigner interface {
	Sign(csr []byte, conf config.Signing) ([]byte, error)
}

type Runner struct {
	CertReqGen CertificateRequestGenerator
	KeyGen     KeyGenerator
	KeyEnc     Encryptor
	ConfGen    SigningConfGenerator
	Signer     CSRSigner
}

func (r Runner) Run() {
	req := r.CertReqGen()
	csr, key, err := r.KeyGen(req)
	if err != nil {
		fmt.Println("failed to generate csr and key:", err)
		return
	}
	fmt.Println(csr)
	fmt.Println(key)
	if r.KeyEnc != nil {
		enc, err := r.KeyEnc.Encrypt(key)
		if err != nil {
			fmt.Println("failed to encrypt key:", err)
			return
		}
		fmt.Println(enc)
	}
	config := r.ConfGen.Conf()
	cert, err := r.Signer.Sign(csr, config)
	if err != nil {
		fmt.Println("failed to sign csr:", err)
		return
	}
	fmt.Println(cert)

}
