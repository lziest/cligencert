package cligencert

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/fatih/color"
)

type Descriptor interface {
	Desc() string
}

type CertificateRequestGenerator interface {
	Descriptor
	GenerateRequest() (*csr.CertificateRequest, error)
}

type KeyGenerator interface {
	Descriptor
	GenerateKeyCSR(req *csr.CertificateRequest) (csr []byte, key []byte, err error)
}

type Encryptor interface {
	Descriptor
	Encrypt(key []byte) ([]byte, error)
}

type SigningConfGenerator interface {
	Descriptor
	Conf() config.Signing
}
type CSRSigner interface {
	Descriptor
	Sign(csr []byte, conf config.Signing) ([]byte, error)
}

type Runner struct {
	CertReqGen CertificateRequestGenerator
	KeyGen     KeyGenerator
	KeyEnc     Encryptor
	ConfGen    SigningConfGenerator
	Signer     CSRSigner
}

var bufin *bufio.Reader
var cout *color.Color
var errout *color.Color

func init() {
	bufin = bufio.NewReader(os.Stdin)
	cout = color.New(color.FgCyan, color.Bold)
	errout = color.New(color.FgRed, color.Bold)

}

func Getline() string {
	str, _ := bufin.ReadString('\n')
	return strings.TrimSpace(str)
}

func Say(a ...interface{}) {
	cout.Println(a...)
}

func Error(a ...interface{}) {
	errout.Println(a...)
}

func (r Runner) Run() {
	req, err := r.CertReqGen.GenerateRequest()
	if err != nil {
		Error("failed to generate csr and key:", err)
		return
	}
	csr, key, err := r.KeyGen.GenerateKeyCSR(req)
	if err != nil {
		Error("failed to generate csr and key:", err)
		return
	}
	Say("I have the private key and csr now.")
	Say("Here is the csr")
	// non-colored output for contrast
	fmt.Println(string(csr))
	Say("Here is the key")
	fmt.Println(string(key))
	if r.KeyEnc != nil {
		enc, err := r.KeyEnc.Encrypt(key)
		if err != nil {
			Error("failed to encrypt key:", err)
			return
		}
		Say("Here is the encrypted key")
		fmt.Println(enc)
	}
	/*
		config := r.ConfGen.Conf()
		cert, err := r.Signer.Sign(csr, config)
		if err != nil {
			fmt.Println("failed to sign csr:", err)
			return
		}
		fmt.Println(cert)
	*/

}
