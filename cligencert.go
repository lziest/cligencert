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
	Conf() (*config.Signing, error)
}
type CSRSigner interface {
	Descriptor
	Sign(csr []byte, conf *config.Signing) ([]byte, error)
}

type Runner struct {
	CertReqGen CertificateRequestGenerator
	KeyGen     KeyGenerator
	KeyEnc     Encryptor
	ConfGen    SigningConfGenerator
	Signer     CSRSigner
}

var (
	bufin  *bufio.Reader
	cout   *color.Color
	gout   *color.Color
	errout *color.Color
)

func init() {
	bufin = bufio.NewReader(os.Stdin)
	cout = color.New(color.FgCyan, color.Bold)
	gout = color.New(color.FgGreen, color.Bold)
	errout = color.New(color.FgRed, color.Bold)

}

func Getline() string {
	str, _ := bufin.ReadString('\n')
	return strings.TrimSpace(str)
}

func Say(a ...interface{}) {
	cout.Println(a...)
}

func Greet(a ...interface{}) {
	gout.Println(a...)
}

func Error(a ...interface{}) {
	errout.Println(a...)
}

func (r Runner) Run() {
	if r.CertReqGen == nil {
		Error("bad csr generating routine")
		return
	}
	req, err := r.CertReqGen.GenerateRequest()
	if err != nil {
		Error("failed to generate csr and key:", err)
		return
	}
	if r.KeyGen == nil {
		Error("bad key generating routine")
		return
	}
	csr, key, err := r.KeyGen.GenerateKeyCSR(req)
	if err != nil {
		Error("failed to generate csr and key:", err)
		return
	}
	Say("I have the private key and csr now.")
	Greet("Here is the csr")
	// non-colored output for contrast
	fmt.Println(string(csr))
	Greet("Here is the key")
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

	if r.ConfGen == nil {
		Error("bad remote signer conf generator routine")
		return
	}
	config, err := r.ConfGen.Conf()
	if err != nil {
		Error("failed to get remote signer config:", err)
		return
	}

	if r.Signer == nil {
		Error("bad remote signer routine")
		return
	}
	cert, err := r.Signer.Sign(csr, config)
	if err != nil {
		fmt.Println("failed to sign csr:", err)
		return
	}
	Greet("Here is the certificate")
	fmt.Println(string(cert))

}
