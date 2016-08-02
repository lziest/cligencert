package cligencert

import (
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/remote"
)

type Signer struct {
}

func (s *Signer) Desc() string {
	return "CSR signer using a cfssl server"
}

func (s *Signer) Sign(csr []byte, conf *config.Signing) ([]byte, error) {
	rsigner, err := remote.NewSigner(conf)
	if err != nil {
		return nil, err
	}

	Say("What's the label of the remote CA?")
	label := Getline()

	req := signer.SignRequest{
		Request: string(csr),
		Label:   label,
	}

	return rsigner.Sign(req)
}
