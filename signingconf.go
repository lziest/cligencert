package cligencert

import (
	"github.com/cloudflare/cfssl/auth"
	"github.com/cloudflare/cfssl/config"
)

type ConfAsker struct {
}

func (a *ConfAsker) Desc() string {
	return "Type in the remote (cfssl API based) signer info"
}

func (a *ConfAsker) Conf() (*config.Signing, error) {
	Say("The remote signer address:")
	remote := Getline()
	Say("The authentication key (hex-based):")
	key := Getline()
	provider, err := auth.New(key, nil)
	if err != nil {
		return nil, err
	}
	p := config.Signing{
		Default: &config.SigningProfile{
			AuthRemote: config.AuthRemote{
				RemoteName:  "dummy",
				AuthKeyName: "dummy",
			},
			RemoteServer:   remote,
			RemoteProvider: provider,
		},
	}

	return &p, nil

}
