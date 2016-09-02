package cligencert

import (
	"bytes"
	"strconv"
	"strings"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

type PGPEncryptor struct{}

func (e *PGPEncryptor) Desc() string {
	return "do PGP encryption on private key"
}

func (e *PGPEncryptor) Encrypt(key []byte) ([]byte, error) {
	Say("May I ask you to paste in the public key block?")
	Say("I will keep reading until I see -----END PGP PUBLIC KEY BLOCK-----")

	var keyBlock string
	for {
		str := Getline()
		keyBlock = keyBlock + str + "\n"
		if str == "-----END PGP PUBLIC KEY BLOCK-----" {
			break
		}
	}

	pubringBlock, err := armor.Decode(bytes.NewBuffer([]byte(keyBlock)))
	if err != nil {
		Error("failed to parse keys:", err)
		return nil, err
	}

	keyring, err := openpgp.ReadKeyRing(pubringBlock.Body)
	if err != nil {
		Error("failed to parse keys:", err)
		return nil, err
	}
	// list keys
	for i, entity := range keyring {
		var names []string
		for _, id := range entity.Identities {
			names = append(names, id.UserId.Id)
		}
		Say("key [", i, "]", "with identities:", names)
	}

	// choose a key
	Say("Please choose keys for encryption, you can choose multiple keys, sperated by comma")
	str := Getline()
	var choices []int
	rawChoices := strings.Split(str, ",")
	for _, c := range rawChoices {
		i, err := strconv.Atoi(c)
		if err != nil {
			Error("Can't parse the choices:", err)
			return nil, err
		}
		choices = append(choices, i)
	}

	var chosenEntities openpgp.EntityList
	for _, c := range choices {
		chosenEntities = append(chosenEntities, keyring[c])
	}
	headers := map[string]string{
		"Version": "cligencert util v0.01",
	}
	outbuf := bytes.NewBuffer(nil)
	w, err := armor.Encode(outbuf, "PGP MESSAGE", headers)
	if err != nil {
		return nil, err
	}

	plaintext, err := openpgp.Encrypt(w, chosenEntities, nil, nil, nil)
	if err != nil {
		return nil, err
	}

	_, err = plaintext.Write(key)
	if err != nil {
		return nil, err
	}

	plaintext.Close()
	w.Close()
	return outbuf.Bytes(), nil

}
