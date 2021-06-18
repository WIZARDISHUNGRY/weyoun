package hostkey

import (
	"fmt"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
)

func GetPublicKeysCallback() (ssh.AuthMethod, error) {
	signers, err := getSigners()
	if err != nil {
		return nil, err
	}

	log.Debug().
		Int("numSigners", len(signers)).
		Msg("GetPublicKeysCallback")

	return ssh.PublicKeysCallback(func() ([]ssh.Signer, error) { return signers, nil }), nil
}

func getSigners() ([]ssh.Signer, error) {
	agent, err := LoadAgent()
	if err != nil {
		return nil, err
	}
	signers, err := agent.Signers()
	if err != nil {
		return nil, fmt.Errorf("Failed to get keys: %w", err)
	}

	newSigners := make([]ssh.Signer, 0, len(signers))
	for _, signer := range signers {
		// RSA keys are blacklisted because I can't figure out how to
		// disallow YubiKey keys from my gpg/ssh-agent
		if signer.PublicKey().Type() == "ssh-rsa" {
			continue
		}
		newSigners = append(newSigners, signer)
	}

	return newSigners, nil
}

func PublicKeys() ([]ssh.PublicKey, error) {
	signers, err := getSigners()
	if err != nil {
		return nil, err
	}
	pkeys := make([]ssh.PublicKey, 0)
	for _, signer := range signers {
		pkeys = append(pkeys, signer.PublicKey())
	}
	return pkeys, nil
}

// FilterKeys returns the union of two sets of keys
// TODO prehash host keys (set)
func FilterKeys(set []ssh.PublicKey, intersect []string) (out []ssh.PublicKey) {
OUTER:
	for _, sKey := range set {
		h := ssh.FingerprintSHA256(sKey)
		for _, iKey := range intersect {
			if h == iKey {
				out = append(out, sKey)
				continue OUTER
			}
		}
	}
	return
}
