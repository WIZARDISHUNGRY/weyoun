package hostkey

import (
	"bytes"
	"fmt"

	"golang.org/x/crypto/ssh"
)

func GetPublicKeysCallback() (ssh.AuthMethod, error) {

	agent, err := LoadAgent()
	if err != nil {
		return nil, err
	}
	signers, err := agent.Signers()
	if err != nil {
		return nil, fmt.Errorf("Failed to get keys: %w", err)
	}

	return ssh.PublicKeysCallback(func() ([]ssh.Signer, error) { return signers, nil }), nil
}

func PublicKeys() ([]ssh.PublicKey, error) {

	agent, err := LoadAgent()
	if err != nil {
		return nil, err
	}
	signers, err := agent.Signers()
	if err != nil {
		return nil, fmt.Errorf("Failed to get keys: %w", err)
	}
	pkeys := make([]ssh.PublicKey, 0)
	for _, signer := range signers {
		pkeys = append(pkeys, signer.PublicKey())
	}
	return pkeys, nil
}

// FilterKeys returns the union of two sets of keys
func FilterKeys(set, intersect []ssh.PublicKey) (out []ssh.PublicKey) {
OUTER:
	for _, sKey := range set {
		for _, iKey := range intersect {
			if bytes.Equal(sKey.Marshal(), iKey.Marshal()) {
				out = append(out, sKey)
				continue OUTER
			}
		}
	}
	return
}
