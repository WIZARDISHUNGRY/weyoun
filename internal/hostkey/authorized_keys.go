package hostkey

import (
	"fmt"
	"io/ioutil"
	"os/user"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func GetAuthorizedKeys() ([]ssh.PublicKey, error) {
	usr, err := user.Current()
	if err != nil {
		return nil, err
	}
	authorizedKeysPath := usr.HomeDir + "/.ssh/authorized_keys"

	// Public key authentication is done by comparing
	// the public key of a received connection
	// with the entries in the authorized_keys file.
	authorizedKeysBytes, err := ioutil.ReadFile(authorizedKeysPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to load authorized_keys: %w", err)
	}
	agentKeys, err := List()
	if err != nil {
		return nil, err
	}

	authorizedKeys := []ssh.PublicKey{}
	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			return nil, err
		}

		authorizedKeys = append(authorizedKeys, pubKey)
		authorizedKeysBytes = rest
	}

	for _, pubKey := range agentKeys {
		authorizedKeys = append(authorizedKeys, pubKey)
	}

	return authorizedKeys, nil
}

func GetAuthorizedKeysCallback() (func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error), error) {
	authorizedKeys, err := GetAuthorizedKeys()
	if err != nil {
		return nil, err
	}

	authorizedKeysMap := map[string]bool{}
	for _, pubKey := range authorizedKeys {
		authorizedKeysMap[string(pubKey.Marshal())] = true
	}

	return func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
		if authorizedKeysMap[string(pubKey.Marshal())] {
			return &ssh.Permissions{
				// Record the public key used for authentication.
				Extensions: map[string]string{
					"pubkey-fp":   ssh.FingerprintSHA256(pubKey),
					"pubkey-type": pubKey.Type(),
				},
			}, nil
		}
		return nil, fmt.Errorf("unknown public key for %q", c.User())
	}, nil
}

func List() ([]*agent.Key, error) {
	agent, err := LoadAgent()
	if err != nil {
		return nil, fmt.Errorf("failed to load agent: %w", err)
	}

	agentKeys, err := agent.List()
	if err != nil {
		return nil, fmt.Errorf("failed to load agent identities: %w", err)
	}
	return agentKeys, nil
}
