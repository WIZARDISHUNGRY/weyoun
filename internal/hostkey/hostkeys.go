package hostkey

import (
	"crypto/subtle"
	"fmt"
	"net"

	"golang.org/x/crypto/ssh"
)

func GetHostKeyCallBack(keys []ssh.PublicKey) (
	func(hostname string, remote net.Addr, key ssh.PublicKey) error,
	error) {

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		remoteBytes := key.Marshal()
		ok := false
		for _, key := range keys {
			if subtle.ConstantTimeCompare(remoteBytes, key.Marshal()) == 1 {
				ok = true
			}
		}
		if ok {
			return nil
		}
		return fmt.Errorf("host key mismatch")
	}, nil
}

func Signers() ([]ssh.Signer, error) {
	agent, err := LoadAgent()
	if err != nil {
		return nil, err
	}
	signers, err := agent.Signers()
	if err != nil {
		return nil, fmt.Errorf("Failed to get keys: %w", err)
	}
	return signers, nil
}
