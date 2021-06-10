package weyoun

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"

	zeroconf "github.com/grandcat/zeroconf"
	"golang.org/x/crypto/ssh"
	"jonwillia.ms/weyoun/internal/hostkey"
)

func Locator(ctx context.Context, serviceName string) (<-chan *zeroconf.ServiceEntry, error) {
	// for now only connect to services who publish a text record matching one of our signing keys
	// TODO: ideally this would be a signed version of host + port with the key
	myKeys, err := hostkey.Signers()
	if err != nil {
		return nil, fmt.Errorf("failed to get user signers: %w", err)
	}
	matchers := make([][]string, 0)
	for _, myKey := range myKeys {
		matchers = append(matchers, RegisterText(
			[]ssh.PublicKey{
				myKey.PublicKey(),
			},
		))
	}

	return Locate(ctx, serviceName, matchers)
}

func Dialers(ctx context.Context, svc *zeroconf.ServiceEntry) ([]func(ctx context.Context) (*ssh.Client, error), error) {
	host := ""
	nilStringer := func(s fmt.Stringer) string {
		if s == nil {
			return ""
		}
		return s.String()
	}
	addrStrings := []string{}
	for _, addr := range append(svc.AddrIPv6, svc.AddrIPv4...) {
		s := nilStringer(addr)
		addrStrings = append(addrStrings, s)
	}
	dialers := make([]func(ctx context.Context) (*ssh.Client, error), 0)

	for _, s := range addrStrings {
		host = s
		if host == "" {
			continue
		}
		dialers = append(dialers, dialerFor(host, svc))
	}

	return dialers, nil
}

func dialerFor(host string, svc *zeroconf.ServiceEntry,
) func(ctx context.Context) (*ssh.Client, error) {
	return func(ctx context.Context) (*ssh.Client, error) {
		addrStr := net.JoinHostPort(host, strconv.Itoa(svc.Port))
		log.Info().Str("addr", addrStr).Msg("Connecting")

		remoteKeys, err := hostkey.PublicKeys()
		zeroconfKeys := HostKeys(svc)
		remoteKeys = hostkey.FilterKeys(remoteKeys, zeroconfKeys)

		hkcb, err := hostkey.GetHostKeyCallBack(remoteKeys)
		if err != nil {
			return nil, fmt.Errorf("failed to get host keys: %w", err)
		}

		authMethod, err := hostkey.GetPublicKeysCallback()
		if err != nil {
			return nil, fmt.Errorf("failed to get user keys: %w", err)
		}

		config := &ssh.ClientConfig{
			User: "pubkey-fp", // TODO don't use this
			Auth: []ssh.AuthMethod{
				authMethod,
			},
			HostKeyCallback: hkcb,
			Timeout:         time.Second,
		}
		dialer := net.Dialer{}
		conn, err := dialer.DialContext(ctx, "tcp", addrStr)
		if err != nil {
			return nil, fmt.Errorf("net.Dialer.DialContext: %w", err)
		}
		sshConn, newChannelChan, reqs, err := ssh.NewClientConn(conn, addrStr, config)
		if err != nil {
			return nil, fmt.Errorf("ssh.NewClientConn: %w", err)
		}
		return ssh.NewClient(sshConn, newChannelChan, reqs), nil
	}
}
