package weyoun

import (
	"context"
	"fmt"
	"net"
	"runtime/debug"
	"strings"

	"github.com/rs/zerolog/log"

	zeroconf "github.com/grandcat/zeroconf"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func Locate(ctx context.Context, service string, matchers [][]string) (<-chan *zeroconf.ServiceEntry, error) {
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize resolver: %w", err)
	}

	results := make(chan *zeroconf.ServiceEntry)
	output := make(chan *zeroconf.ServiceEntry)
	err = resolver.Lookup(ctx, "", service, "", results)
	if err != nil {
		return nil, fmt.Errorf("Failed to Lookup: %w", err)
	}

	go func() {
		defer close(output)
		for {
			select {
			case result := <-results:
				if result == nil {
					return
				}
				if matchAny(result.Text, matchers) {
					output <- result
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return output, nil
}

func matchAny(record []string, matchers [][]string) bool {
	ok := true
	for _, matcher := range matchers {
		ok = match(record, matcher)
		if ok {
			return true
		}
	}
	return ok
}

func match(record []string, matcher []string) bool {
	for _, query := range matcher {
		ok := false
		for _, line := range record {
			if line == query {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func Register(ctx context.Context, name, service string, tcpAddr *net.TCPAddr, zeroconfKeys []string) error {

	s, err := zeroconf.Register(name, service, "local.", tcpAddr.Port, zeroconfKeys, nil)
	if err != nil {
		return err
	}
	go func() {
		defer s.Shutdown()
		<-ctx.Done()
	}()
	return nil
}

const (
	keyPrefix   = "weyoun-"
	keySsh      = keyPrefix + "key"
	keyMainPath = keyPrefix + "mainPath"
)

func RegisterText(pubKeys []ssh.PublicKey) (result []string) {
	register := func(k, v string) { result = append(result, k+"="+v) }
	bi, ok := debug.ReadBuildInfo()
	if ok {
		main := bi.Main
		register(keyMainPath, main.Path)
	}
	for _, pk := range pubKeys {
		register(keySsh, knownhosts.Line([]string{"weyoun.example.com"}, pk))
	}
	return
}

// HostKeys keys announced in zeroconf
func HostKeys(svc *zeroconf.ServiceEntry) []ssh.PublicKey {
	return parseTextRecord(svc.Text)
}

func parseTextRecord(txt []string) []ssh.PublicKey {
	pubKeys := make([]ssh.PublicKey, 0)
	for _, s := range txt {
		bits := strings.SplitN(s, "=", 2)
		if len(bits) != 2 {
			continue
		}
		k, v := bits[0], bits[1]
		switch k {
		case keySsh:
			_, _, pubKey, _, _, err := ssh.ParseKnownHosts([]byte(v))
			if err != nil {
				log.Printf("bad key in zeroconf: %v\n", err)
				continue
			}
			pubKeys = append(pubKeys, pubKey)
		}
	}
	return pubKeys
}
