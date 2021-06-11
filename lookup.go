package weyoun

import (
	"context"
	"fmt"
	"net"
	"runtime/debug"
	"strings"

	zeroconf "github.com/grandcat/zeroconf"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
)

func Locate(ctx context.Context, service string, matchers, negativeMatchers [][]string) (<-chan *zeroconf.ServiceEntry, error) {
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
				if !matchAny(result.Text, matchers) {
					continue
				}
				log.Debug().Str("Instance", result.Instance).Msg("matched")
				if !matchAny(result.Text, negativeMatchers) {
					output <- result
				} else {
					fmt.Println(negativeMatchers)
					log.Debug().Str("Instance", result.Instance).Msg("and skipped")
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return output, nil
}

func matchAny(record []string, matchers [][]string) bool {
	ok := false
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
	keyUniq     = keyPrefix + "uniq"
)

func textRecord(k, v string) string {
	return k + "=" + v
}

func PublicKeys2TXTRecords(pubKeys []ssh.PublicKey) (result []string) {
	register := func(k, v string) { result = append(result, textRecord(k, v)) }
	bi, ok := debug.ReadBuildInfo()
	if ok {
		main := bi.Main
		register(keyMainPath, main.Path)
	}
	for _, pk := range pubKeys {
		register(keySsh, ssh.FingerprintSHA256(pk))
	}
	return
}

// HostKeys keys announced in zeroconf as fingerprints
func HostKeys(svc *zeroconf.ServiceEntry) []string {
	return parseTextRecord(svc.Text)
}

func parseTextRecord(txt []string) []string {
	pubKeys := make([]string, 0)
	for _, s := range txt {
		bits := strings.SplitN(s, "=", 2)
		if len(bits) != 2 {
			continue
		}
		k, v := bits[0], bits[1]
		switch k {
		case keySsh:
			pubKeys = append(pubKeys, v)
		}
	}
	return pubKeys
}
