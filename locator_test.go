package weyoun

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/google/uuid"
	bonjour "github.com/grandcat/zeroconf"
)

const timeout = 2 * time.Second

func TestLocate(t *testing.T) {
	// t.SkipNow() //
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c, err := Locate(ctx, "_sleep-proxy._udp", nil, nil)
	if err != nil {
		t.Fatalf("Lookup %v", err)
	}
	svc := <-c
	log.Debug().Msgf("%v", svc)
}

func TestRegisterAndLocate(t *testing.T) {
	const (
		svcName = "whatever"
	)
	testCases := []struct {
		desc        string
		matchers    [][]string
		bonjourKeys []string
		locateFail  bool
	}{
		{
			desc:       "base case",
			locateFail: false,
		},
		{
			desc:        "no match",
			locateFail:  true,
			bonjourKeys: []string{"other=value"},
			matchers:    [][]string{{"no=value"}},
		},
		{
			desc:        "match alternate",
			locateFail:  false,
			bonjourKeys: []string{"other=value"},
			matchers: [][]string{
				{"no=value"},
				{},
			},
		},
		{
			desc:        "match multiple",
			locateFail:  false,
			bonjourKeys: []string{"some=value", "other=value", "third=value"},
			matchers: [][]string{
				{"some=value", "other=value"},
			},
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			listener, err := net.Listen("tcp", "")
			if err != nil {
				t.Fatalf("Listen %v", err)
			}
			defer listener.Close()

			id := func() string {
				i, _ := uuid.NewRandom()
				return i.String()
			}()

			err = Register(ctx, id, svcName, listener.Addr().(*net.TCPAddr), tC.bonjourKeys)
			if err != nil {
				t.Fatalf("Register %v", err)
			}

			c, err := Locate(ctx, svcName, tC.matchers, nil)
			if err != nil {
				t.Fatalf("Locate %v", err)
			}

			svc := <-c
			if tC.locateFail {
				if svc != nil {
					t.Fatalf("Locate needed failure")
				}
				return
			}

			if svc.HostName == "" {
				t.Fatal("no HostName")
			}

			addrStr := fmt.Sprintf("%s:%d", svc.HostName, svc.Port)

			go func() {
				conn, err := net.Dial("tcp", addrStr)
				if err != nil {
					t.Fatalf("Dial %v", err)
				}
				defer conn.Close()
			}()

			accepted := make(chan struct{})
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					t.Fatalf("Accept %v", err)
				}
				defer conn.Close()
				close(accepted)
			}()

			select {
			case <-ctx.Done():
				t.Fatalf("no Accept")
			case <-accepted:
			}
		})
	}
}

func TestParseKeys(t *testing.T) {
	svc := &bonjour.ServiceEntry{
		Text: []string{
			"weyoun-key=b9d.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ3UsqMQY7eMwWUjX8WAWuZZEDFSqXYouQFE2f4DVO7L",
			"weyoun-key=b9d.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIED6ebecRkhbv3Uw7eaTeb6MS1Vd27+FVeljdDXT9xHu",
			"weyoun-mainPath=jonwillia.ms/whatever",
		},
	}
	keys := HostKeys(svc)
	if len(keys) != 2 {
		t.Fatalf("len(keys) != 2: %d", len(keys))
	}
}
