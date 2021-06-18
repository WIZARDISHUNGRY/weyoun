package weyoun

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
	"jonwillia.ms/weyoun/pkg/handlers"
)

func TestClient(t *testing.T) {
	const svcName = "something"
	const dialAddr = "127.0.0.1:9999"
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	serverOK2 := false
	go func() {
		http.ListenAndServe(dialAddr, http.HandlerFunc(
			func(rw http.ResponseWriter, r *http.Request) {
				serverOK2 = true
			},
		))
	}()

	serverOK := false
	server := NewServer(svcName, handlers.Handlers{OpenDirect: func(ctx context.Context, channel ssh.Channel, msg handlers.ChannelOpenDirectMsg) {
		serverOK = true
		conn, err := net.Dial("tcp", dialAddr)
		if err != nil {
			fmt.Println("dial error", err)
			return
		}
		defer conn.Close()
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			io.Copy(channel, conn)
		}()
		go func() {
			defer wg.Done()
			io.Copy(conn, channel)
		}()
		wg.Wait()
	}})

	ok := false
	client := NewClient(svcName, func(c context.Context, client *ssh.Client) {
		ok = true
		rt := &http.Transport{Dial: client.Dial}
		httpClient := http.Client{Transport: rt}
		resp, err := httpClient.Get("http://www.example.com/")
		fmt.Println("get", resp, err)
	}, func(_ context.Context, _ *ssh.Client) {}, nil)

	err := client.Run(ctx)
	if err != nil {
		t.Fatalf("client.Run %v", err)
	}
	err = server.Run(ctx)
	if err != nil {
		t.Fatalf("server.Run %v", err)
	}

	<-ctx.Done()
	if !ok {
		t.Fatalf("!ok")
	}
	if !serverOK {
		t.Fatalf("!serverOK")
	}
	if !serverOK2 {
		t.Fatalf("!serverOK2")
	}
}
