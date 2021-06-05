package weyoun

import (
	"context"
	"fmt"
	"sync"

	"github.com/grandcat/zeroconf"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
)

type Client struct {
	serviceName                 string
	runOnce                     sync.Once
	serviceEntries              <-chan *zeroconf.ServiceEntry
	clientHandler, closeHandler func(context.Context, *ssh.Client)
}

func NewClient(serviceName string,
	clientHandler,
	closeHandler func(context.Context, *ssh.Client),
) *Client {
	return &Client{
		serviceName:   serviceName,
		clientHandler: clientHandler,
		closeHandler:  closeHandler,
	}
}

func (c *Client) Run(ctx context.Context,
) (err error) {
	var ok bool
	c.runOnce.Do(func() { ok = true })
	if !ok {
		return fmt.Errorf("already Run()")
	}
	c.serviceEntries, err = Locator(ctx, c.serviceName)
	if err != nil {
		return err
	}

	go c.eventLoop(ctx)
	return nil
}

func (c *Client) eventLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case svc := <-c.serviceEntries: // TODO maintain service entry map
			dialers, err := Dialers(ctx, svc)
			if err != nil {
				log.Print("Failed to get dialers: ", err)
				continue
			}
			for _, dialer := range dialers {
				sshClient, err := dialer(ctx)
				if err != nil {
					log.Print("Failed to dial: ", err)
					continue
				}
				go c.clientHandler(ctx, sshClient)
				go func() {
					sshClient.Wait()
					c.closeHandler(ctx, sshClient)
				}()
				break // one service entry found
			}
		}
	}
}
