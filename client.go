package weyoun

import (
	"context"
	"fmt"
	"sync"

	"github.com/grandcat/zeroconf"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
	"jonwillia.ms/weyoun/internal/hostkey"
)

type Client struct {
	serviceName                 string
	runOnce                     sync.Once
	serviceEntries              <-chan *zeroconf.ServiceEntry
	clientHandler, closeHandler func(context.Context, *ssh.Client)
	instanceBlacklist           []string
}

func NewClient(serviceName string,
	clientHandler,
	closeHandler func(context.Context, *ssh.Client),
	instanceBlacklist []string,
) *Client {
	return &Client{
		serviceName:       serviceName,
		clientHandler:     clientHandler,
		closeHandler:      closeHandler,
		instanceBlacklist: instanceBlacklist,
	}
}

func (c *Client) Run(ctx context.Context,
) (err error) {
	var ok bool
	c.runOnce.Do(func() { ok = true })
	if !ok {
		return fmt.Errorf("already Run()")
	}
	c.serviceEntries, err = Locator(ctx, c.serviceName, c.instanceBlacklist)
	if err != nil {
		return err
	}

	go c.eventLoop(ctx)
	return nil
}

func (c *Client) ListPublic() ([]ssh.PublicKey, error) {
	return hostkey.ListPublic()
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
					log.Warn().Err(err).Str("instance", svc.Instance).
						Msg("Failed to dial")
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
