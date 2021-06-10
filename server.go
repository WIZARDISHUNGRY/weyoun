package weyoun

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/google/uuid"
	"github.com/grandcat/zeroconf"
	"golang.org/x/crypto/ssh"
	"jonwillia.ms/weyoun/internal/hostkey"
	"jonwillia.ms/weyoun/internal/server"
	"jonwillia.ms/weyoun/pkg/handlers"
)

type Server struct {
	serviceName    string
	runOnce        sync.Once
	serviceEntries <-chan *zeroconf.ServiceEntry
	handlers       handlers.Handlers
	id             string
}

func NewServer(serviceName string,
	handlers handlers.Handlers,
) *Server {
	u, _ := uuid.NewUUID()
	return &Server{
		serviceName: serviceName,
		handlers:    handlers,
		id:          u.String(),
	}
}

func (s *Server) Run(ctx context.Context,
) (err error) {
	publicKeyCallback, err := hostkey.GetAuthorizedKeysCallback()
	if err != nil {
		return fmt.Errorf("can't load authorized keys: %w", err)
	}
	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
		PublicKeyCallback: publicKeyCallback,
	}

	keys, err := hostkey.Signers()
	if err != nil {
		return fmt.Errorf("can't load host keys: %w", err)
	}
	pubKeys := make([]ssh.PublicKey, 0, 0)
	for _, key := range keys {
		config.AddHostKey(key)
		pubKeys = append(pubKeys, key.PublicKey())
	}

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	lc := net.ListenConfig{}
	listener, err := lc.Listen(ctx, "tcp", "")
	if err != nil {
		return fmt.Errorf("failed to listen for connection: %w", err)
	}
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	if err := Register(ctx, s.id, s.serviceName, listener.Addr().(*net.TCPAddr), RegisterText(pubKeys)); err != nil {
		return fmt.Errorf("unable to register bonjour service: %w", err)

	}

	sImpl := server.New(
		listener.Accept,
		func() (*ssh.ServerConfig, error) {
			return config, nil
		},
		s.handlers,
	)
	go sImpl.Start(ctx)
	return nil
}