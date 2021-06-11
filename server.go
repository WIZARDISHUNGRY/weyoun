package weyoun

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/user"
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
	id, name       string
}

func NewServer(serviceName string,
	handlers handlers.Handlers,
) *Server {
	u, _ := uuid.NewUUID()
	return &Server{
		serviceName: serviceName,
		handlers:    handlers,
		id:          u.String(),
		name:        getName(),
	}
}

func (s *Server) GetID() string {
	return s.id
}

func getName() string {
	user, err := user.Current()
	if err != nil {
		panic(err)
	}
	hostname, err := os.Hostname()
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%s@%s", user.Username, hostname)
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

	authKeys, err := hostkey.GetAuthorizedKeys()
	if err != nil {
		return fmt.Errorf("can't load authorized keys: %w", err)
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

	txtRecords := append(PublicKeys2TXTRecords(authKeys), textRecord(keyUniq, s.id))
	if err := Register(ctx, s.name, s.serviceName, listener.Addr().(*net.TCPAddr), txtRecords); err != nil {
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
