package weyoun

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/user"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
	"jonwillia.ms/weyoun/internal/hostkey"
	"jonwillia.ms/weyoun/internal/server"
	"jonwillia.ms/weyoun/pkg/handlers"
)

type Server struct {
	serviceName string
	handlers    handlers.Handlers
	id, name    string
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

func (s *Server) GetAuthorizedKeys() ([]ssh.PublicKey, error) {
	return hostkey.GetAuthorizedKeys()
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
	for _, key := range keys {
		// RSA keys are blacklisted because I can't figure out how to
		// disallow YubiKey keys from my gpg/ssh-agent
		if key.PublicKey().Type() == "ssh-rsa" {
			continue
		}
		config.AddHostKey(key)
	}
	if len(pubKeys) == 0 {
		return fmt.Errorf("no available ssh keys for server")
	}

	authKeys, err := hostkey.GetAuthorizedKeys()
	if err != nil {
		return fmt.Errorf("can't load authorized keys: %w", err)
	}
	if len(authKeys) == 0 {
		return fmt.Errorf("no available authorized keys for server")
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
