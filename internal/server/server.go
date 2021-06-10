package server

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/semaphore"
	"jonwillia.ms/weyoun/pkg/handlers"
)

func New(
	accept func() (net.Conn, error),
	config func() (*ssh.ServerConfig, error),
	handlers handlers.Handlers,
) *Server {

	const (
		unauthMultiplier = 5
	)
	var (
		maxUnauthWorkers = runtime.GOMAXPROCS(0) * unauthMultiplier
		sem              = semaphore.NewWeighted(int64(maxUnauthWorkers))
	)

	return &Server{
		accept:   accept,
		config:   config,
		handlers: handlers,
		sem:      sem,
	}
}

type Server struct {
	accept   func() (net.Conn, error)
	config   func() (*ssh.ServerConfig, error)
	handlers handlers.Handlers

	sem *semaphore.Weighted
}

func (s *Server) Start(ctx context.Context) {

	for {
		if err := s.sem.Acquire(ctx, 1); err != nil {
			log.Fatal().Err(err).Msg("Failed to acquire semaphore")
		}

		nConn, err := s.accept()
		if err != nil {
			log.Error().Err(err).Msg("failed to accept incoming connection")
			return
		}

		go func() {
			defer s.sem.Release(1)

			config, err := s.config()
			if err != nil {
				log.Error().Err(err).Msg("failed to get server config")
				time.Sleep(time.Second)
				return
			}
			// Before use, a handshake must be performed on the incoming
			// net.Conn.
			conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
			if err != nil {
				log.Error().Err(err).Msg("failed to handshake")

				return
			}
			ctx, cancel := context.WithCancel(ctx)
			go func() {
				conn.Wait()
				cancel()
			}()
			u := conn.User()
			log.Info().Str("user", u).Str("key", conn.Permissions.Extensions["pubkey-fp"]).Str("type", conn.Permissions.Extensions["pubkey-type"]).Msg("logged in")
			go s.handleConn(ctx, conn, chans, reqs)
		}()
	}
}

func (s *Server) handleConn(ctx context.Context,
	conn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request,
) {
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	for newChannel := range chans {
		var cb func(ctx context.Context, channel ssh.Channel, extraData []byte)
		ct := newChannel.ChannelType()
		switch ct {
		case "session":
			go s.handleSessionChannel(ctx, newChannel)
			continue
		case "direct-tcpip":
			if s.handlers.OpenDirect != nil {
				cb = func(ctx context.Context, channel ssh.Channel, extraData []byte) {
					msg := handlers.ChannelOpenDirectMsg{}
					err := ssh.Unmarshal(extraData, &msg)
					if err != nil {
						log.Error().Err(err).Str("ChannelType", ct).Msg("failed to Unmarshal")
						return
					}
					s.handlers.OpenDirect(ctx, channel, msg)
				}
			}
		default:
			handler, ok := s.handlers.FreeForm[ct]
			if ok {
				cb = handler
			}
		}
		if cb != nil {
			channel, reqs, err := newChannel.Accept()
			if err != nil {
				log.Error().Err(err).Str("ChannelType", ct).Msg("failed newChannel.Accept")
				continue
			}
			go ssh.DiscardRequests(reqs)
			go func() {
				defer channel.Close()
				cb(ctx, channel, newChannel.ExtraData())
			}()
		} else {
			newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type %v", newChannel.ChannelType()))
		}
	}
}

func (s *Server) handleSessionChannel(ctx context.Context, newChannel ssh.NewChannel) {
	channel, reqs, err := newChannel.Accept()
	if err != nil {
		log.Error().Err(err).Msg("handleSessionChannel failed to newChannel.Accept")
	}
	defer channel.Close()

	go func(in <-chan *ssh.Request) {
		for req := range in {
			req.Reply(req.Type == "shell", nil)
		}
	}(reqs)

	channel.Write([]byte("no interactive access sorry\n"))

}
