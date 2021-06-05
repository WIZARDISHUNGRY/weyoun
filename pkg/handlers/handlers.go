package handlers

import (
	"context"

	"golang.org/x/crypto/ssh"
)

type Handlers struct {
	OpenDirect func(ctx context.Context, channel ssh.Channel, msg ChannelOpenDirectMsg) // direct-tcpip
	FreeForm   map[string]func(ctx context.Context, channel ssh.Channel, extra []byte)
}

// RFC 4254 7.2
type ChannelOpenDirectMsg struct {
	Raddr string
	Rport uint32
	Laddr string
	Lport uint32
}
