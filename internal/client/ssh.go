package client

import (
	"fmt"

	"golang.org/x/crypto/ssh"
)

const (
	channelName = "weyoun"
)

func ChannelName() string { return channelName }

type Client struct {
	channel ssh.Channel
}

func NewClient(sshClient *ssh.Client) (*Client, error) {
	channel, requests, err := sshClient.OpenChannel(ChannelName(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create channel: %w", err)
	}

	go func(in <-chan *ssh.Request) {
		for _ = range in {
		}
	}(requests)

	return &Client{
		channel: channel,
	}, nil
}

func (c *Client) Close() error {
	defer c.channel.Close()
	return nil
}
