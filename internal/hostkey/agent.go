package hostkey

import (
	"fmt"
	"net"
	"os"
	"sync"

	"golang.org/x/crypto/ssh/agent"
)

var (
	agentOnce   sync.Once
	agentClient agent.ExtendedAgent
	agentErr    error
)

func LoadAgent() (agent.ExtendedAgent, error) {
	var conn net.Conn
	agentOnce.Do(func() {
		socket := os.Getenv("SSH_AUTH_SOCK")
		conn, agentErr = net.Dial("unix", socket)
		if agentErr != nil {
			agentErr = fmt.Errorf("Failed to open SSH_AUTH_SOCK: %w", agentErr)
			return
		}
		agentClient = agent.NewClient(conn)
	})
	if agentErr != nil {
		return nil, agentErr
	}

	return agentClient, nil
}
