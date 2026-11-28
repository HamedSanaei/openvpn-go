package tlscontrol

import (
	"bufio"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/testkit"
)

func TestAuthenticatedControlAuthorityAtRetirement(t *testing.T) {
	pki := testkit.NewPKI(t)
	serverKey, err := tls.X509KeyPair(pki.Server.Certificate, pki.Server.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, err := ClientConfig(pki.CA, pki.Client.Certificate, pki.Client.PrivateKey, false, false)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig.ServerName = testkit.TestServerName
	for _, tc := range []struct {
		name, command string
		want          error
	}{
		{"halt", "HALT,private detail", ErrPeerStopped},
		{"auth", "AUTH_FAILED,private detail", ErrAuth},
		{"restart", "RESTART,[N]private detail", ErrPeerRestartSame},
	} {
		for _, retired := range []bool{false, true} {
			name := tc.name + "/before"
			if retired {
				name = tc.name + "/after"
			}
			t.Run(name, func(t *testing.T) {
				local, remote := net.Pipe()
				defer local.Close()
				defer remote.Close()
				deadline := time.Now().Add(2 * time.Second)
				local.SetDeadline(deadline)
				remote.SetDeadline(deadline)
				client := tls.Client(local, clientConfig)
				peer := tls.Server(remote, &tls.Config{Certificates: []tls.Certificate{serverKey}})
				link := &Link{reader: bufio.NewReader(client)}
				if retired && link.RetireControl() != nil {
					t.Fatal("new link has a terminal decision")
				}
				peerResult := make(chan error, 1)
				go func() {
					_, err := peer.Write([]byte(tc.command + "\x00"))
					peerResult <- err
				}()
				want := tc.want
				if retired {
					want = nil
				}
				if got := link.ReadUntilClosed(); got != want {
					t.Fatalf("authenticated control read = %v, want %v", got, want)
				}
				if err := <-peerResult; err != nil {
					t.Fatal(err)
				}
				if got := link.RetireControl(); got != want {
					t.Fatalf("decision at promotion = %v, want %v", got, want)
				}
			})
		}
	}
}
