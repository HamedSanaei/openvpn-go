package tlscontrol

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestPendingAuthenticationExchange(t *testing.T) {
	for _, scenario := range []string{"roundtrip", "web", "denied", "canceled", "callback-canceled", "unsolicited", "deadline", "callback-error"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
			defer cancel()
			local, peer := net.Pipe()
			defer local.Close()
			defer peer.Close()
			peer.SetDeadline(time.Now().Add(4 * time.Second))
			peerDone := make(chan error, 1)
			go func() {
				r := bufio.NewReader(peer)
				request, err := r.ReadString(0)
				if err != nil || request != "PUSH_REQUEST\x00" {
					peerDone <- errors.New("unexpected request")
					return
				}
				var verdict string
				switch scenario {
				case "unsolicited":
					verdict = "INFO_PRE,CR_TEXT:R:One-time code\x00"
				case "denied":
					verdict = "AUTH_PENDING,timeout 2\x00AUTH_FAILED,synthetic-private-details\x00"
				case "deadline":
					verdict = "AUTH_PENDING,timeout 1\x00"
				case "web":
					verdict = "AUTH_PENDING,timeout 2\x00INFO_PRE,WEB_AUTH:external:https://login.example.test/saml?opaque=secret\x00"
				default:
					verdict = "AUTH_PENDING,timeout 2\x00INFO_PRE,CR_TEXT:E,R:One-time code\x00"
				}
				if _, err := io.WriteString(peer, verdict); err != nil || scenario != "roundtrip" && scenario != "web" {
					peerDone <- err
					return
				}
				if scenario == "roundtrip" {
					answer, err := r.ReadString(0)
					if err != nil || answer != "CR_RESPONSE,MTIzNDU2\x00" {
						peerDone <- errors.New("unexpected challenge response")
						return
					}
				}
				_, err = io.WriteString(peer, "PUSH_REPLY,peer-id 7,key-derivation tls-ekm,cipher AES-256-GCM,auth-token test-token\x00")
				peerDone <- err
			}()
			calls := 0
			push := pushState{allowed: []string{"AES-256-GCM"}}
			interaction := Interaction{Challenge: func(cb context.Context, challenge Challenge) (string, error) {
				calls++
				if challenge.Prompt != "One-time code" || !challenge.Echo || !challenge.Required {
					t.Errorf("unexpected challenge: %+v", challenge)
				}
				switch scenario {
				case "canceled":
					cancel()
					<-cb.Done()
				case "callback-error":
					return "", errors.New("synthetic-private-details")
				case "callback-canceled":
					return "", fmt.Errorf("synthetic-private-details: %w", context.Canceled)
				}
				return "123456", nil
			}}
			interaction.WebAuth = func(_ context.Context, address string) error {
				calls++
				if address != "https://login.example.test/saml?opaque=secret" {
					return errors.New("unexpected browser address")
				}
				return nil
			}
			err := readPushInteractive(ctx, local, bufio.NewReader(local), &push, interaction)
			want := ErrAuth
			switch scenario {
			case "roundtrip", "web":
				want = nil
				if calls != 1 || push.PeerID != 7 || string(push.token) != "test-token" {
					t.Fatal("challenge or authenticated push did not complete")
				}
			case "canceled", "callback-canceled":
				want = context.Canceled
			case "deadline":
				want = context.DeadlineExceeded
			}
			if !errors.Is(err, want) || err != nil && strings.Contains(err.Error(), "synthetic-private-details") {
				t.Fatalf("push result = %v, want %v", err, want)
			}
			if err := <-peerDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCredentialProviderTokenLifecycle(t *testing.T) {
	calls := 0
	provider := func(context.Context) (Credentials, error) {
		calls++
		return Credentials{Username: "test-user", Password: "fresh-password"}, nil
	}
	auth := NewAuthentication(Credentials{})
	initial, err := auth.forHandshake(t.Context(), provider)
	if err != nil || calls != 1 || initial.Password != "fresh-password" {
		t.Fatal("initial credential was not obtained")
	}
	if err := auth.update([]byte("auth-token refreshed-token")); err != nil {
		t.Fatal(err)
	}
	refresh, err := auth.forHandshake(t.Context(), provider)
	if err != nil || calls != 1 || refresh.Password != "refreshed-token" || refresh.Username != initial.Username {
		t.Fatal("session did not use the pushed token")
	}
	if err := unexpectedCommand([]byte("AUTH_FAILED,SESSION:synthetic-private-token")); err != ErrAuth {
		t.Fatal("session expiry was not a redacted terminal failure")
	}
	auth.Clear()
	next := NewAuthentication(Credentials{})
	fresh, err := next.forHandshake(t.Context(), provider)
	if err != nil || calls != 2 || fresh.Password != initial.Password {
		t.Fatal("fresh connection did not reacquire credentials")
	}
}
