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
	"testing/synctest"
	"time"
)

func TestWebAuthRejectsMalformedURLsBeforeCallback(t *testing.T) {
	for _, bad := range []string{
		"https://login.example.test:/flow", "https://login.example.test:0/flow",
		"https://login.example.test:99999/flow", "https://login.example.test/flow#",
		"https://login.example.test/flow\\unsafe", "https://user@login.example.test/flow",
		"https://2001:db8::1/flow", "https://[login.example.test]/flow",
	} {
		p := pendingAuth{ctx: t.Context(), Interaction: Interaction{
			WebAuth: func(context.Context, string) error { t.Error("malformed URL reached callback"); return nil },
		}}
		if handled, _, err := p.handle(t.Context(), []byte("INFO_PRE,WEB_AUTH:external:"+bad)); !handled || err != ErrAuth || p.webUsed {
			t.Fatalf("invalid WEB_AUTH URL %q: %v", bad, err)
		}
	}
	for _, good := range []string{
		"https://login.example.test/login%2Fstep?state=a", "https://192.0.2.1:08443/login",
		"https://[2001:db8::1]:443/login", "https://login.example.test/login%23data",
	} {
		calls := 0
		p := pendingAuth{ctx: t.Context(), Interaction: Interaction{
			WebAuth: func(_ context.Context, value string) error {
				calls++
				if value != good {
					t.Fatalf("browser received unexpected URL %q", value)
				}
				return nil
			},
		}}
		if _, _, err := p.handle(t.Context(), []byte("INFO_PRE,WEB_AUTH:external:"+good)); err != nil || calls != 1 {
			t.Fatalf("valid WEB_AUTH URL %q: %v", good, err)
		}
		if _, _, err := p.handle(t.Context(), []byte("INFO_PRE,WEB_AUTH:external:"+good)); err != ErrAuth || calls != 1 {
			t.Fatalf("accepted a repeated browser interaction: %v", err)
		}
	}
}

func TestPendingAuthenticationExchange(t *testing.T) {
	for _, scenario := range []string{"roundtrip", "optional-empty", "web", "denied", "canceled", "callback-canceled", "unsolicited", "deadline", "callback-error"} {
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
				case "optional-empty":
					verdict = "INFO,testing\x00AUTH_PENDING,timeout 2\x00INFO_PRE,CR_TEXT:E:One-time code\x00"
				case "web":
					verdict = "AUTH_PENDING,timeout 2\x00INFO_PRE,WEB_AUTH:external:https://login.example.test/saml?opaque=secret\x00"
				default:
					verdict = "AUTH_PENDING,timeout 2\x00INFO_PRE,CR_TEXT:E,R:One-time code\x00"
				}
				if _, err := io.WriteString(peer, verdict); err != nil || scenario != "roundtrip" && scenario != "optional-empty" && scenario != "web" {
					peerDone <- err
					return
				}
				if scenario == "roundtrip" || scenario == "optional-empty" {
					answer, err := r.ReadString(0)
					want := "CR_RESPONSE,MTIzNDU2\x00"
					if scenario == "optional-empty" {
						want = "CR_RESPONSE,\x00"
					}
					if err != nil || answer != want {
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
				if challenge.Prompt != "One-time code" || !challenge.Echo || challenge.Required != (scenario != "optional-empty") {
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
				if scenario == "optional-empty" {
					return "", nil
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
			case "roundtrip", "optional-empty", "web":
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

func TestPassivePendingBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		owner, stopOwner := context.WithTimeout(t.Context(), 2*time.Second)
		defer stopOwner()
		setup, stopSetup := context.WithTimeout(owner, 100*time.Millisecond)
		defer stopSetup()
		setup, extended := WithPendingParent(setup, owner)
		local, peer := net.Pipe()
		defer local.Close()
		defer peer.Close()
		pendingSeen := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			if _, err := bufio.NewReader(peer).ReadString(0); err != nil {
				done <- err
				return
			}
			if _, err := io.WriteString(peer, "AUTH_PENDING,timeout 3\x00"); err != nil {
				done <- err
				return
			}
			<-pendingSeen
			time.Sleep(200 * time.Millisecond)
			_, err := io.WriteString(peer, "PUSH_REPLY,peer-id 7,key-derivation tls-ekm,cipher AES-256-GCM\x00")
			done <- err
		}()
		push := pushState{allowed: []string{"AES-256-GCM"}}
		pending := pendingAuth{Interaction: Interaction{AllowPassivePending: true, PendingTimeout: time.Second}}
		defer pending.close()
		if err := readPushWithPending(setup, local, bufio.NewReader(local), &push, &pending,
			func(context.Context) error { close(pendingSeen); return nil }); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if !extended() || setup.Err() != context.DeadlineExceeded || push.PeerID != 7 {
			t.Fatal("passive authentication did not extend the setup budget")
		}
	})
}

func TestInitialTokenUsernameIsOnlyMetadata(t *testing.T) {
	auth := NewAuthentication(Credentials{Username: "original", Password: "password"})
	defer auth.Clear()
	auth.set(nil, "token-name")
	before, err := auth.forHandshake(t.Context(), nil)
	if err != nil || before.Username != "original" || before.Password != "password" {
		t.Fatal("token metadata changed ordinary credentials")
	}
	if err := auth.update([]byte("auth-token-user c29tZS1uYW1l")); !errors.Is(err, ErrNegotiation) {
		t.Fatal("a username-only refresh was accepted")
	}
	if err := auth.update([]byte("auth-token synthetic-token")); err != nil {
		t.Fatal(err)
	}
	after, err := auth.forHandshake(t.Context(), nil)
	if err != nil || after.Username != "token-name" || after.Password != "synthetic-token" {
		t.Fatal("the authenticated token did not inherit the initial metadata")
	}
}
