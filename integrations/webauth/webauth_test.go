package webauth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/integrations/webauth"
)

func TestBrowserCallback(t *testing.T) {
	const origin = "https://login.example.test"
	const callback = "https://app.example.test/sign-in"
	var first string
	mode, opened := "", 0
	handler, err := webauth.New(origin, callback, time.Second, func(ctx context.Context, u, state string) (string, error) {
		opened++
		if first == "" {
			first = state
		}
		switch mode {
		case "replay":
			state = first
		case "wrong-path":
			return callback + "/other?state=" + state, nil
		case "ambiguous":
			return callback + "?state=" + state + "&state=" + state, nil
		case "denied":
			return callback + "?error=access_denied&state=" + state, nil
		}
		return callback + "?state=" + state, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := handler(t.Context(), origin+"/saml"); err != nil || opened != 1 {
		t.Fatalf("mock authentication failed: %v", err)
	}
	for _, invalid := range []string{"replay", "wrong-path", "ambiguous", "denied"} {
		mode = invalid
		if err := handler(t.Context(), origin+"/saml"); !errors.Is(err, webauth.ErrWebAuth) {
			t.Fatalf("%s result = %v", invalid, err)
		}
	}
	if err := handler(t.Context(), origin+".invalid/saml"); !errors.Is(err, webauth.ErrWebAuth) || opened != 5 {
		t.Fatalf("untrusted origin reached browser: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := handler(ctx, origin+"/saml"); !errors.Is(err, context.Canceled) || opened != 5 {
		t.Fatalf("canceled flow reached browser: %v", err)
	}
}

func TestEquivalentHTTPSAuthorities(t *testing.T) {
	for _, tt := range []struct {
		origin, address, callback string
	}{
		{"https://login.example.test", "https://LOGIN.example.test:443/start", "https://app.example.test:443/sign-in"},
		{"https://login.example.test:443", "https://login.example.test/start", "https://app.example.test/sign-in"},
		{"https://[2001:db8::1]:443", "https://[2001:db8::1]/start", "https://app.example.test/sign-in"},
		{"https://login.example.test:8443", "https://login.example.test:8443/start", "https://app.example.test/sign-in"},
	} {
		opened := 0
		handler, err := webauth.New(tt.origin, tt.callback, time.Second, func(_ context.Context, _, state string) (string, error) {
			opened++
			return "https://app.example.test/sign-in?state=" + state, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := handler(t.Context(), tt.address); err != nil {
			t.Fatalf("equivalent authority rejected: %v", err)
		}
		for _, input := range []string{"https://login.example.test:444/start", "https://login.example.test:65536/start",
			"https://login.example.test:/start", "https://other.example.test/start", "http://login.example.test/start"} {
			if err := handler(t.Context(), input); !errors.Is(err, webauth.ErrWebAuth) {
				t.Fatal("invalid login origin accepted")
			}
		}
		if opened != 1 {
			t.Fatal("invalid authority reached the browser")
		}
	}
}
