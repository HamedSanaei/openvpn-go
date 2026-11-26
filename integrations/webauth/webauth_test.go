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
