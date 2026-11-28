// Package webauth validates the browser handoff for OpenVPN WEB_AUTH.
// The caller supplies its browser and callback listener.
package webauth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/httpsurl"
)

var ErrWebAuth = errors.New("OpenVPN web authentication failed")

// Browser opens the verified login URL and returns the callback URL received
// by the application. The application must bind state to this browser flow
// using a mechanism supported by its provider. Browser must honor ctx.
type Browser func(ctx context.Context, loginURL, state string) (callbackURL string, err error)

// New returns a handler for client.Authentication.WebAuth. Each request has
// fresh state and at most one in-flight browser interaction. The login origin
// and exact HTTPS callback location are explicitly configured by the caller.
func New(loginOrigin, callbackLocation string, timeout time.Duration, browser Browser) (func(context.Context, string) error, error) {
	origin, callback := secureURL(loginOrigin), secureURL(callbackLocation)
	if origin == nil || callback == nil || origin.Path != "" && origin.Path != "/" ||
		origin.RawQuery != "" || callback.RawQuery != "" || origin.ForceQuery || callback.ForceQuery ||
		callback.Path == "" || timeout <= 0 || timeout > 5*time.Minute || browser == nil {
		return nil, ErrWebAuth
	}
	var active atomic.Bool
	return func(ctx context.Context, address string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		login := secureURL(address)
		if login == nil || !sameOrigin(login, origin) || !active.CompareAndSwap(false, true) {
			return ErrWebAuth
		}
		defer active.Store(false)
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		var nonce [32]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return ErrWebAuth
		}
		state := base64.RawURLEncoding.EncodeToString(nonce[:])
		address, err := browser(ctx, address, state)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, context.Canceled) {
			return context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return context.DeadlineExceeded
		}
		result := secureURL(address)
		if err != nil || result == nil || !sameOrigin(result, callback) ||
			result.EscapedPath() != callback.EscapedPath() {
			return ErrWebAuth
		}
		fields, err := url.ParseQuery(result.RawQuery)
		states := fields["state"]
		if err != nil || fields.Has("error") || len(states) != 1 ||
			subtle.ConstantTimeCompare([]byte(states[0]), []byte(state)) != 1 {
			return ErrWebAuth
		}
		return nil
	}, nil
}

func secureURL(value string) *url.URL {
	return httpsurl.Parse(value, 4096)
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Hostname(), b.Hostname()) && httpsPort(a) == httpsPort(b)
}

func httpsPort(uri *url.URL) string {
	port := uri.Port()
	if port == "" {
		return "443"
	}
	return strings.TrimLeft(port, "0")
}
