package tlscontrol

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"sync"
)

func authCallbackError(ctx context.Context, err error) error {
	switch {
	case ctx.Err() != nil:
		return ctx.Err()
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case err != nil:
		return ErrAuth
	default:
		return nil
	}
}

// Authentication retains an optional replacement token for this link's
// authenticated rekeys. It is shared by successive control generations.
type Authentication struct {
	mu        sync.Mutex
	base      Credentials
	token     []byte
	tokenUser string
}

func NewAuthentication(base Credentials) *Authentication {
	return &Authentication{base: base}
}

func (a *Authentication) credentialsLocked() Credentials {
	cred := a.base
	if len(a.token) != 0 {
		cred.Password = string(a.token)
		if a.tokenUser != "" {
			cred.Username = a.tokenUser
		}
	}
	return cred
}

func (a *Authentication) forHandshake(ctx context.Context, provider func(context.Context) (Credentials, error)) (Credentials, error) {
	a.mu.Lock()
	if provider == nil || len(a.token) != 0 {
		cred := a.credentialsLocked()
		a.mu.Unlock()
		return cred, nil
	}
	a.mu.Unlock()
	cred, err := provider(ctx)
	if err := authCallbackError(ctx, err); err != nil {
		return Credentials{}, err
	}
	if cred.Validate() != nil {
		return Credentials{}, ErrAuth
	}
	// Remember only the username so a pushed token without token-user can
	// be used on a later generation.
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.token) != 0 {
		return a.credentialsLocked(), nil
	}
	a.base.Username = cred.Username
	return cred, nil
}

func (a *Authentication) set(token []byte, username string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if token != nil {
		clear(a.token)
		a.token = token
		a.base.Password = ""
	}
	if username != "" {
		a.tokenUser = username
	}
}

func (a *Authentication) Clear() {
	a.mu.Lock()
	defer a.mu.Unlock()
	clear(a.token)
	a.token = nil
	a.tokenUser = ""
	a.base = Credentials{}
}

func tokenUsername(arg []byte) (string, error) {
	if len(arg) > base64.StdEncoding.EncodedLen(maxKeyString) {
		return "", ErrNegotiation
	}
	user, err := base64.StdEncoding.DecodeString(string(arg))
	defer clear(user)
	if err != nil || len(user) == 0 || !validKeyString(string(user)) {
		return "", ErrNegotiation
	}
	return string(user), nil
}

// update accepts only a token refresh on a live control channel. Other
// options must have been negotiated in the initial PUSH_REPLY.
func (a *Authentication) update(options []byte) error {
	var token []byte
	var user string
	for field := range bytes.SplitSeq(options, []byte{','}) {
		name, value, _ := bytes.Cut(field, []byte{' '})
		switch string(name) {
		case "auth-token":
			if token != nil || len(value) == 0 || !validKeyString(string(value)) {
				return ErrNegotiation
			}
			token = value
		case "auth-token-user":
			if user != "" {
				return ErrNegotiation
			}
			var err error
			user, err = tokenUsername(value)
			if err != nil {
				return err
			}
		default:
			return ErrNegotiation
		}
	}
	if token == nil {
		return ErrNegotiation
	}
	a.set(bytes.Clone(token), user)
	return nil
}
