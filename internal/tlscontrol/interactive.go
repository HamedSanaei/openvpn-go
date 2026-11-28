package tlscontrol

import (
	"bytes"
	"context"
	"encoding/base64"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/hamedsanaei/openvpn-go/internal/httpsurl"
)

// Challenge is a text prompt from the verified VPN peer.
type Challenge struct {
	Prompt   string
	Echo     bool
	Required bool
}

type Interaction struct {
	Credentials         func(context.Context) (Credentials, error)
	Challenge           func(context.Context, Challenge) (string, error)
	WebAuth             func(context.Context, string) error
	AllowPassivePending bool
	PendingTimeout      time.Duration
}

func (i Interaction) peerInfo() string {
	var methods []string
	if i.Challenge != nil {
		methods = append(methods, "crtext")
	}
	if i.WebAuth != nil {
		methods = append(methods, "webauth")
	}
	if len(methods) == 0 {
		return ""
	}
	return "IV_SSO=" + strings.Join(methods, ",") + "\n"
}

type pendingAuth struct {
	Interaction
	cancel     context.CancelFunc
	ctx        context.Context
	challenges int
	webUsed    bool
}

func (p *pendingAuth) close() {
	if p.cancel != nil {
		p.cancel()
	}
}

func (p *pendingAuth) handle(parent context.Context, message []byte) (bool, []byte, error) {
	command, detail, _ := bytes.Cut(message, []byte{','})
	switch string(command) {
	case "AUTH_PENDING":
		if p.ctx != nil || !p.AllowPassivePending && p.Challenge == nil && p.WebAuth == nil {
			return true, nil, ErrAuth
		}
		duration := MaxPendingTimeout
		if len(detail) != 0 {
			key, value, ok := strings.Cut(string(detail), " ")
			if !ok {
				key, value, ok = strings.Cut(string(detail), "=")
			}
			seconds, err := strconv.ParseUint(value, 10, 32)
			if !ok || key != "timeout" || err != nil || seconds == 0 {
				return true, nil, ErrAuth
			}
			duration = min(MaxPendingTimeout, time.Duration(seconds)*time.Second)
		}
		if err := parent.Err(); err != nil {
			return true, nil, err
		}
		if p.PendingTimeout > 0 {
			if timing, ok := parent.Value(pendingParentKey{}).(*pendingTiming); ok {
				timing.extended = true
				parent = timing.owner
				duration = min(duration, p.PendingTimeout)
			}
		}
		p.ctx, p.cancel = context.WithTimeout(parent, duration)
		return true, nil, nil
	case "INFO_PRE":
		method, rest, _ := bytes.Cut(detail, []byte{':'})
		flags, value, wellFormed := strings.Cut(string(rest), ":")
		switch string(method) {
		case "CR_TEXT", "WEB_AUTH":
			if p.ctx == nil || !wellFormed || len(value) > 1000 || !validKeyString(value) || value == "" ||
				strings.ContainsFunc(value, unicode.IsControl) {
				return true, nil, ErrAuth
			}
			if err := p.ctx.Err(); err != nil {
				return true, nil, err
			}
			if string(method) == "CR_TEXT" {
				reply, err := p.textChallenge(flags, value)
				return true, reply, err
			}
			return true, nil, p.webAuth(flags, value)
		case "NOTIFY":
			return p.ctx != nil, nil, nil
		}
	}
	return false, nil, nil
}

func (p *pendingAuth) textChallenge(flags, prompt string) ([]byte, error) {
	challenge := Challenge{Prompt: prompt}
	if p.Challenge == nil || p.challenges >= 4 {
		return nil, ErrAuth
	}
	if flags != "" {
		for flag := range strings.SplitSeq(flags, ",") {
			switch {
			case flag == "E" && !challenge.Echo:
				challenge.Echo = true
			case flag == "R" && !challenge.Required:
				challenge.Required = true
			default:
				return nil, ErrAuth
			}
		}
	}
	p.challenges++
	answer, err := p.Challenge(p.ctx, challenge)
	if err := authCallbackError(p.ctx, err); err != nil {
		return nil, err
	}
	if len(answer) > 750 || !validKeyString(answer) || challenge.Required && answer == "" {
		return nil, ErrAuth
	}
	reply := base64.StdEncoding.AppendEncode([]byte("CR_RESPONSE,"), []byte(answer))
	return append(reply, 0), nil
}

func (p *pendingAuth) webAuth(flags, address string) error {
	if p.WebAuth == nil || p.webUsed || flags != "" && flags != "external" ||
		httpsurl.Parse(address, 1000) == nil {
		return ErrAuth
	}
	p.webUsed = true
	return authCallbackError(p.ctx, p.WebAuth(p.ctx, address))
}

// MaxPendingTimeout bounds one verified deferred authentication decision.
const MaxPendingTimeout = 5 * time.Minute

type pendingParentKey struct{}

type pendingTiming struct {
	owner    context.Context
	extended bool
}

// WithPendingParent keeps the connection owner's deadline available if an
// authenticated AUTH_PENDING activates the optional interaction budget.
func WithPendingParent(setup, owner context.Context) (context.Context, func() bool) {
	timing := &pendingTiming{owner: owner}
	return context.WithValue(setup, pendingParentKey{}, timing), func() bool { return timing.extended }
}
