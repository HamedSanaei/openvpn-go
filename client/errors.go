package client

import (
	"context"
	"errors"
	"net"
)

// ErrorCode classifies failures without exposing raw endpoint or peer input.
type ErrorCode string

const (
	CodeConfig         ErrorCode = "invalid configuration"
	CodeNetwork        ErrorCode = "network failure"
	CodeAuthentication ErrorCode = "authentication failure"
	CodeCertificate    ErrorCode = "certificate verification failure"
	CodeProtocol       ErrorCode = "protocol failure"
	CodeUnavailable    ErrorCode = "OpenVPN data channel unavailable"
	CodeNotConnected   ErrorCode = "client is not connected"
	CodeBusy           ErrorCode = "client operation already in progress"
	CodeClosed         ErrorCode = "client is closed"
	CodeCanceled       ErrorCode = "operation canceled"
	CodeTimeout        ErrorCode = "operation timed out"
	CodeTunnel         ErrorCode = "tunnel failure"
	CodePeerRestart    ErrorCode = "peer requested a restart"
	CodePeerStopped    ErrorCode = "peer stopped the session"
)

// Error is a redacted error returned by the client. Code supports programmatic
// classification via errors.As. Context and closed errors also support errors.Is.
type Error struct {
	Op    string
	Code  ErrorCode
	Field string
}

func (e *Error) Error() string {
	if e.Field != "" {
		return "openvpn: " + e.Op + ": " + string(e.Code) + " (" + e.Field + ")"
	}
	return "openvpn: " + e.Op + ": " + string(e.Code)
}

func (e *Error) Is(target error) bool {
	switch e.Code {
	case CodeClosed:
		return target == net.ErrClosed
	case CodeCanceled:
		return target == context.Canceled
	case CodeTimeout:
		return target == context.DeadlineExceeded
	default:
		return false
	}
}

func configError(field string) *Error {
	return &Error{Op: "configure", Code: CodeConfig, Field: field}
}

func errorCode(err error) ErrorCode {
	var failure *Error
	if errors.As(err, &failure) {
		return failure.Code
	}
	return contextCode(err, CodeNetwork)
}

func contextCode(err error, fallback ErrorCode) ErrorCode {
	switch {
	case errors.Is(err, context.Canceled):
		return CodeCanceled
	case errors.Is(err, context.DeadlineExceeded):
		return CodeTimeout
	default:
		return fallback
	}
}
