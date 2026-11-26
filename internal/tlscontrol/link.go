package tlscontrol

import (
	"bytes"
	"context"

	"github.com/hamedsanaei/openvpn-go/internal/crypt"
)

// DataKeys hands per-generation keys to the authenticated data session.
func (l *Link) DataKeys() (crypt.DataKeys, error) {
	if l.Info.Derivation == crypt.ClassicKM2 {
		keys := l.classicKeys
		l.classicKeys = crypt.DataKeys{}
		if keys.Send.AEAD == nil || keys.Receive.AEAD == nil {
			return crypt.DataKeys{}, crypt.ErrDataKeys
		}
		return keys, nil
	}
	state := l.conn.ConnectionState()
	return crypt.ExportDataKeys(state.ExportKeyingMaterial, l.Info.Cipher)
}

// ReadUntilClosed monitors authenticated control commands, including token
// refreshes and a peer rejection of the credentials presented during rekey.
func (l *Link) ReadUntilClosed() error {
	var commands commandReader
	defer func() { clear(commands.partial) }()
	for {
		message, err := commands.read(l.reader)
		if err != nil {
			return streamError(l.stream, err)
		}
		command, options, _ := bytes.Cut(message, []byte{','})
		switch string(command) {
		case "INFO", "INFO_PRE", "ECHO":
		case "PUSH_REPLY":
			err = l.auth.update(options)
		default:
			err = unexpectedCommand(message)
		}
		clear(message)
		if err != nil {
			return err
		}
	}
}

func (l *Link) Close() { l.stream.Close() }

// NotifyExit sends an authenticated exit and waits for reliable delivery.
func (l *Link) NotifyExit(ctx context.Context) error {
	deadline, _ := ctx.Deadline()
	if err := l.conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	if _, err := l.conn.Write([]byte("EXIT\x00")); err != nil {
		return err
	}
	return l.stream.Drain(ctx)
}
