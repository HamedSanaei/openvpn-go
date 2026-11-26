package tlscontrol

import (
	"bytes"

	"github.com/hamedsanaei/openvpn-go/internal/crypt"
)

// DataKeys exports per-generation keys from this verified control TLS session.
func (l *Link) DataKeys() (crypt.DataKeys, error) {
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
			return err
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
