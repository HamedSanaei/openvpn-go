package tlscontrol

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"strings"

	"github.com/hamedsanaei/openvpn-go/internal/crypt"
)

const keyMethod = 2

func writeKeyMethod(w io.Writer, network, digest string, ciphers []string, user Credentials) error {
	// Key method 2 includes legacy entropy fields even when both peers
	// negotiate data-channel keying material via the TLS exporter.
	message := make([]byte, 5+48+32+32, 5+48+32+32+4*maxKeyString)
	defer func() { clear(message) }()
	message[4] = keyMethod
	if _, err := rand.Read(message[5:]); err != nil {
		return ErrNegotiation
	}

	proto := "UDPv4"
	if strings.HasPrefix(network, "tcp") {
		proto = "TCPv4_CLIENT"
	}
	if strings.HasSuffix(network, "6") {
		proto = strings.Replace(proto, "v4", "v6", 1)
	}
	if digest == "" {
		digest = "SHA1"
	}
	keySize := "256"
	if ciphers[0] == crypt.AES128GCM {
		keySize = "128"
	}
	options := "V4,dev-type tun,link-mtu 1555,tun-mtu 1500,proto " + proto +
		",cipher " + ciphers[0] + ",auth " + digest + ",keysize " + keySize + ",key-method 2,tls-client"

	// Bit 1 advertises DATA_V2. Bit 3 selects the TLS exporter when both
	// peers support it. Address floating and dynamic wrapping are omitted.
	peer := "IV_PROTO=10\nIV_CIPHERS=" + strings.Join(ciphers, ":") + "\n"
	for _, field := range []string{options, user.Username, user.Password, peer} {
		if field == "" {
			message = binary.BigEndian.AppendUint16(message, 0)
		} else {
			message = binary.BigEndian.AppendUint16(message, uint16(len(field)+1))
			message = append(message, field...)
			message = append(message, 0)
		}
	}
	n, err := w.Write(message)
	if err == nil && n != len(message) {
		return io.ErrShortWrite
	}
	return err
}

func readKeyMethod(r *bufio.Reader) error {
	first, err := r.Peek(1)
	if err != nil {
		return err
	}
	if first[0] != 0 {
		var commands commandReader
		msg, err := commands.read(r)
		if err != nil {
			return err
		}
		defer clear(msg)
		return unexpectedCommand(msg)
	}

	var header [5 + 64]byte
	defer clear(header[:])
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	if !bytes.Equal(header[:5], []byte{0, 0, 0, 0, keyMethod}) {
		return ErrNegotiation
	}
	var field [maxKeyString]byte
	defer clear(field[:])
	for i := range 4 {
		var length [2]byte
		if _, err := io.ReadFull(r, length[:]); err != nil {
			return err
		}
		n := int(binary.BigEndian.Uint16(length[:]))
		if n > len(field) || (i == 0 && n < 2) {
			return ErrNegotiation
		}
		if n == 0 {
			continue
		}
		if _, err := io.ReadFull(r, field[:n]); err != nil {
			return err
		}
		if field[n-1] != 0 || bytes.IndexByte(field[:n-1], 0) != -1 {
			return ErrNegotiation
		}
	}
	return nil
}

const maxCommand = 16 * 1024

type commandReader struct{ partial []byte }

func (c *commandReader) read(r *bufio.Reader) ([]byte, error) {
	for {
		fragment, err := r.ReadSlice(0)
		if len(fragment) > maxCommand+1-len(c.partial) {
			return nil, ErrNegotiation
		}
		c.partial = append(c.partial, fragment...)
		switch {
		case err == nil:
			message := c.partial[:len(c.partial)-1]
			c.partial = nil
			return message, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			return nil, err
		}
	}
}

func unexpectedCommand(message []byte) error {
	command, detail, _ := bytes.Cut(message, []byte{','})
	switch string(command) {
	case "AUTH_FAILED", "AUTH_PENDING":
		return ErrAuth
	case "HALT", "EXIT":
		return ErrPeerStopped
	case "RESTART":
		if len(detail) == 0 || detail[0] != '[' {
			return ErrPeerRestart
		}
		flags, _, ok := bytes.Cut(detail[1:], []byte{']'})
		if !ok {
			return ErrNegotiation
		}
		for _, flag := range flags {
			switch flag {
			case 'P':
				// A purge needs new credentials from the embedding application.
				return ErrAuth
			case 'N':
			default:
				return ErrNegotiation
			}
		}
		if bytes.ContainsRune(flags, 'N') {
			return ErrPeerRestartSame
		}
		return ErrPeerRestart
	default:
		return ErrNegotiation
	}
}
