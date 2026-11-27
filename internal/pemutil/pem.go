package pemutil

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"unicode"
)

// Next decodes the first PEM block without skipping invalid input.
func Next(raw []byte) (*pem.Block, []byte) {
	const begin = "-----BEGIN "
	content := bytes.TrimLeftFunc(raw, unicode.IsSpace)
	offset := len(raw) - len(content)
	if offset != 0 && raw[offset-1] != '\n' {
		return nil, nil
	}
	raw = content
	if !bytes.HasPrefix(raw, []byte(begin)) {
		return nil, nil
	}
	block, rest := pem.Decode(raw)
	if block == nil {
		return nil, nil
	}
	if len(block.Headers) != 0 || bytes.Count(raw[:len(raw)-len(rest)], []byte(begin)) != 1 {
		clear(block.Bytes)
		return nil, nil
	}
	return block, rest
}

// Certificates accepts only a nonempty, complete certificate bundle.
func Certificates(raw []byte) ([]*x509.Certificate, bool) {
	raw = bytes.TrimRightFunc(raw, unicode.IsSpace)
	var chain []*x509.Certificate
	for len(raw) != 0 {
		block, next := Next(raw)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, false
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, false
		}
		chain = append(chain, cert)
		raw = next
	}
	return chain, len(chain) != 0
}

// PrivateKey checks the framing of one supported unencrypted private key.
func PrivateKey(raw []byte) bool {
	block, rest := Next(raw)
	if block == nil {
		return false
	}
	defer clear(block.Bytes)
	switch block.Type {
	case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
		return len(bytes.TrimSpace(rest)) == 0
	default:
		return false
	}
}

// EnvelopeCount validates complete PEM framing without decoding its base64.
// The caller must decode the exact number of envelopes and validate their DER.
func EnvelopeCount(raw []byte, key bool) (int, bool) {
	const begin = "-----BEGIN "
	const end = "-----END "
	const dashes = "-----"
	raw = bytes.TrimRightFunc(raw, unicode.IsSpace)
	var count int
	for len(raw) != 0 {
		content := bytes.TrimLeftFunc(raw, unicode.IsSpace)
		offset := len(raw) - len(content)
		if offset != 0 && raw[offset-1] != '\n' {
			return 0, false
		}
		line, rest, _ := bytes.Cut(content, []byte{'\n'})
		line = bytes.TrimRight(line, " \t\r")
		if !bytes.HasPrefix(line, []byte(begin)) || !bytes.HasSuffix(line, []byte(dashes)) ||
			len(line) <= len(begin)+len(dashes) {
			return 0, false
		}
		name := line[len(begin) : len(line)-len(dashes)]
		if key {
			if !bytes.Equal(name, []byte("PRIVATE KEY")) && !bytes.Equal(name, []byte("RSA PRIVATE KEY")) &&
				!bytes.Equal(name, []byte("EC PRIVATE KEY")) {
				return 0, false
			}
		} else if !bytes.Equal(name, []byte("CERTIFICATE")) {
			return 0, false
		}

		foundEnd := false
		for len(rest) != 0 {
			line, rest, _ = bytes.Cut(rest, []byte{'\n'})
			line = bytes.TrimRight(line, " \t\r")
			if bytes.HasPrefix(line, []byte(end)) {
				provided, ok := bytes.CutSuffix(line[len(end):], []byte(dashes))
				foundEnd = ok && bytes.Equal(provided, name)
				break
			}
			// PEM headers and delimiters cannot be part of the base64 body.
			if bytes.IndexAny(line, ":-") >= 0 {
				return 0, false
			}
		}
		if !foundEnd {
			return 0, false
		}
		raw = rest
		count++
	}
	return count, count != 0
}
