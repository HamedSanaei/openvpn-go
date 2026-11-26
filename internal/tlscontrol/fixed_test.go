package tlscontrol

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/hamedsanaei/openvpn-go/internal/crypt"
)

func TestConciseServerKeyMethodRequiresExplicitPolicy(t *testing.T) {
	const options = "V4,dev-type tun,cipher AES-256-GCM"
	header := make([]byte, 69)
	header[4], header[5], header[37] = 2, 1, 2
	frame := binary.BigEndian.AppendUint16(header, uint16(len(options)+1))
	frame = append(append(frame, options...), 0)
	if err := readKeyMethod(bufio.NewReader(bytes.NewReader(frame))); !errors.Is(err, io.EOF) {
		t.Fatalf("modern framing accepted missing metadata: %v", err)
	}
	next := []byte("PUSH_REPLY,peer-id 0\x00")
	reader := bufio.NewReader(bytes.NewReader(append(bytes.Clone(frame), next...)))
	var material crypt.ClassicMaterial
	if err := readPeerKeyMethod(t.Context(), reader, crypt.AES256GCM, &material); err != nil ||
		material.ServerRandom1[0] != 1 || material.ServerRandom2[0] != 2 {
		t.Fatalf("fixed-mode key exchange = %v", err)
	}
	if left, err := io.ReadAll(reader); err != nil || !bytes.Equal(left, next) {
		t.Fatal("concise key exchange consumed the following command")
	}
	for _, value := range []string{
		"V4", "V4,cipher AES-128-GCM", "V4,cipher AES-256-GCM,cipher AES-256-GCM",
		"V4,cipher AES-256-GCM, cipher AES-128-GCM", "V4,cipher AES-256-GCM,cipher\tAES-128-GCM",
	} {
		if matchFixedOptions([]byte(value), crypt.AES256GCM) {
			t.Fatal("ambiguous fixed cipher was accepted")
		}
	}
	empty := binary.BigEndian.AppendUint16(bytes.Clone(header), 0)
	if err := readPeerKeyMethod(t.Context(), bufio.NewReader(bytes.NewReader(empty)), crypt.AES256GCM, &material); !errors.Is(err, ErrNegotiation) {
		t.Fatalf("fixed-mode key exchange accepted an absent OCC field: %v", err)
	}
}

func TestFixedPushStillRequiresPeerIDAndRejectsContradictions(t *testing.T) {
	for _, row := range []struct {
		message string
		accept  bool
	}{
		{"PUSH_REPLY,peer-id 0", true},
		{"PUSH_REPLY,peer-id 0,cipher AES-256-GCM", true},
		{"PUSH_REPLY,cipher AES-256-GCM", false},
		{"PUSH_REPLY,peer-id 0,cipher AES-128-GCM", false},
		{"PUSH_REPLY,peer-id 0,key-derivation tls-ekm", false},
		{"PUSH_REPLY,peer-id 0,protocol-flags tls-ekm", false},
		{"PUSH_REPLY,peer-id 0,peer-id 1", false},
		{"PUSH_REPLY,peer-id 0,cipher AES-256-GCM,cipher AES-256-GCM", false},
		{"PUSH_REPLY,peer-id 16777215", false},
	} {
		fixed := pushState{allowed: []string{crypt.AES256GCM}, fixedAEAD: crypt.AES256GCM}
		complete, err := fixed.add([]byte(row.message))
		if row.accept {
			if err != nil || !complete || fixed.Derivation != crypt.ClassicKM2 || fixed.Cipher != crypt.AES256GCM {
				t.Fatalf("fixed push did not complete: %v", err)
			}
		} else if !errors.Is(err, ErrNegotiation) || complete {
			t.Fatalf("invalid fixed push accepted: %v", err)
		}
	}
	modern := pushState{allowed: []string{crypt.AES256GCM}}
	if complete, err := modern.add([]byte("PUSH_REPLY,peer-id 0")); complete || !errors.Is(err, ErrNegotiation) {
		t.Fatal("modern negotiation silently selected fixed AEAD")
	}
}
