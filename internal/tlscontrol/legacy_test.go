package tlscontrol

import (
	"github.com/hamedsanaei/openvpn-go/internal/crypt"
	"testing"
)

func TestExplicitDataV1Push(t *testing.T) {
	for _, tc := range []struct {
		name, push    string
		fixed, v1, ok bool
	}{
		{"legacy", "PUSH_REPLY,ping 3", true, true, true},
		{"modern-reject", "PUSH_REPLY,ping 3", false, false, false},
		{"v2-reject", "PUSH_REPLY,ping 3", true, false, false},
		{"v1-peer-id", "PUSH_REPLY,peer-id 1", true, true, false},
		{"v1-exporter", "PUSH_REPLY,key-derivation tls-ekm", true, true, false},
		{"v1-conflicting-cipher", "PUSH_REPLY,cipher AES-128-GCM", true, true, false},
		{"v1-without-fixed", "PUSH_REPLY,ping 3", false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := pushState{allowed: []string{crypt.AES256GCM}, fixedDataV1: tc.v1}
			if tc.fixed {
				p.fixedAEAD = crypt.AES256GCM
			}
			done, err := p.add([]byte(tc.push))
			if (err == nil && done) != tc.ok {
				t.Fatalf("done=%v err=%v", done, err)
			}
			if tc.ok && (!p.DataV1 || p.Derivation != crypt.ClassicKM2 || p.Cipher != crypt.AES256GCM) {
				t.Fatal("incorrect negotiation")
			}
		})
	}
}
