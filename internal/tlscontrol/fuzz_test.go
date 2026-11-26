package tlscontrol

import (
	"bytes"
	"testing"
)

func FuzzControlPush(f *testing.F) {
	const valid = "PUSH_REPLY,peer-id 5,key-derivation tls-ekm,cipher AES-256-GCM"
	for _, seed := range []string{
		"", valid, valid + ",compress lz4", valid + ",ping-exit 1", valid + ",ping-restart 2",
		"PUSH_REPLY,key-derivation tls-ekm,push-continuation 2\x00PUSH_REPLY,peer-id 5,cipher AES-256-GCM,push-continuation 1",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 2*maxCommand {
			return
		}
		p := pushState{allowed: []string{"AES-256-GCM"}}
		defer func() { clear(p.token) }()
		for message := range bytes.SplitSeq(input, []byte{0}) {
			complete, err := p.add(message)
			if err != nil {
				if complete {
					t.Fatal("failed push was marked complete")
				}
				return
			}
			if complete {
				if p.Cipher != "AES-256-GCM" || !p.exporter || !p.havePeer ||
					p.PeerID >= 0xffffff || p.parts > 16 || p.total > maxCommand {
					t.Fatal("completed push bypassed negotiation constraints")
				}
				return
			}
		}
	})
}
