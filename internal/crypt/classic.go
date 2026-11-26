package crypt

import (
	"crypto/fips140"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"hash"
)

// ClassicMaterial is short-lived key-method-2 entropy from verified TLS.
type ClassicMaterial struct {
	Premaster                    [48]byte
	ClientRandom1, ClientRandom2 [32]byte
	ServerRandom1, ServerRandom2 [32]byte
}

func (m *ClassicMaterial) Clear() { *m = ClassicMaterial{} }

// ClassicDataKeys runs the legacy OpenVPN derivation only for explicitly
// selected AES-GCM endpoints. It is independent of the negotiated TLS version.
func ClassicDataKeys(name string, m *ClassicMaterial, clientID, serverID [8]byte) (DataKeys, error) {
	if m == nil || clientID == ([8]byte{}) || serverID == ([8]byte{}) ||
		fips140.Enabled() || (name != AES128GCM && name != AES256GCM) {
		return DataKeys{}, ErrDataKeys
	}
	var keys [ExporterSize]byte
	defer clear(keys[:])
	classicKeyBlock(keys[:], m, clientID, serverID)
	return fromMaterial(name, keys[:])
}

func classicKeyBlock(out []byte, m *ClassicMaterial, clientID, serverID [8]byte) {
	var secret [48]byte
	defer clear(secret[:])
	masterSeed := make([]byte, 0, len("OpenVPN master secret")+64)
	masterSeed = append(masterSeed, "OpenVPN master secret"...)
	masterSeed = append(masterSeed, m.ClientRandom1[:]...)
	masterSeed = append(masterSeed, m.ServerRandom1[:]...)
	tls10PRF(secret[:], m.Premaster[:], masterSeed)
	clear(masterSeed)

	keySeed := make([]byte, 0, len("OpenVPN key expansion")+80)
	keySeed = append(keySeed, "OpenVPN key expansion"...)
	keySeed = append(keySeed, m.ClientRandom2[:]...)
	keySeed = append(keySeed, m.ServerRandom2[:]...)
	keySeed = append(keySeed, clientID[:]...)
	keySeed = append(keySeed, serverID[:]...)
	tls10PRF(out, secret[:], keySeed)
	clear(keySeed)
}

// RFC 2246 section 5 splits the secret into overlapping halves for odd
// lengths and combines the two P_hash streams with XOR.
func tls10PRF(out, secret, seed []byte) {
	clear(out)
	half := (len(secret) + 1) / 2
	xorPHash(out, md5.New, secret[:half], seed)
	xorPHash(out, sha1.New, secret[len(secret)-half:], seed)
}

func xorPHash(out []byte, digest func() hash.Hash, secret, seed []byte) {
	mac := hmac.New(digest, secret)
	var a, buf [sha1.Size]byte
	defer clear(a[:])
	defer clear(buf[:])
	chain := seed
	for len(out) > 0 {
		mac.Reset()
		mac.Write(chain)
		chain = mac.Sum(a[:0])
		mac.Reset()
		mac.Write(chain)
		mac.Write(seed)
		block := mac.Sum(buf[:0])
		n := min(len(out), len(block))
		for i := range n {
			out[i] ^= block[i]
		}
		out = out[n:]
	}
}
