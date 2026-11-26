package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/fips140"
	"encoding/hex"
	"testing"
)

// Generated independently with the OpenSSL TLS1-PRF KDF using the
// synthetic inputs from this test and the two published OpenVPN labels.
const classicVector = "079cd169033e6b666bc8939b340644fd889f83ba6ba431520ee44ab8b5563500" +
	"9de4dbf71f5a2d99dbfd8aaa380bf86ab6d14d361ea47df57e177b107e536680" +
	"aa80a72652cde4cfb1ac7debf1bc606dac051827217214b41dc7be4cabce99c7" +
	"45cad805c6f8feefa0f54201722fb1df0d75108e0a5041a5a8b1f3929aa33e55" +
	"49f5567d1dfee8187032779a886cd0f8918776fd1cbf4d7d05b781fd2029a87c" +
	"3f922b4055e0046c79af09b7e6bf6bfdc0c38feb6d0a8fd2acb266e1b7bd63b8" +
	"5a761ef55b4d7cc6cd7eb0ab6a3acc9f8e6c09e7f483cf0263bc174d52317e5c" +
	"0841aa1d0e3d52139be53bc4a21b20f70a1296dc32c889b78e113a56237a8c9d"

func TestClassicKM2OpenSSLVector(t *testing.T) {
	if fips140.Enabled() {
		t.Skip("legacy derivation is disabled in FIPS mode")
	}
	var m ClassicMaterial
	fill := func(dst []byte, base byte) {
		for i := range dst {
			dst[i] = base + byte(i)
		}
	}
	fill(m.Premaster[:], 0x00)
	fill(m.ClientRandom1[:], 0x40)
	fill(m.ClientRandom2[:], 0x60)
	fill(m.ServerRandom1[:], 0x80)
	fill(m.ServerRandom2[:], 0xa0)
	var local, peer [8]byte
	fill(local[:], 0xc0)
	fill(peer[:], 0xd0)
	want, err := hex.DecodeString(classicVector)
	if err != nil {
		t.Fatal(err)
	}
	var block [ExporterSize]byte
	classicKeyBlock(block[:], &m, local, peer)
	if !bytes.Equal(block[:], want) {
		t.Fatal("classic key expansion disagrees with OpenSSL")
	}
	classicKeyBlock(block[:], &m, peer, local)
	if bytes.Equal(block[:], want) {
		t.Fatal("key expansion ignored control session ID order")
	}
	for _, tc := range []struct {
		name string
		size int
	}{{AES128GCM, 16}, {AES256GCM, 32}} {
		keys, err := ClassicDataKeys(tc.name, &m, local, peer)
		if err != nil {
			t.Fatal(err)
		}
		for i, dir := range []Direction{keys.Send, keys.Receive} {
			offset := i * 128
			oracleBlock, err := aes.NewCipher(want[offset : offset+tc.size])
			if err != nil {
				t.Fatal(err)
			}
			oracle, err := cipher.NewGCM(oracleBlock)
			if err != nil {
				t.Fatal(err)
			}
			var nonce [12]byte
			copy(nonce[4:], want[offset+64:offset+72])
			actual := dir.AEAD.Seal(nil, nonce[:], []byte("synthetic data"), nil)
			if !bytes.Equal(actual, oracle.Seal(nil, nonce[:], []byte("synthetic data"), nil)) ||
				!bytes.Equal(dir.ImplicitIV[:], nonce[4:]) {
				t.Fatal("incorrect data key direction or implicit nonce")
			}
		}
	}
	m.Clear()
	if m != (ClassicMaterial{}) {
		t.Fatal("classic entropy was not cleared")
	}
}

func TestTLS10PRFOddSecret(t *testing.T) {
	if fips140.Enabled() {
		t.Skip("legacy derivation is disabled in FIPS mode")
	}
	out := make([]byte, 19)
	tls10PRF(out, []byte("odd"), []byte("seed"))
	if hex.EncodeToString(out) != "91ef764bcff4b63390e9f4d1f514aca2773898" {
		t.Fatal("odd-length secret split differs from OpenSSL")
	}
}
