package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"math"
	"slices"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	AES256GCM        = "AES-256-GCM"
	AES128GCM        = "AES-128-GCM"
	ChaCha20Poly1305 = "CHACHA20-POLY1305"
	ExporterLabel    = "EXPORTER-OpenVPN-datakeys"
	ExporterSize     = 256
)

var ErrDataKeys = errors.New("invalid OpenVPN data key material or cipher")

// DataCiphers validates and copies the AEAD offer. An empty offer selects
// the complete supported set.
func DataCiphers(allowed []string) ([]string, error) {
	supported := []string{AES256GCM, AES128GCM, ChaCha20Poly1305}
	if len(allowed) == 0 {
		return supported, nil
	}
	if len(allowed) > len(supported) {
		return nil, ErrDataKeys
	}
	for i, name := range allowed {
		if !slices.Contains(supported, name) || slices.Contains(allowed[:i], name) {
			return nil, ErrDataKeys
		}
	}
	return slices.Clone(allowed), nil
}

// Probe the same nonce-taking constructors used for the actual data channel.
// Go applies runtime cryptographic mode restrictions for the whole process.
var runtimeCiphers = sync.OnceValue(func() map[string]bool {
	names, _ := DataCiphers(nil)
	available := make(map[string]bool, len(names))
	var synthetic [128]byte
	for _, name := range names {
		_, err := direction(name, synthetic[:])
		available[name] = err == nil
	}
	return available
})

// RuntimeDataCiphers filters a validated default offer and rejects an explicit
// offer containing any cipher unavailable in this Go runtime. The caller
// owns the validated slice and must use the returned offer.
func RuntimeDataCiphers(offer []string, explicit bool) ([]string, error) {
	available := runtimeCiphers()
	if explicit {
		for _, name := range offer {
			if !available[name] {
				return nil, ErrDataKeys
			}
		}
	} else {
		offer = slices.DeleteFunc(offer, func(name string) bool { return !available[name] })
	}
	if len(offer) == 0 {
		return nil, ErrDataKeys
	}
	return offer, nil
}

type Direction struct {
	AEAD       cipher.AEAD
	ImplicitIV [8]byte
}

type DataKeys struct {
	Send, Receive Direction
	PacketLimit   uint32
}

type Derivation string

const (
	TLSExporter Derivation = "tls_exporter"
	ClassicKM2  Derivation = "classic_km2"
)

// ExportDataKeys derives the two directional AEAD keys and nonce suffixes
// from the verified control TLS connection's key material exporter.
func ExportDataKeys(export func(string, []byte, int) ([]byte, error), name string) (DataKeys, error) {
	material, err := export(ExporterLabel, nil, ExporterSize)
	defer clear(material)
	if err != nil || len(material) != ExporterSize {
		return DataKeys{}, ErrDataKeys
	}
	return fromMaterial(name, material)
}

func fromMaterial(name string, material []byte) (DataKeys, error) {
	tx, err := direction(name, material[:128])
	if err != nil {
		return DataKeys{}, err
	}
	rx, err := direction(name, material[128:])
	if err != nil {
		return DataKeys{}, err
	}
	limit := uint32(math.MaxUint32)
	if name != ChaCha20Poly1305 {
		limit = 1 << 24
	}
	return DataKeys{Send: tx, Receive: rx, PacketLimit: limit}, nil
}

func direction(name string, material []byte) (Direction, error) {
	var aead cipher.AEAD
	var err error
	switch name {
	case AES256GCM, AES128GCM:
		size := 32
		if name == AES128GCM {
			size = 16
		}
		block, blockErr := aes.NewCipher(material[:size])
		if blockErr != nil {
			return Direction{}, ErrDataKeys
		}
		aead, err = cipher.NewGCM(block)
	case ChaCha20Poly1305:
		aead, err = chacha20poly1305.New(material[:32])
	default:
		return Direction{}, ErrDataKeys
	}
	if err != nil {
		return Direction{}, ErrDataKeys
	}
	var iv [8]byte
	copy(iv[:], material[64:])
	return Direction{AEAD: aead, ImplicitIV: iv}, nil
}
