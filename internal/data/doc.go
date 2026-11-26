// Package data implements OpenVPN data-channel packet processing.
//
// It owns negotiated data packet formats, AEAD protection, packet IDs,
// replay checks and key-generation selection. It must not expose key material.
package data
