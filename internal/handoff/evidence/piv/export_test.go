package piv

import (
	"crypto/x509"

	"ritueel.id/ritueel/internal/handoff"
)

// The unexported readers of the extensions and of the subject, for the tests of package piv_test.

// DecodeFirmware is decodeFirmware.
func DecodeFirmware(v []byte) (string, error) { return decodeFirmware(v) }

// DecodeSerial is decodeSerial.
func DecodeSerial(v []byte) (string, error) { return decodeSerial(v) }

// DecodePolicy is decodePolicy.
func DecodePolicy(v []byte) (handoff.PINPolicy, string, error) { return decodePolicy(v) }

// DecodeFormFactor is decodeFormFactor.
func DecodeFormFactor(v []byte) (string, error) { return decodeFormFactor(v) }

// SlotOf is slotOf.
func SlotOf(c *x509.Certificate) (string, error) { return slotOf(c) }
