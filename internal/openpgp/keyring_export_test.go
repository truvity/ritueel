package openpgp

import "time"

// The names below are visible to the tests of the package that stand outside it. They open nothing
// of the code under test: the shared check of a certification is called with the bytes of a key
// packet, the way the reader of the keyring file calls it.

// RaceEnabled tells whether the tests are built with the race detector.
const RaceEnabled = raceEnabled

// The bounds of the reader that the tests pin.
const (
	MaxCertificationBody = maxCertificationBody
	MaxBindingSubpackets = maxBindingSubpackets
	MaxKeyringPackets    = maxKeyringPackets
	MaxUserIDBytes       = maxUserID
)

// CheckCertificationBytes runs the one shared check of a self-certification: pkt is one whole
// signature packet, keyPacket one whole Public-Key packet, and notBefore the time that the
// certification may not precede. It returns the creation time and the key expiration time that
// the certification holds.
func CheckCertificationBytes(pkt, keyPacket []byte, userID string, notBefore time.Time) (created time.Time, life uint32, err error) {
	k, err := readKey(keyPacket, tagPublicKey)
	if err != nil {
		return time.Time{}, 0, err
	}
	c, err := checkCertification(pkt, k, userID, notBefore)
	return c.created, c.life, err
}
