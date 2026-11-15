package openpgp

import (
	"bytes"
	"time"
)

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

// ReadKeyringCounting reads a keyring file as ReadKeyring does, with no recover, through the same inner
// function, and returns the whole signature packets that the reader gave to the check of one
// certification, in the order it gave them. The check itself is the real one.
func ReadKeyringCounting(file []byte, want []KeyringEntry) (keys []*PrimaryKey, checked [][]byte, err error) {
	want = append([]KeyringEntry(nil), want...)
	if err := checkKeyringEntries(want); err != nil {
		return nil, nil, err
	}
	count := func(pkt []byte, k *key, userID string, notBefore time.Time) (certification, error) {
		checked = append(checked, bytes.Clone(pkt))
		return checkCertificationWork(pkt, k, userID, notBefore)
	}
	keys, err = readKeyring(file, want, count)
	return keys, checked, err
}

// ReadKeyringNoRecover reads a keyring file as ReadKeyring does, through the inner function that has no
// recover, so that a panic in the reader reaches the caller. A fault of want is returned as ReadKeyring
// returns it.
func ReadKeyringNoRecover(file []byte, want []KeyringEntry) ([]*PrimaryKey, error) {
	want = append([]KeyringEntry(nil), want...)
	if err := checkKeyringEntries(want); err != nil {
		return nil, err
	}
	return readKeyring(file, want, checkCertificationWork)
}

// ReadKeyringWithPanickingCheck reads a keyring file with no recover and with a check of one
// certification that panics when it is called. A panic that reaches the caller was raised by the check.
func ReadKeyringWithPanickingCheck(file []byte, want []KeyringEntry) ([]*PrimaryKey, error) {
	want = append([]KeyringEntry(nil), want...)
	if err := checkKeyringEntries(want); err != nil {
		return nil, err
	}
	return readKeyring(file, want, func([]byte, *key, string, time.Time) (certification, error) {
		panic("the check of a certification was called")
	})
}

// CheckCertificationBytesNoRecover is CheckCertificationBytes through the inner function of the shared
// check, which has no recover.
func CheckCertificationBytesNoRecover(pkt, keyPacket []byte, userID string, notBefore time.Time) (created time.Time, life uint32, err error) {
	k, err := readKey(keyPacket, tagPublicKey)
	if err != nil {
		return time.Time{}, 0, err
	}
	c, err := checkCertificationWork(pkt, k, userID, notBefore)
	return c.created, c.life, err
}
