package trustset

import "strconv"

// SetName spells the folder name of a trust set: the number in plain decimal digits, a hyphen, and
// the first eight characters of a SHA-256 digest (64 lower-case hexadecimal digits). It is the
// spelling that internal/bundle reads ("^[1-9][0-9]*-[0-9a-f]{8}$"). This function takes the digest it
// is given and chooses none; the writers of this package, Draft.SetName and Set.Name, pass the
// SHA-256 of root-list.json, so the name of a set is its number and the first eight characters of
// that digest. The sequence is 1 to strictjson.MaxSafeInt. Every error wraps ErrParams.
func SetName(sequence int64, digest string) (string, error) {
	if err := checkSequence(sequence); err != nil {
		return "", err
	}
	if !isLowerHex(digest, 64) {
		return "", fail(ErrParams, "the digest is not 64 lower-case hexadecimal digits")
	}
	return strconv.FormatInt(sequence, 10) + "-" + digest[:8], nil
}
