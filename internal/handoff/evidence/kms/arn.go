package kms

import (
	"errors"
	"strings"
)

// errKeyARN is the error of a text that is not the ARN of a KMS key.
var errKeyARN = errors.New("kms: not the ARN of a KMS key (arn:PARTITION:kms:REGION:ACCOUNT:key/ID)")

// maxRoleARN is the longest role ARN that ParseRoleARN reads.
const maxRoleARN = 512

// KeyARN is an ARN that names a KMS key: arn:PARTITION:kms:REGION:ACCOUNT:key/ID.
type KeyARN struct {
	// Partition is "aws", or "aws" and lower-case letters and hyphens ("aws-cn", "aws-us-gov").
	Partition string
	// Region is the Region of the key.
	Region string
	// Account is the 12 digits of the account that owns the key.
	Account string
	// ID is a UUID in lower-case hexadecimal, or "mrk-" and 32 lower-case hexadecimal digits.
	ID string
}

// ParseKeyARN reads exactly the form of the page's example (hand-off-contract.md, "aws-kms"): "arn:", a
// partition, ":kms:", a Region, ":", an account of 12 digits, ":key/" and a key ID. An alias ARN, a bare key
// ID, upper case, white space and trailing text are errors, as is a text longer than [MaxTextLength]. The
// grammar is this package's reading of one example and is proposed. The error is fixed words.
func ParseKeyARN(s string) (KeyARN, error) {
	if len(s) == 0 || len(s) > MaxTextLength {
		return KeyARN{}, errKeyARN
	}
	parts := strings.Split(s, ":")
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "kms" {
		return KeyARN{}, errKeyARN
	}
	id, ok := strings.CutPrefix(parts[5], "key/")
	if !ok || !validPartition(parts[1]) || !validRegion(parts[3]) || !digits(parts[4], 12) || !validKeyID(id) {
		return KeyARN{}, errKeyARN
	}
	return KeyARN{Partition: parts[1], Region: parts[3], Account: parts[4], ID: id}, nil
}

// String writes the one spelling that [ParseKeyARN] reads.
func (a KeyARN) String() string {
	return "arn:" + a.Partition + ":kms:" + a.Region + ":" + a.Account + ":key/" + a.ID
}

// ParseRoleARN reads the ARN of an IAM role, arn:aws*:iam::ACCOUNT:role/PATH-AND-NAME, and returns its
// account. The path and the name are of the characters IAM allows (letters, digits and + = , . @ _ -), with
// "/" between parts; the ARN is at most 512 characters. The error is fixed words.
func ParseRoleARN(s string) (account string, err error) {
	acct, kind, ok := parseIAMARN(s)
	if !ok || kind != "role" || len(s) > maxRoleARN {
		return "", errors.New("kms: not the ARN of an IAM role (arn:PARTITION:iam::ACCOUNT:role/NAME)")
	}
	return acct, nil
}

// parseIAMARN reads arn:PARTITION:iam::ACCOUNT:root, :role/PATH-AND-NAME or :user/PATH-AND-NAME and returns the
// account and "root", "role" or "user".
func parseIAMARN(s string) (account, kind string, ok bool) {
	if len(s) == 0 || len(s) > MaxTextLength {
		return "", "", false
	}
	parts := strings.Split(s, ":")
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "iam" || parts[3] != "" ||
		!validPartition(parts[1]) || !digits(parts[4], 12) {
		return "", "", false
	}
	res := parts[5]
	if res == "root" {
		return parts[4], "root", true
	}
	for _, k := range []string{"role", "user"} {
		if name, found := strings.CutPrefix(res, k+"/"); found {
			if !validIAMName(name) {
				return "", "", false
			}
			return parts[4], k, true
		}
	}
	return "", "", false
}

// validIAMName reports whether s is one or more parts of IAM's characters, separated by single slashes.
func validIAMName(s string) bool {
	if s == "" {
		return false
	}
	for _, part := range strings.Split(s, "/") {
		if part == "" {
			return false
		}
		for i := 0; i < len(part); i++ {
			c := part[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			case c == '+', c == '=', c == ',', c == '.', c == '@', c == '_', c == '-':
			default:
				return false
			}
		}
	}
	return true
}

// validPartition reports whether s is "aws" followed by lower-case letters and hyphens.
func validPartition(s string) bool {
	rest, ok := strings.CutPrefix(s, "aws")
	if !ok || len(s) > 32 {
		return false
	}
	for i := 0; i < len(rest); i++ {
		if c := rest[i]; (c < 'a' || c > 'z') && c != '-' {
			return false
		}
	}
	return true
}

// validRegion reports whether s is 1 to 32 characters of lower-case letters, digits and hyphens, starting
// with a letter.
func validRegion(s string) bool {
	if s == "" || len(s) > 32 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// digits reports whether s is exactly n ASCII digits.
func digits(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// lowerHex reports whether s is exactly n lower-case hexadecimal digits.
func lowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// validKeyID reports whether s is a UUID in lower-case hexadecimal (8-4-4-4-12) or "mrk-" and 32 lower-case
// hexadecimal digits.
func validKeyID(s string) bool {
	if rest, ok := strings.CutPrefix(s, "mrk-"); ok {
		return lowerHex(rest, 32)
	}
	p := strings.Split(s, "-")
	if len(p) != 5 {
		return false
	}
	for i, n := range []int{8, 4, 4, 4, 12} {
		if !lowerHex(p[i], n) {
			return false
		}
	}
	return true
}
