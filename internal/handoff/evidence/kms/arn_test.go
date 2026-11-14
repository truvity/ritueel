package kms_test

import (
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/handoff/evidence/kms"
)

const (
	uuid = "11111111-2222-3333-4444-555555555555"
	mrk  = "mrk-0123456789abcdef0123456789abcdef"
)

func TestParseKeyARN(t *testing.T) {
	good := []struct {
		name, text string
		want       kms.KeyARN
	}{
		{"the example of the page", "arn:aws:kms:eu-west-1:123456789012:key/" + uuid,
			kms.KeyARN{Partition: "aws", Region: "eu-west-1", Account: "123456789012", ID: uuid}},
		{"a multi-Region key", "arn:aws:kms:us-east-1:123456789012:key/" + mrk,
			kms.KeyARN{Partition: "aws", Region: "us-east-1", Account: "123456789012", ID: mrk}},
		{"the China partition", "arn:aws-cn:kms:cn-north-1:123456789012:key/" + uuid,
			kms.KeyARN{Partition: "aws-cn", Region: "cn-north-1", Account: "123456789012", ID: uuid}},
		{"the GovCloud partition", "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/" + uuid,
			kms.KeyARN{Partition: "aws-us-gov", Region: "us-gov-west-1", Account: "123456789012", ID: uuid}},
		{"a Region of one letter", "arn:aws:kms:a:123456789012:key/" + uuid,
			kms.KeyARN{Partition: "aws", Region: "a", Account: "123456789012", ID: uuid}},
		{"a Region of 32 characters", "arn:aws:kms:" + strings.Repeat("a", 32) + ":123456789012:key/" + uuid,
			kms.KeyARN{Partition: "aws", Region: strings.Repeat("a", 32), Account: "123456789012", ID: uuid}},
		{"a partition of 32 characters", "arn:aws" + strings.Repeat("-", 29) + ":kms:eu-west-1:123456789012:key/" + uuid,
			kms.KeyARN{Partition: "aws" + strings.Repeat("-", 29), Region: "eu-west-1", Account: "123456789012", ID: uuid}},
		{"every hexadecimal digit", "arn:aws:kms:eu-west-1:123456789012:key/01234567-89ab-cdef-0123-456789abcdef",
			kms.KeyARN{Partition: "aws", Region: "eu-west-1", Account: "123456789012", ID: "01234567-89ab-cdef-0123-456789abcdef"}},
		{"a Region with a digit", "arn:aws:kms:ap-southeast-2:123456789012:key/" + uuid,
			kms.KeyARN{Partition: "aws", Region: "ap-southeast-2", Account: "123456789012", ID: uuid}},
	}
	for _, tc := range good {
		t.Run(tc.name, func(t *testing.T) {
			got, err := kms.ParseKeyARN(tc.text)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
			if got.String() != tc.text {
				t.Fatalf("String() is %q, want %q", got.String(), tc.text)
			}
		})
	}

	bad := map[string]string{
		"the empty text":                        "",
		"an alias ARN":                          "arn:aws:kms:eu-west-1:123456789012:alias/example",
		"a bare key id":                         uuid,
		"a bare multi-Region key id":            mrk,
		"an alias":                              "alias/example",
		"upper case in the partition":           "arn:AWS:kms:eu-west-1:123456789012:key/" + uuid,
		"upper case in arn":                     "ARN:aws:kms:eu-west-1:123456789012:key/" + uuid,
		"upper case in the service":             "arn:aws:KMS:eu-west-1:123456789012:key/" + uuid,
		"upper case in the Region":              "arn:aws:kms:eu-West-1:123456789012:key/" + uuid,
		"upper case in key":                     "arn:aws:kms:eu-west-1:123456789012:Key/" + uuid,
		"upper case in the key id":              "arn:aws:kms:eu-west-1:123456789012:key/11111111-2222-3333-4444-55555555555A",
		"upper case in a multi-Region key id":   "arn:aws:kms:eu-west-1:123456789012:key/mrk-0123456789ABCDEF0123456789abcdef",
		"11 digits":                             "arn:aws:kms:eu-west-1:12345678901:key/" + uuid,
		"13 digits":                             "arn:aws:kms:eu-west-1:1234567890123:key/" + uuid,
		"a letter in the account":               "arn:aws:kms:eu-west-1:12345678901a:key/" + uuid,
		"no account":                            "arn:aws:kms:eu-west-1::key/" + uuid,
		"no Region":                             "arn:aws:kms::123456789012:key/" + uuid,
		"a Region that starts with a digit":     "arn:aws:kms:1eu-west-1:123456789012:key/" + uuid,
		"a Region that starts with a hyphen":    "arn:aws:kms:-eu-west-1:123456789012:key/" + uuid,
		"a Region of 33 characters":             "arn:aws:kms:" + strings.Repeat("a", 33) + ":123456789012:key/" + uuid,
		"a Region with a space":                 "arn:aws:kms:eu west-1:123456789012:key/" + uuid,
		"a Region with an underscore":           "arn:aws:kms:eu_west-1:123456789012:key/" + uuid,
		"a partition that is not aws":           "arn:azure:kms:eu-west-1:123456789012:key/" + uuid,
		"a partition that starts with letters":  "arn:xaws:kms:eu-west-1:123456789012:key/" + uuid,
		"a partition with a digit":              "arn:aws2:kms:eu-west-1:123456789012:key/" + uuid,
		"a partition of 33 characters":          "arn:aws" + strings.Repeat("-", 30) + ":kms:eu-west-1:123456789012:key/" + uuid,
		"the service is not kms":                "arn:aws:s3:eu-west-1:123456789012:key/" + uuid,
		"a UUID that is too short":              "arn:aws:kms:eu-west-1:123456789012:key/1111111-2222-3333-4444-abcdefabcdef",
		"a UUID that is too long":               "arn:aws:kms:eu-west-1:123456789012:key/111111111-2222-3333-4444-555555555555",
		"a UUID with the last group too short":  "arn:aws:kms:eu-west-1:123456789012:key/11111111-2222-3333-4444-55555555555",
		"a UUID with the last group too long":   "arn:aws:kms:eu-west-1:123456789012:key/11111111-2222-3333-4444-5555555555555",
		"a UUID with four groups":               "arn:aws:kms:eu-west-1:123456789012:key/11111111-2222-3333-4444",
		"a UUID with six groups":                "arn:aws:kms:eu-west-1:123456789012:key/11111111-2222-3333-4444-555555555555-1",
		"a UUID without hyphens":                "arn:aws:kms:eu-west-1:123456789012:key/11111111222233334444555555555555",
		"a UUID with a letter beyond f":         "arn:aws:kms:eu-west-1:123456789012:key/1111111g-2222-3333-4444-abcdefabcdef",
		"a multi-Region id that is too short":   "arn:aws:kms:eu-west-1:123456789012:key/mrk-0123456789abcdef0123456789abcde",
		"a multi-Region id that is too long":    "arn:aws:kms:eu-west-1:123456789012:key/mrk-0123456789abcdef0123456789abcdef0",
		"a multi-Region id with a letter":       "arn:aws:kms:eu-west-1:123456789012:key/mrk-0123456789abcdef0123456789abcdeg",
		"a multi-Region id with no mrk":         "arn:aws:kms:eu-west-1:123456789012:key/0123456789abcdef0123456789abcdef",
		"no key id":                             "arn:aws:kms:eu-west-1:123456789012:key/",
		"a trailing newline":                    "arn:aws:kms:eu-west-1:123456789012:key/" + uuid + "\n",
		"a leading space":                       " arn:aws:kms:eu-west-1:123456789012:key/" + uuid,
		"a trailing space":                      "arn:aws:kms:eu-west-1:123456789012:key/" + uuid + " ",
		"a trailing slash":                      "arn:aws:kms:eu-west-1:123456789012:key/" + uuid + "/",
		"trailing text":                         "arn:aws:kms:eu-west-1:123456789012:key/" + uuid + "x",
		"a seventh part":                        "arn:aws:kms:eu-west-1:123456789012:key/" + uuid + ":x",
		"five parts only":                       "arn:aws:kms:eu-west-1:123456789012",
		"a NUL":                                 "arn:aws:kms:eu-west-1:123456789012:key/" + uuid[:8] + "\x00" + uuid[9:],
		"a non-ASCII digit in the account":      "arn:aws:kms:eu-west-1:12345678901\xd9\xa3:key/" + uuid,
		"a non-ASCII character in the Region":   "arn:aws:kms:eu-w\xc3\xa9st-1:123456789012:key/" + uuid,
		"a character that is not UTF-8":         "arn:aws:kms:eu-west-1:123456789012:key/" + uuid[:8] + "\xff" + uuid[9:],
		"a text over MaxTextLength":             "arn:aws:kms:eu-west-1:123456789012:key/" + strings.Repeat("a", kms.MaxTextLength),
		"a long text of the right form":         "arn:aws" + strings.Repeat("a", 2100) + ":kms:eu-west-1:123456789012:key/" + uuid,
		"a role ARN":                            "arn:aws:iam::123456789012:role/example",
		"a double colon":                        "arn:aws:kms::eu-west-1:123456789012:key/" + uuid,
		"a key id with an upper-case multi tag": "arn:aws:kms:eu-west-1:123456789012:key/MRK-0123456789abcdef0123456789abcdef",
	}
	for name, text := range bad {
		t.Run("refuses "+name, func(t *testing.T) {
			got, err := kms.ParseKeyARN(text)
			if err == nil {
				t.Fatalf("accepted %q as %+v", text, got)
			}
			if got != (kms.KeyARN{}) {
				t.Fatalf("an error beside a value: %+v", got)
			}
			// The words are fixed: no byte of the input is repeated in the error.
			if len(text) > 8 && strings.Contains(err.Error(), text[len(text)/2:]) {
				t.Fatalf("the error repeats the input: %v", err)
			}
		})
	}
}

// A text of exactly MaxTextLength characters is read when it is of the form; the form is shorter than the
// limit, so the one way to reach the limit is a text that the form refuses, and the limit is the boundary of
// the refusal that this test fixes: 2048 bytes of a refused form and 2049 are both refused.
func TestParseKeyARNLongTexts(t *testing.T) {
	for _, n := range []int{kms.MaxTextLength - 1, kms.MaxTextLength, kms.MaxTextLength + 1, 1 << 20} {
		text := "arn:aws:kms:eu-west-1:123456789012:key/" + strings.Repeat("1", n)
		if _, err := kms.ParseKeyARN(text); err == nil {
			t.Fatalf("accepted a text of %d bytes", len(text))
		}
	}
}

func TestKeyARNStringWritesTheOneSpelling(t *testing.T) {
	a := kms.KeyARN{Partition: "aws", Region: "eu-west-1", Account: "123456789012", ID: uuid}
	want := "arn:aws:kms:eu-west-1:123456789012:key/" + uuid
	if a.String() != want {
		t.Fatalf("String() is %q, want %q", a.String(), want)
	}
	back, err := kms.ParseKeyARN(a.String())
	if err != nil || back != a {
		t.Fatalf("round trip: %+v, %v", back, err)
	}
}

func TestParseRoleARN(t *testing.T) {
	good := map[string]string{
		"arn:aws:iam::123456789012:role/example-key-holder":             "123456789012",
		"arn:aws:iam::123456789012:role/a":                              "123456789012",
		"arn:aws:iam::111122223333:role/path/to/example":                "111122223333",
		"arn:aws:iam::123456789012:role/A+=,.@_-b":                      "123456789012",
		"arn:aws-cn:iam::123456789012:role/example":                     "123456789012",
		"arn:aws-us-gov:iam::123456789012:role/example":                 "123456789012",
		"arn:aws:iam::123456789012:role/" + strings.Repeat("a", 512-31): "123456789012",
		"arn:aws:iam::123456789012:role/0123456789abcdefABCDEF/x.y@z_w": "123456789012",
	}
	for text, acct := range good {
		got, err := kms.ParseRoleARN(text)
		if err != nil {
			t.Errorf("refused %q: %v", text, err)
			continue
		}
		if got != acct {
			t.Errorf("%q: account %q, want %q", text, got, acct)
		}
	}
	long := "arn:aws:iam::123456789012:role/" + strings.Repeat("a", 512-30)
	if len(long) != 513 {
		t.Fatalf("test text is %d bytes", len(long))
	}
	bad := map[string]string{
		"the empty text":              "",
		"a user":                      "arn:aws:iam::123456789012:user/example",
		"the account root":            "arn:aws:iam::123456789012:root",
		"a key ARN":                   keyARN,
		"an assumed role":             "arn:aws:sts::123456789012:assumed-role/example/session",
		"a Region in an IAM ARN":      "arn:aws:iam:eu-west-1:123456789012:role/example",
		"11 digits":                   "arn:aws:iam::12345678901:role/example",
		"13 digits":                   "arn:aws:iam::1234567890123:role/example",
		"no account":                  "arn:aws:iam:::role/example",
		"no name":                     "arn:aws:iam::123456789012:role/",
		"a trailing slash":            "arn:aws:iam::123456789012:role/example/",
		"a double slash":              "arn:aws:iam::123456789012:role/a//b",
		"a leading slash":             "arn:aws:iam::123456789012:role//example",
		"a space in the name":         "arn:aws:iam::123456789012:role/exa mple",
		"a star in the name":          "arn:aws:iam::123456789012:role/exa*",
		"a question mark":             "arn:aws:iam::123456789012:role/exa?",
		"a colon in the name":         "arn:aws:iam::123456789012:role/exa:mple",
		"a non-ASCII name":            "arn:aws:iam::123456789012:role/exa\xc3\xa9",
		"a NUL in the name":           "arn:aws:iam::123456789012:role/exa\x00",
		"a newline in the name":       "arn:aws:iam::123456789012:role/example\n",
		"an upper-case partition":     "arn:AWS:iam::123456789012:role/example",
		"a partition that is not aws": "arn:gcp:iam::123456789012:role/example",
		"upper case Role":             "arn:aws:iam::123456789012:Role/example",
		"upper case service":          "arn:aws:IAM::123456789012:role/example",
		"513 characters":              long,
		"a long text":                 "arn:aws:iam::123456789012:role/" + strings.Repeat("a", kms.MaxTextLength),
	}
	for name, text := range bad {
		t.Run("refuses "+name, func(t *testing.T) {
			if acct, err := kms.ParseRoleARN(text); err == nil || acct != "" {
				t.Fatalf("accepted %q (account %q, error %v)", text, acct, err)
			}
		})
	}
}

// The role ARN of 512 characters is read, the one of 513 is not: the bound is the one the page of the
// delegation file gives a role.
func TestParseRoleARNLimit(t *testing.T) {
	prefix := "arn:aws:iam::123456789012:role/"
	if _, err := kms.ParseRoleARN(prefix + strings.Repeat("a", 512-len(prefix))); err != nil {
		t.Fatalf("a role ARN of 512 characters is refused: %v", err)
	}
	if _, err := kms.ParseRoleARN(prefix + strings.Repeat("a", 513-len(prefix))); err == nil {
		t.Fatal("a role ARN of 513 characters is accepted")
	}
}

func FuzzParseKeyARN(f *testing.F) {
	for _, s := range []string{
		"", keyARN, "arn:aws:kms:eu-west-1:123456789012:key/" + mrk, "arn:aws-cn:kms:cn-north-1:123456789012:key/" + uuid,
		"arn:aws:kms:eu-west-1:123456789012:alias/x", uuid, "arn:aws:kms:::::", "arn:aws:kms:eu-west-1:123456789012:key/\xff",
		"arn:aws:iam::123456789012:role/example",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		a, err := kms.ParseKeyARN(s)
		if err != nil {
			if a != (kms.KeyARN{}) {
				t.Fatalf("an error beside a value: %+v", a)
			}
			return
		}
		if a.String() != s {
			t.Fatalf("an accepted text does not round-trip: %q gives %q", s, a.String())
		}
		if len(s) > kms.MaxTextLength {
			t.Fatalf("accepted a text of %d bytes", len(s))
		}
		if !printable(s) {
			t.Fatalf("accepted a text with a character outside printable ASCII: %q", s)
		}
		b, err := kms.ParseKeyARN(a.String())
		if err != nil || b != a {
			t.Fatalf("second read: %+v, %v", b, err)
		}
	})
}

func FuzzParseRoleARN(f *testing.F) {
	for _, s := range []string{"", holder, readRole, "arn:aws:iam::123456789012:user/x", "arn:aws:iam::123456789012:role/a/b/c", "arn:aws:iam::123456789012:role/\xff"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		acct, err := kms.ParseRoleARN(s)
		if err != nil {
			if acct != "" {
				t.Fatalf("an error beside an account: %q", acct)
			}
			return
		}
		if len(acct) != 12 || len(s) > 512 || !printable(s) || !strings.Contains(s, ":iam::"+acct+":role/") {
			t.Fatalf("accepted %q with the account %q", s, acct)
		}
	})
}
