package handoff_test

import (
	"fmt"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/handoff"
)

// The page, "Versioning": a receiver that does not know the version refuses the message with
// `version-unsupported` and reads nothing else in it. The table of the checks gives `malformed` to check 2
// and `version-unsupported` to check 1. So a file whose version cannot be read (it is not one JSON object,
// has no member handoff, has it twice, or not as an integer) is `malformed` and the check that fails is
// check 2, with check 1 not run; a JSON object with a version that is not known is `version-unsupported`
// at check 1, whatever else it holds.

func TestAFileWhoseVersionCannotBeReadFailsCheckTwoAndCheckOneIsNotRun(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	for name, proof := range map[string]string{
		"not an object":                       `[{"handoff":2}]`,
		"a string":                            `"handoff"`,
		"nothing":                             ``,
		"no member handoff":                   `{"type":"x509-intermediate","store":"software"}`,
		"the member twice, the same":          `{"handoff":2,"handoff":2}`,
		"the member twice, two versions":      `{"handoff":1,"handoff":2}`,
		"the member in another case":          `{"HANDOFF":1}`,
		"the member as a float":               `{"handoff":2.0}`,
		"the member as a string":              `{"handoff":"2"}`,
		"the member as null":                  `{"handoff":null}`,
		"the member as a boolean":             `{"handoff":true}`,
		"the member as a list":                `{"handoff":[2]}`,
		"the member out of the range":         `{"handoff":9007199254740992}`,
		"the member only inside a member":     `{"x":{"handoff":2}}`,
		"an object and then text":             `{"handoff":2} x`,
		"an object that is cut":               `{"handoff":2,"a":`,
		"an object with a trailing comma":     `{"handoff":2,}`,
		"a byte order mark before a good one": "\xef\xbb\xbf" + `{"handoff":1}`,
		"a NUL after the object":              "{\"handoff\":2}\x00",
	} {
		t.Run(name, func(t *testing.T) {
			v, err := newChecker(t).Check(t.Context(), withProofBytes(f, []byte(proof)))
			wantUnreadableVersion(t, v, err)
			if v.Checks[0].Status != handoff.StatusNotRun || v.Checks[1].Status != handoff.StatusFailed {
				t.Errorf("check 1 is %s and check 2 is %s", v.Checks[0].Status, v.Checks[1].Status)
			}
		})
	}
}

func TestAJSONObjectWithAVersionThatIsNotKnownIsVersionUnsupportedWhateverElseItHolds(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	deep := strings.Repeat("[", 9000) + strings.Repeat("]", 9000)
	for name, proof := range map[string]string{
		"nothing else":                           `{"handoff":2}`,
		"white space around it":                  " \n\t{ \"handoff\" : 2 }\r\n ",
		"the version last":                       `{"type":"x509-intermediate","handoff":2}`,
		"the version first and a null":           `{"handoff":2,"x":null}`,
		"a float elsewhere":                      `{"handoff":3,"x":1.5,"y":1e9}`,
		"a member twice elsewhere":               `{"handoff":2,"a":1,"a":2}`,
		"a member twice, with the version once":  `{"a":1,"handoff":2,"a":1}`,
		"a lone surrogate elsewhere":             `{"handoff":2,"x":"\ud800"}`,
		"a number out of the range elsewhere":    `{"handoff":2,"x":9007199254740993}`,
		"a member that the page does not define": `{"handoff":2,"zzz":{"a":[1,2,3]}}`,
		"a handoff inside another member":        `{"x":{"handoff":1},"handoff":2}`,
		"the members of a version 1 proof":       `{"handoff":2,"type":"x509-intermediate","request_sha256":"x","store":"nope"}`,
		"the members of another contract":        `{"handoff":2,"kind":"somethingelse","payload":[{"a":null}]}`,
		"nesting of 9000 levels":                 `{"handoff":2,"x":` + deep + `}`,
		"version zero and a wrong digest":        `{"handoff":0,"request_sha256":"nope"}`,
		"a negative version":                     `{"handoff":-7,"zzz":null}`,
		"the largest version":                    `{"handoff":9007199254740991,"a":1.5}`,
		"minus zero":                             `{"handoff":-0,"a":null}`,
	} {
		t.Run(name, func(t *testing.T) {
			v, err := newChecker(t).Check(t.Context(), withProofBytes(f, []byte(proof)))
			wantRefusal(t, v, err, handoff.CodeVersionUnsupported, 1)
			if got := statuses(v); got != "fnnnnnnnn" {
				t.Errorf("statuses %s", got)
			}
			if v.Detail == "" {
				t.Error("a refusal with no detail")
			}
		})
	}
}

func TestAVersionThatIsNotKnownIsRefusedWhateverTheOtherFilesHold(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	for name, mut := range map[string]func(r *handoff.Request){
		"no request file":       func(r *handoff.Request) { delete(r.Files, handoff.FileCSR) },
		"a request that is bad": func(r *handoff.Request) { r.Files[handoff.FileCSR] = []byte("junk") },
		"a request over the size limit": func(r *handoff.Request) {
			r.Files[handoff.FileCSR] = make([]byte, handoff.MaxFileSize+1)
		},
		"files of the other types": func(r *handoff.Request) {
			r.Files[handoff.FileSubkey], r.Files[handoff.FileSSHKey], r.Files[handoff.FileSSHSig] = []byte("x"), []byte("y"), []byte("z")
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := withProofBytes(f, []byte(`{"handoff":2}`))
			mut(r)
			v, err := newChecker(t).Check(t.Context(), r)
			wantRefusal(t, v, err, handoff.CodeVersionUnsupported, 1)
		})
	}
}

func TestTheVersionThatIsKnownPassesCheckOneWhateverCheckTwoFindsAfterIt(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	for name, proof := range map[string]string{
		"only the version":             `{"handoff":1}`,
		"the version and white space":  " {\n\"handoff\" : 1\n}\n",
		"the version and a bad member": `{"handoff":1,"zzz":1}`,
		"the version and a null":       `{"handoff":1,"type":null}`,
		"the version twice elsewhere":  `{"handoff":1,"a":1,"a":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			v, err := newChecker(t).Check(t.Context(), withProofBytes(f, []byte(proof)))
			wantRefusal(t, v, err, handoff.CodeMalformed, 2)
			if got := statuses(v); got != "pfnnnnnnn" {
				t.Errorf("statuses %s", got)
			}
		})
	}
}

func TestEveryVersionOfTheLoopIsDecidedByCheckOneAlone(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	for version := -3; version <= 5; version++ {
		proof := []byte(fmt.Sprintf(`{"handoff":%d,"zzz":null}`, version))
		v, err := newChecker(t).Check(t.Context(), withProofBytes(f, proof))
		if version == handoff.Version {
			wantRefusal(t, v, err, handoff.CodeMalformed, 2)
			continue
		}
		wantRefusal(t, v, err, handoff.CodeVersionUnsupported, 1)
	}
}
