package canonjson

import "testing"

// A repeated member is reported at the member's own path by Canonicalize and IsCanonical, and by
// Marshal for a Raw (the path of the Raw goes on with the member).
func TestARepeatedMemberIsReportedAtItsOwnPath(t *testing.T) {
	a61 := string(rune(92)) + "u0061"
	cases := []struct{ name, doc, want string }{
		{"at the top", `{"a":1,"a":2}`, "malformed JSON: $.a: the member appears twice at byte 10"},
		{"the second with an escape", `{"a":1,"` + a61 + `":2}`, "malformed JSON: $.a: the member appears twice at byte 15"},
		{"nested", `{"o":{"a":1,"a":2}}`, "malformed JSON: $.o.a: the member appears twice at byte 15"},
		{"in an element of a list", `{"l":[{"x":1},{"a":1,"a":2}]}`, "malformed JSON: $.l[1].a: the member appears twice at byte 24"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Canonicalize([]byte(tc.doc))
			if err == nil || err.Error() != tc.want || got != nil {
				t.Errorf("Canonicalize = %q, %v; want %s", got, err, tc.want)
			}
			ok, err := IsCanonical([]byte(tc.doc))
			if err == nil || err.Error() != tc.want || ok {
				t.Errorf("IsCanonical = %v, %v; want %s", ok, err, tc.want)
			}
		})
	}
	t.Run("inside a Raw that is a field", func(t *testing.T) {
		type doc struct {
			R Raw `json:"r"`
		}
		got, err := Marshal(doc{R: Raw(`{"a":1,"a":2}`)})
		if want := "malformed JSON: $.r.a: the member appears twice at byte 10"; err == nil || err.Error() != want || got != nil {
			t.Errorf("%q, %v; want %s", got, err, want)
		}
		got, err = Marshal(Raw(`{"a":{"b":1,"b":2}}`))
		if want := "malformed JSON: $.a.b: the member appears twice at byte 15"; err == nil || err.Error() != want || got != nil {
			t.Errorf("a Raw at the top: %q, %v; want %s", got, err, want)
		}
	})
}
