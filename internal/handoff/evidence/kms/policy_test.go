package kms_test

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/evidence/kms"
	"ritueel.id/ritueel/internal/jsonset"
)

// principals reads the policy and fails the test on an error.
func principals(t testing.TB, policy string) []handoff.Principal {
	t.Helper()
	got, err := kms.SignPrincipals(policy)
	if err != nil {
		t.Fatalf("refused: %v\npolicy: %.300s", err, policy)
	}
	return got
}

// wantPolicyFault checks that the policy is refused with the fault policy and returns nothing.
func wantPolicyFault(t testing.TB, policy string) {
	t.Helper()
	got, err := kms.SignPrincipals(policy)
	if err == nil {
		t.Fatalf("accepted as %+v\npolicy: %.300s", got, policy)
	}
	var r *kms.Refusal
	if !errors.As(err, &r) || r.Fault != kms.FaultPolicy {
		t.Fatalf("error %v (%T), want a *kms.Refusal with the fault policy", err, err)
	}
	if got != nil {
		t.Fatalf("an error beside a list: %+v", got)
	}
	if !printable(err.Error()) {
		t.Fatalf("the error holds a character outside printable ASCII: %q", err.Error())
	}
}

func TestSignActionPatterns(t *testing.T) {
	matching := []string{
		"kms:Sign", "kms:sign", "KMS:SIGN", "Kms:SiGn", "kms:*", "*", "kms:Si*", "kms:S?gn", "kms:S*n*", "kms:S*", "kms:*Sign",
		"kms:Sig?", "?ms:Sign", "kms:Sign*", "*:Sign", "kms:??gn", "k*s*:*n", "**", "kms:Sig*n", "*sign", "*n", "k*", "?*", "*?",
		"kms:*i*g*n", "kms:*****", "kms:S??n", "????????", "*k*m*s*:*s*i*g*n*",
	}
	for _, pat := range matching {
		t.Run("allows "+pat, func(t *testing.T) {
			got := principals(t, policyOf(t, stmt(holder, pat)))
			if want := []handoff.Principal{{ARN: holder, Kind: handoff.PrincipalRole}}; !reflect.DeepEqual(got, want) {
				t.Fatalf("pattern %q: got %+v, want %+v", pat, got, want)
			}
		})
	}
	notMatching := []string{
		"kms:Sig", "kms:Signx", "kms:xSign", "kms:Describe*", "kms:Get*", "kms:List*", "kms:Verify", "kms:Sign ", " kms:Sign", "kms: Sign",
		"", "kms", "kms:", "s3:*", "sign", "kms:Si?n?", "kms:S?n", "kms:Sig??", "?kms:Sign", "kms:Sign?", "????????x", "???????",
		"kms:Signn", "kms:Sin", "kms:*x", "x*", "*x*", "kms:\xc4\xb1", "\xe2\x84\xaams:sign", "kms:\xc5\xbfign", "KMS:S\xc4\xb0GN", "kms:sign\u0000",
		"kms:Sign\n", "km*:*x", "kms:Sig*x", "kms:Sign**x", "kms*:Signx", "ec2:*", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion",
		"kms:Decrypt", "kms:Encrypt", "kms:Si", "arn:kms:Sign", "*kms:Sign:*",
	}
	for _, pat := range notMatching {
		t.Run("does not allow "+strings.ToValidUTF8(pat, "?"), func(t *testing.T) {
			got := principals(t, policyOf(t, stmt(holder, pat)))
			if len(got) != 0 {
				t.Fatalf("pattern %q: got %+v, want none", pat, got)
			}
		})
	}
}

func TestSignActionLists(t *testing.T) {
	t.Run("one match among others", func(t *testing.T) {
		got := principals(t, policyOf(t, stmt(holder, "kms:Describe*", "kms:Sign", "kms:Get*")))
		if len(got) != 1 {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("a match last", func(t *testing.T) {
		got := principals(t, policyOf(t, stmt(holder, "kms:Describe*", "kms:Get*", "kms:*")))
		if len(got) != 1 {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("no match", func(t *testing.T) {
		if got := principals(t, policyOf(t, stmt(holder, "kms:Describe*", "kms:Get*", "kms:List*"))); len(got) != 0 {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("a list of one", func(t *testing.T) {
		st := stmt(holder, "kms:Sign")
		st["Action"] = []string{"kms:Sign"}
		if got := principals(t, policyOf(t, st)); len(got) != 1 {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("a thousand patterns, the last matches", func(t *testing.T) {
		pats := make([]string, kms.MaxActions)
		for i := range pats {
			pats[i] = fmt.Sprintf("kms:Other%d", i)
		}
		pats[len(pats)-1] = "kms:Sign"
		if got := principals(t, policyOf(t, stmt(holder, pats...))); len(got) != 1 {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("a thousand patterns, none matches", func(t *testing.T) {
		pats := make([]string, kms.MaxActions)
		for i := range pats {
			pats[i] = fmt.Sprintf("kms:Other%d", i)
		}
		if got := principals(t, policyOf(t, stmt(holder, pats...))); len(got) != 0 {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("a thousand and one patterns", func(t *testing.T) {
		pats := make([]string, kms.MaxActions+1)
		for i := range pats {
			pats[i] = "kms:Describe*"
		}
		wantPolicyFault(t, policyOf(t, stmt(holder, pats...)))
	})
	t.Run("a pattern of 256 characters", func(t *testing.T) {
		pat := strings.Repeat("x", kms.MaxPatternLen)
		if got := principals(t, policyOf(t, stmt(holder, pat, "kms:Sign"))); len(got) != 1 {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("a pattern of 257 characters", func(t *testing.T) {
		wantPolicyFault(t, policyOf(t, stmt(holder, strings.Repeat("x", kms.MaxPatternLen+1), "kms:Sign")))
	})
	t.Run("a single action of 257 characters", func(t *testing.T) {
		wantPolicyFault(t, policyOf(t, stmt(holder, strings.Repeat("x", kms.MaxPatternLen+1))))
	})
	t.Run("a single action of 256 characters", func(t *testing.T) {
		if got := principals(t, policyOf(t, stmt(holder, strings.Repeat("*", kms.MaxPatternLen)))); len(got) != 1 {
			t.Fatalf("got %+v", got)
		}
	})
}

func TestADeepPatternOfStarsIsFast(t *testing.T) {
	// A pattern of many stars and an unlucky tail is the classic case of a matcher that takes exponential time.
	pat := strings.Repeat("*a", 120) + "*b"
	start := time.Now()
	for i := 0; i < 200; i++ {
		principals(t, policyOf(t, stmt(holder, pat)))
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("200 reads of a pattern of stars took %s", d)
	}
}

func TestEffectAndNotAction(t *testing.T) {
	deny := stmt(holder, "kms:Sign")
	deny["Effect"] = "Deny"
	t.Run("Deny with Sign is ignored", func(t *testing.T) {
		if got := principals(t, policyOf(t, deny)); len(got) != 0 {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("Deny beside an Allow only adds the Allow", func(t *testing.T) {
		other := stmt("arn:aws:iam::123456789012:role/example-other", "kms:Sign")
		other["Effect"] = "Deny"
		got := principals(t, policyOf(t, other, stmt(holder, "kms:Sign")))
		if want := []handoff.Principal{role("example-key-holder")}; !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})

	notAction := func(effect string, actions ...string) map[string]any {
		st := stmt(holder, actions...)
		st["Effect"] = effect
		st["NotAction"] = st["Action"]
		delete(st, "Action")
		return st
	}
	for _, tc := range []struct {
		name    string
		effect  string
		actions []string
		want    int
	}{
		{"NotAction that lists Sign", "Allow", []string{"kms:Sign"}, 0},
		{"NotAction that lists sign in lower case", "Allow", []string{"kms:sign"}, 0},
		{"NotAction that lists kms:*", "Allow", []string{"kms:*"}, 0},
		{"NotAction that lists a pattern for Sign", "Allow", []string{"kms:S?gn"}, 0},
		{"NotAction that lists everything", "Allow", []string{"*"}, 0},
		{"NotAction that lists Sign among others", "Allow", []string{"kms:Describe*", "kms:Sign"}, 0},
		{"NotAction that does not list Sign", "Allow", []string{"kms:Describe*"}, 1},
		{"NotAction of another service", "Allow", []string{"s3:*"}, 1},
		{"NotAction of near misses", "Allow", []string{"kms:Sig", "kms:Signx"}, 1},
		{"Deny NotAction that does not list Sign", "Deny", []string{"kms:Describe*"}, 0},
		{"Deny NotAction that lists Sign", "Deny", []string{"kms:Sign"}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := principals(t, policyOf(t, notAction(tc.effect, tc.actions...))); len(got) != tc.want {
				t.Fatalf("got %+v, want %d", got, tc.want)
			}
		})
	}
}

func TestAConditionIsIgnoredAndTheStatementStillCounts(t *testing.T) {
	st := stmt(holder, "kms:Sign")
	st["Condition"] = map[string]any{"StringEquals": map[string]any{"kms:SigningAlgorithm": "ECDSA_SHA_384", "kms:MessageType": "DIGEST"}}
	got := principals(t, policyOf(t, st))
	if want := []handoff.Principal{role("example-key-holder")}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	// With the same condition, the statement that does not allow Sign still does not count.
	st2 := stmt(holder, "kms:Describe*")
	st2["Condition"] = st["Condition"]
	if got := principals(t, policyOf(t, st2)); len(got) != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestTheStatementsOfTheVectorsThatDoNotAllowSign(t *testing.T) {
	admin := map[string]any{
		"Sid": "Admin", "Effect": "Allow", "Principal": map[string]any{"AWS": "arn:aws:iam::123456789012:role/example-key-admin"},
		"Action":   []string{"kms:Describe*", "kms:Get*", "kms:List*", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion"},
		"Resource": "*",
	}
	certifierRead := map[string]any{
		"Sid": "CertifierRead", "Effect": "Allow", "Principal": map[string]any{"AWS": "arn:aws:iam::111122223333:role/example-certifier-read"},
		"Action": []string{"kms:DescribeKey", "kms:GetPublicKey", "kms:GetKeyPolicy"}, "Resource": "*",
	}
	use := map[string]any{
		"Sid": "Use", "Effect": "Allow", "Principal": map[string]any{"AWS": holder},
		"Action": []string{"kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"}, "Resource": "*",
	}
	if got := principals(t, policyOf(t, admin, certifierRead)); len(got) != 0 {
		t.Fatalf("the Admin and CertifierRead statements count as Sign: %+v", got)
	}
	got := principals(t, policyOf(t, admin, use, certifierRead))
	if want := []handoff.Principal{role("example-key-holder")}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestStatementAsOneObjectOrAList(t *testing.T) {
	st := stmt(holder, "kms:Sign")
	one := jsonOf(t, map[string]any{"Version": "2012-10-17", "Statement": st})
	list := policyOf(t, st)
	if a, b := principals(t, one), principals(t, list); !reflect.DeepEqual(a, b) || len(a) != 1 {
		t.Fatalf("one object gives %+v, a list gives %+v", a, b)
	}
	for _, v := range []string{"2012-10-17", "2008-10-17"} {
		doc := jsonOf(t, map[string]any{"Version": v, "Id": "example-policy", "Statement": []any{st}})
		if got := principals(t, doc); len(got) != 1 {
			t.Fatalf("version %s: got %+v", v, got)
		}
	}
}

func TestPrincipalKinds(t *testing.T) {
	const acct = "123456789012"
	type member = map[string]any
	cases := []struct {
		name      string
		principal any
		want      []handoff.Principal
	}{
		{"a star", "*", []handoff.Principal{{ARN: "*", Kind: handoff.PrincipalWildcard}}},
		{"AWS star", member{"AWS": "*"}, []handoff.Principal{{ARN: "*", Kind: handoff.PrincipalWildcard}}},
		{"the account root ARN", member{"AWS": "arn:aws:iam::" + acct + ":root"},
			[]handoff.Principal{{ARN: "arn:aws:iam::" + acct + ":root", Kind: handoff.PrincipalRoot}}},
		{"a bare account id", member{"AWS": acct}, []handoff.Principal{{ARN: acct, Kind: handoff.PrincipalRoot}}},
		{"a role ARN", member{"AWS": holder}, []handoff.Principal{{ARN: holder, Kind: handoff.PrincipalRole}}},
		{"a role ARN with a path", member{"AWS": "arn:aws:iam::" + acct + ":role/path/to/example"},
			[]handoff.Principal{{ARN: "arn:aws:iam::" + acct + ":role/path/to/example", Kind: handoff.PrincipalRole}}},
		{"a user ARN", member{"AWS": "arn:aws:iam::" + acct + ":user/example"},
			[]handoff.Principal{{ARN: "arn:aws:iam::" + acct + ":user/example", Kind: handoff.PrincipalUser}}},
		{"a role ARN of another partition", member{"AWS": "arn:aws-cn:iam::" + acct + ":role/example"},
			[]handoff.Principal{{ARN: "arn:aws-cn:iam::" + acct + ":role/example", Kind: handoff.PrincipalRole}}},
		{"a list of two", member{"AWS": []string{holder, "arn:aws:iam::" + acct + ":user/example"}},
			[]handoff.Principal{{ARN: holder, Kind: handoff.PrincipalRole}, {ARN: "arn:aws:iam::" + acct + ":user/example", Kind: handoff.PrincipalUser}}},
		{"a list of one", member{"AWS": []string{holder}}, []handoff.Principal{{ARN: holder, Kind: handoff.PrincipalRole}}},
		{"an assumed-role ARN", member{"AWS": "arn:aws:sts::" + acct + ":assumed-role/example/session"},
			[]handoff.Principal{{ARN: "arn:aws:sts::" + acct + ":assumed-role/example/session", Kind: handoff.PrincipalOther}}},
		{"a unique id", member{"AWS": "AROAEXAMPLEEXAMPLE"}, []handoff.Principal{{ARN: "AROAEXAMPLEEXAMPLE", Kind: handoff.PrincipalOther}}},
		{"an empty string", member{"AWS": ""}, []handoff.Principal{{ARN: "", Kind: handoff.PrincipalOther}}},
		{"11 digits", member{"AWS": "12345678901"}, []handoff.Principal{{ARN: "12345678901", Kind: handoff.PrincipalOther}}},
		{"13 digits", member{"AWS": "1234567890123"}, []handoff.Principal{{ARN: "1234567890123", Kind: handoff.PrincipalOther}}},
		{"an ARN with a star in the name", member{"AWS": "arn:aws:iam::" + acct + ":role/*"},
			[]handoff.Principal{{ARN: "arn:aws:iam::" + acct + ":role/*", Kind: handoff.PrincipalWildcard}}},
		{"an ARN with a question mark", member{"AWS": "arn:aws:iam::" + acct + ":role/example?"},
			[]handoff.Principal{{ARN: "arn:aws:iam::" + acct + ":role/example?", Kind: handoff.PrincipalWildcard}}},
		{"a star among roles", member{"AWS": []string{holder, "*"}},
			[]handoff.Principal{{ARN: holder, Kind: handoff.PrincipalRole}, {ARN: "*", Kind: handoff.PrincipalWildcard}}},
		{"a role with a name of the wrong characters", member{"AWS": "arn:aws:iam::" + acct + ":role/exa mple"},
			[]handoff.Principal{{ARN: "arn:aws:iam::" + acct + ":role/exa\\x20mple", Kind: handoff.PrincipalOther}}},
		{"a role with a non-ASCII name", member{"AWS": "arn:aws:iam::" + acct + ":role/ex\xc3\xa4mple"},
			[]handoff.Principal{{ARN: "arn:aws:iam::" + acct + ":role/ex\\u00e4mple", Kind: handoff.PrincipalOther}}},
		{"a role with an empty name", member{"AWS": "arn:aws:iam::" + acct + ":role/"},
			[]handoff.Principal{{ARN: "arn:aws:iam::" + acct + ":role/", Kind: handoff.PrincipalOther}}},
		{"a role ARN with a Region", member{"AWS": "arn:aws:iam:eu-west-1:" + acct + ":role/example"},
			[]handoff.Principal{{ARN: "arn:aws:iam:eu-west-1:" + acct + ":role/example", Kind: handoff.PrincipalOther}}},
		{"a role ARN in upper case", member{"AWS": "arn:aws:iam::" + acct + ":Role/example"},
			[]handoff.Principal{{ARN: "arn:aws:iam::" + acct + ":Role/example", Kind: handoff.PrincipalOther}}},
		{"a backslash", member{"AWS": `a\b`}, []handoff.Principal{{ARN: `a\\b`, Kind: handoff.PrincipalOther}}},
		{"a service", member{"Service": "kms.amazonaws.com"}, []handoff.Principal{{ARN: "kms.amazonaws.com", Kind: handoff.PrincipalOther}}},
		{"a service star", member{"Service": "*"}, []handoff.Principal{{ARN: "*", Kind: handoff.PrincipalWildcard}}},
		{"a service that looks like a role ARN", member{"Service": holder}, []handoff.Principal{{ARN: holder, Kind: handoff.PrincipalOther}}},
		{"a service that looks like the account root", member{"Service": acct}, []handoff.Principal{{ARN: acct, Kind: handoff.PrincipalOther}}},
		{"a federated name", member{"Federated": "cognito-identity.amazonaws.com"},
			[]handoff.Principal{{ARN: "cognito-identity.amazonaws.com", Kind: handoff.PrincipalOther}}},
		{"a federated name that looks like a user", member{"Federated": "arn:aws:iam::" + acct + ":user/example"},
			[]handoff.Principal{{ARN: "arn:aws:iam::" + acct + ":user/example", Kind: handoff.PrincipalOther}}},
		{"a federated star", member{"Federated": "*"}, []handoff.Principal{{ARN: "*", Kind: handoff.PrincipalWildcard}}},
		{"a canonical user", member{"CanonicalUser": "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"},
			[]handoff.Principal{{ARN: "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be", Kind: handoff.PrincipalOther}}},
		{"a canonical user star", member{"CanonicalUser": "*"}, []handoff.Principal{{ARN: "*", Kind: handoff.PrincipalWildcard}}},
		{"an empty object", member{}, []handoff.Principal{{ARN: "", Kind: handoff.PrincipalOther}}},
		{"an unknown member", member{"Account": acct}, []handoff.Principal{{ARN: "", Kind: handoff.PrincipalOther}}},
		{"an unknown member beside a role", member{"AWS": holder, "Account": acct},
			[]handoff.Principal{{ARN: holder, Kind: handoff.PrincipalRole}, {ARN: "", Kind: handoff.PrincipalOther}}},
		{"AWS in lower case is not a member", member{"aws": holder}, []handoff.Principal{{ARN: "", Kind: handoff.PrincipalOther}}},
		{"members in the order AWS, Service, Federated, CanonicalUser",
			member{"CanonicalUser": "c", "Federated": "f", "Service": "s", "AWS": holder},
			[]handoff.Principal{
				{ARN: holder, Kind: handoff.PrincipalRole}, {ARN: "s", Kind: handoff.PrincipalOther},
				{ARN: "f", Kind: handoff.PrincipalOther}, {ARN: "c", Kind: handoff.PrincipalOther},
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := map[string]any{"Effect": "Allow", "Principal": tc.principal, "Action": "kms:Sign", "Resource": "*"}
			got := principals(t, policyOf(t, st))
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
			// The same principal in a statement that does not allow Sign is not read.
			st["Action"] = "kms:Describe*"
			if got := principals(t, policyOf(t, st)); len(got) != 0 {
				t.Fatalf("a statement without Sign gave %+v", got)
			}
		})
	}
}

func TestNotPrincipalAndNoPrincipal(t *testing.T) {
	t.Run("NotPrincipal", func(t *testing.T) {
		st := map[string]any{"Effect": "Allow", "NotPrincipal": map[string]any{"AWS": holder}, "Action": "kms:Sign", "Resource": "*"}
		got := principals(t, policyOf(t, st))
		if want := []handoff.Principal{{ARN: "NotPrincipal", Kind: handoff.PrincipalWildcard}}; !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})
	t.Run("NotPrincipal of any shape", func(t *testing.T) {
		for _, np := range []any{"*", "x", 7, []any{}, nil, map[string]any{}, true} {
			st := map[string]any{"Effect": "Allow", "NotPrincipal": np, "Action": "kms:Sign", "Resource": "*"}
			doc := policyOf(t, st)
			if np == nil {
				// A null is refused by the reader, as anywhere in a policy.
				wantPolicyFault(t, doc)
				continue
			}
			got := principals(t, doc)
			if want := []handoff.Principal{{ARN: "NotPrincipal", Kind: handoff.PrincipalWildcard}}; !reflect.DeepEqual(got, want) {
				t.Fatalf("NotPrincipal %v: got %+v, want %+v", np, got, want)
			}
		}
	})
	t.Run("Principal and NotPrincipal together are both listed", func(t *testing.T) {
		st := map[string]any{
			"Effect": "Allow", "Principal": map[string]any{"AWS": holder}, "NotPrincipal": map[string]any{"AWS": "x"},
			"Action": "kms:Sign", "Resource": "*",
		}
		got := principals(t, policyOf(t, st))
		want := []handoff.Principal{{ARN: holder, Kind: handoff.PrincipalRole}, {ARN: "NotPrincipal", Kind: handoff.PrincipalWildcard}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})
	t.Run("neither is one principal of kind other", func(t *testing.T) {
		st := map[string]any{"Effect": "Allow", "Action": "kms:Sign", "Resource": "*"}
		got := principals(t, policyOf(t, st))
		if want := []handoff.Principal{{ARN: "", Kind: handoff.PrincipalOther}}; !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})
	t.Run("neither, in a statement that does not allow Sign", func(t *testing.T) {
		st := map[string]any{"Effect": "Allow", "Action": "kms:Describe*", "Resource": "*"}
		if got := principals(t, policyOf(t, st)); len(got) != 0 {
			t.Fatalf("got %+v", got)
		}
	})
}

func TestPrincipalsInTheOrderOfThePolicy(t *testing.T) {
	a, b, c := role("example-a"), role("example-b"), role("example-c")
	got := principals(t, policyOf(t,
		stmt(b.ARN, "kms:Sign"),
		stmt(a.ARN, "kms:Describe*"),
		stmt([]string{c.ARN, a.ARN}, "kms:*"),
		stmt(b.ARN, "*"),
	))
	if want := []handoff.Principal{b, c, a, b}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// A principal that two statements name is listed twice: counting the distinct ones is check 9's.
func TestAPrincipalListedTwiceIsListedTwiceAndCountsOnce(t *testing.T) {
	got := principals(t, policyOf(t, stmt(holder, "kms:Sign"), stmt(holder, "kms:*")))
	if len(got) != 2 || got[0] != got[1] {
		t.Fatalf("got %+v, want the one principal twice", got)
	}
	if n := distinct(got); n != 1 {
		t.Fatalf("%d distinct principals, want 1", n)
	}
}

func distinct(list []handoff.Principal) int {
	seen := map[handoff.Principal]bool{}
	for _, p := range list {
		seen[p] = true
	}
	return len(seen)
}

func TestNoStatementThatAllowsSignGivesAnEmptyListAndNoError(t *testing.T) {
	got, err := kms.SignPrincipals(policyOf(t, stmt(holder, "kms:Describe*")))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("got %+v", got)
	}
}

// Two principals whose text differs only where Escape is not one to one are two principals.
func TestPrincipalsThatEscapeAlikeAreTwo(t *testing.T) {
	letter := "\xc3\xa9"
	text := "\\" + "u00e9"
	if jsonset.Escape(letter) != jsonset.Escape(text) {
		t.Fatalf("the premise is wrong: Escape gives %q and %q", jsonset.Escape(letter), jsonset.Escape(text))
	}
	got := principals(t, policyOf(t, stmt([]string{letter, text}, "kms:Sign")))
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	if got[0].ARN == got[1].ARN {
		t.Fatalf("two different principals read as the same text %q", got[0].ARN)
	}
	if distinct(got) != 2 {
		t.Fatalf("the distinct count is %d, want 2", distinct(got))
	}
	// The same, through invalid UTF-8 and the replacement character, and through a space.
	for _, pair := range [][2]string{
		{"\xef\xbf\xbd", "\xff"}, {"a b", `a\x20b`}, {"\xfe", "\xff"}, {`\`, `\\`}, {"a\xe2\x80\xa8b", "a\xe2\x80\xa9b"}, {"\xc3\xa9", "e\xcc\x81"},
	} {
		doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":[` + rawJSONString(pair[0]) + `,` + rawJSONString(pair[1]) + `]},"Action":"kms:Sign"}]}`
		g, err := kms.SignPrincipals(doc)
		if err != nil {
			// A reader may refuse bytes that are not UTF-8; it must then refuse both, never one.
			continue
		}
		if len(g) != 2 || g[0].ARN == g[1].ARN {
			t.Fatalf("%q and %q: got %+v", pair[0], pair[1], g)
		}
	}
}

// rawJSONString writes s as a JSON string and keeps its bytes as they are, the ones that are not UTF-8 too.
func rawJSONString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 0x20:
			fmt.Fprintf(&b, `\u%04x`, c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func TestEveryReturnedPrincipalTextIsPrintableASCII(t *testing.T) {
	hostile := []string{"\xe2\x80\xae", "a\u0000b", "a\nb", "\xc3\xa9", "\xff\xfe", "\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e", "\xe2\x80\xa8", "\U0001F600", `a\b`, `"quoted"`}
	for _, h := range hostile {
		raw := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":[` + rawJSONString(h) + `]},"Action":"kms:Sign"}]}`
		got, err := kms.SignPrincipals(raw)
		if err != nil {
			continue
		}
		for _, p := range got {
			if !printable(p.ARN) {
				t.Errorf("a principal text with a character outside printable ASCII: %q", p.ARN)
			}
		}
	}
}

func TestRefusedPolicies(t *testing.T) {
	good := stmt(holder, "kms:Sign")
	st := func(change func(m map[string]any)) any {
		m := map[string]any{}
		for k, v := range good {
			m[k] = v
		}
		change(m)
		return m
	}
	doc := func(statement any) string {
		return jsonOf(t, map[string]any{"Version": "2012-10-17", "Statement": statement})
	}
	goodStatement := `{"Effect":"Allow","Principal":{"AWS":"` + holder + `"},"Action":"kms:Sign"}`
	bad := map[string]string{
		"not JSON":                         "not json",
		"the empty text":                   "",
		"white space only":                 "  \n ",
		"an empty array":                   "[]",
		"null":                             "null",
		"a string":                         `"x"`,
		"a number":                         "7",
		"an empty object":                  "{}",
		"a list of statements only":        "[" + goodStatement + "]",
		"a trailing second object":         policyOf(t, good) + "{}",
		"trailing text":                    policyOf(t, good) + " x",
		"a byte order mark":                "\ufeff" + policyOf(t, good),
		"a float":                          `{"Version":"2012-10-17","Statement":[` + goodStatement + `],"Id":1.5}`,
		"a float in a condition":           `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"kms:Sign","Condition":{"NumericLessThan":{"x":1.5}}}]}`,
		"an exponent":                      `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"kms:Sign","Condition":{"x":1e3}}]}`,
		"null in a condition":              `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"kms:Sign","Condition":{"x":null}}]}`,
		"null as Resource":                 `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"kms:Sign","Resource":null}]}`,
		"null as Sid":                      `{"Version":"2012-10-17","Statement":[{"Sid":null,"Effect":"Allow","Principal":"*","Action":"kms:Sign"}]}`,
		"null as Id":                       `{"Version":"2012-10-17","Id":null,"Statement":[` + goodStatement + `]}`,
		"a repeated member at the top":     `{"Version":"2012-10-17","Version":"2008-10-17","Statement":[` + goodStatement + `]}`,
		"a repeated Statement":             `{"Version":"2012-10-17","Statement":[],"Statement":[` + goodStatement + `]}`,
		"a repeated member in a statement": `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Effect":"Allow","Principal":"*","Action":"kms:Sign"}]}`,
		"a repeated member written with an escape": `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Effect":"Allow","Principal":"*","Action":"kms:Sign"}]}`,
		"a repeated member in a principal":         `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"x","AWS":"y"},"Action":"kms:Sign"}]}`,
		"a repeated member deep in a condition":    `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"kms:Sign","Condition":{"a":{"b":1,"b":2}}}]}`,
		"a missing Statement":                      `{"Version":"2012-10-17"}`,
		"an empty Statement list":                  `{"Version":"2012-10-17","Statement":[]}`,
		"Statement as a string":                    `{"Version":"2012-10-17","Statement":"x"}`,
		"Statement as a number":                    `{"Version":"2012-10-17","Statement":1}`,
		"Statement as a list of lists":             `{"Version":"2012-10-17","Statement":[[` + goodStatement + `]]}`,
		"Statement as a list of strings":           `{"Version":"2012-10-17","Statement":["x"]}`,
		"a statement that is null":                 `{"Version":"2012-10-17","Statement":[null]}`,
		"a missing Version":                        `{"Statement":[` + goodStatement + `]}`,
		"Version of another text":                  `{"Version":"2020-01-01","Statement":[` + goodStatement + `]}`,
		"Version in another case":                  `{"version":"2012-10-17","Statement":[` + goodStatement + `]}`,
		"Version as a number":                      `{"Version":2012,"Statement":[` + goodStatement + `]}`,
		"Version as a list":                        `{"Version":["2012-10-17"],"Statement":[` + goodStatement + `]}`,
		"Version with a trailing space":            `{"Version":"2012-10-17 ","Statement":[` + goodStatement + `]}`,
		"an unknown top-level member":              `{"Version":"2012-10-17","Extra":1,"Statement":[` + goodStatement + `]}`,
		"statement in lower case":                  `{"Version":"2012-10-17","statement":[` + goodStatement + `]}`,
		"Id as a number":                           `{"Version":"2012-10-17","Id":7,"Statement":[` + goodStatement + `]}`,
		"Id of 2049 characters":                    `{"Version":"2012-10-17","Id":"` + strings.Repeat("a", kms.MaxTextLength+1) + `","Statement":[` + goodStatement + `]}`,
		"Sid as a number":                          `{"Version":"2012-10-17","Statement":[{"Sid":7,"Effect":"Allow","Principal":"*","Action":"kms:Sign"}]}`,
		"Sid of 2049 characters": `{"Version":"2012-10-17","Statement":[{"Sid":"` + strings.Repeat("a", kms.MaxTextLength+1) +
			`","Effect":"Allow","Principal":"*","Action":"kms:Sign"}]}`,
		"an unknown statement member":              doc(st(func(m map[string]any) { m["Extra"] = 1 })),
		"Effect allow in lower case":               doc(st(func(m map[string]any) { m["Effect"] = "allow" })),
		"Effect ALLOW":                             doc(st(func(m map[string]any) { m["Effect"] = "ALLOW" })),
		"Effect with a space":                      doc(st(func(m map[string]any) { m["Effect"] = "Allow " })),
		"Effect of another text":                   doc(st(func(m map[string]any) { m["Effect"] = "Permit" })),
		"no Effect":                                doc(st(func(m map[string]any) { delete(m, "Effect") })),
		"Effect as a list":                         doc(st(func(m map[string]any) { m["Effect"] = []string{"Allow"} })),
		"Effect as a bool":                         doc(st(func(m map[string]any) { m["Effect"] = true })),
		"both Action and NotAction":                doc(st(func(m map[string]any) { m["NotAction"] = "s3:*" })),
		"neither Action nor NotAction":             doc(st(func(m map[string]any) { delete(m, "Action") })),
		"Action as a number":                       doc(st(func(m map[string]any) { m["Action"] = 7 })),
		"Action as a bool":                         doc(st(func(m map[string]any) { m["Action"] = true })),
		"Action as an object":                      doc(st(func(m map[string]any) { m["Action"] = map[string]any{"a": "b"} })),
		"Action as an empty list":                  doc(st(func(m map[string]any) { m["Action"] = []string{} })),
		"Action as a list of numbers":              doc(st(func(m map[string]any) { m["Action"] = []any{1, 2} })),
		"Action as a list of lists":                doc(st(func(m map[string]any) { m["Action"] = []any{[]string{"kms:Sign"}} })),
		"Action with a number among strings":       doc(st(func(m map[string]any) { m["Action"] = []any{"kms:Describe*", 1} })),
		"NotAction as an empty list":               doc(st(func(m map[string]any) { delete(m, "Action"); m["NotAction"] = []string{} })),
		"NotAction as a number":                    doc(st(func(m map[string]any) { delete(m, "Action"); m["NotAction"] = 1 })),
		"Principal as a string that is not a star": doc(st(func(m map[string]any) { m["Principal"] = holder })),
		"Principal as two stars":                   doc(st(func(m map[string]any) { m["Principal"] = "**" })),
		"Principal as an empty string":             doc(st(func(m map[string]any) { m["Principal"] = "" })),
		"Principal as a list":                      doc(st(func(m map[string]any) { m["Principal"] = []string{"*"} })),
		"Principal as a number":                    doc(st(func(m map[string]any) { m["Principal"] = 1 })),
		"Principal as a bool":                      doc(st(func(m map[string]any) { m["Principal"] = true })),
		"an AWS member that is a number":           doc(st(func(m map[string]any) { m["Principal"] = map[string]any{"AWS": 1} })),
		"an AWS member that is an object":          doc(st(func(m map[string]any) { m["Principal"] = map[string]any{"AWS": map[string]any{"a": "b"}} })),
		"an AWS member that is an empty list":      doc(st(func(m map[string]any) { m["Principal"] = map[string]any{"AWS": []string{}} })),
		"an AWS list with a number":                doc(st(func(m map[string]any) { m["Principal"] = map[string]any{"AWS": []any{holder, 1}} })),
		"a Service member that is a bool":          doc(st(func(m map[string]any) { m["Principal"] = map[string]any{"Service": false} })),
		"a principal of 2049 characters": doc(st(func(m map[string]any) {
			m["Principal"] = map[string]any{"AWS": strings.Repeat("a", kms.MaxTextLength+1)}
		})),
		"a principal of 2049 characters in a list": doc(st(func(m map[string]any) {
			m["Principal"] = map[string]any{"AWS": []string{holder, strings.Repeat("a", kms.MaxTextLength+1)}}
		})),
		"a statement that does not allow Sign with a bad shape": doc(st(func(m map[string]any) {
			m["Action"] = "kms:Describe*"
			m["Effect"] = "Maybe"
		})),
		"a Deny statement with an unknown member": doc(st(func(m map[string]any) { m["Effect"] = "Deny"; m["Extra"] = 1 })),
		"a bad second statement":                  jsonOf(t, map[string]any{"Version": "2012-10-17", "Statement": []any{good, map[string]any{"Effect": "Allow"}}}),
		"a bad statement after a Deny": jsonOf(t, map[string]any{"Version": "2012-10-17", "Statement": []any{
			st(func(m map[string]any) { m["Effect"] = "Deny" }), map[string]any{"Effect": "Allow", "Action": 5},
		}}),
		"a lone surrogate escape":             `{"Version":"2012-10-17","Statement":[{"Sid":"\ud800","Effect":"Allow","Principal":"*","Action":"kms:Sign"}]}`,
		"a raw control character in a string": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"a\nb\",\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"kms:Sign\"}]}",
		"a number with a leading zero":        `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"kms:Sign","Condition":{"x":01}}]}`,
		"a trailing comma":                    `{"Version":"2012-10-17","Statement":[` + goodStatement + `,]}`,
		"single quotes":                       `{'Version':'2012-10-17','Statement':[]}`,
		"a comment":                           `{"Version":"2012-10-17" /* c */,"Statement":[` + goodStatement + `]}`,
	}
	for name, text := range bad {
		t.Run(name, func(t *testing.T) {
			wantPolicyFault(t, text)
		})
	}
	// The accepted twin of every row: the good statement is read.
	if got := principals(t, doc(good)); len(got) != 1 {
		t.Fatalf("the good statement gives %+v", got)
	}
}

func TestPolicyBounds(t *testing.T) {
	t.Run("200 statements", func(t *testing.T) {
		list := make([]any, kms.MaxStatements)
		for i := range list {
			list[i] = stmt(holder, "kms:Describe*")
		}
		if got := principals(t, policyOf(t, list...)); len(got) != 0 {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("201 statements", func(t *testing.T) {
		list := make([]any, kms.MaxStatements+1)
		for i := range list {
			list[i] = stmt(holder, "kms:Describe*")
		}
		wantPolicyFault(t, policyOf(t, list...))
	})
	roles := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("arn:aws:iam::123456789012:role/example-%04d", i)
		}
		return out
	}
	t.Run("1000 principals in one statement", func(t *testing.T) {
		if got := principals(t, policyOf(t, stmt(roles(kms.MaxPrincipals), "kms:Sign"))); len(got) != kms.MaxPrincipals {
			t.Fatalf("got %d", len(got))
		}
	})
	t.Run("1001 principals in one statement", func(t *testing.T) {
		wantPolicyFault(t, policyOf(t, stmt(roles(kms.MaxPrincipals+1), "kms:Sign")))
	})
	t.Run("1000 principals over two statements", func(t *testing.T) {
		r := roles(kms.MaxPrincipals)
		if got := principals(t, policyOf(t, stmt(r[:500], "kms:Sign"), stmt(r[500:], "kms:Sign"))); len(got) != kms.MaxPrincipals {
			t.Fatalf("got %d", len(got))
		}
	})
	t.Run("1001 principals over two statements", func(t *testing.T) {
		r := roles(kms.MaxPrincipals + 1)
		wantPolicyFault(t, policyOf(t, stmt(r[:500], "kms:Sign"), stmt(r[500:], "kms:Sign")))
	})
	t.Run("1001 principals over members of one statement", func(t *testing.T) {
		r := roles(kms.MaxPrincipals + 1)
		st := map[string]any{"Effect": "Allow", "Action": "kms:Sign", "Principal": map[string]any{"AWS": r[:501], "Service": r[501:]}}
		wantPolicyFault(t, policyOf(t, st))
	})
	t.Run("principals of statements that do not allow Sign are not counted", func(t *testing.T) {
		r := roles(kms.MaxPrincipals)
		got := principals(t, policyOf(t, stmt(r, "kms:Describe*"), stmt(holder, "kms:Sign")))
		if len(got) != 1 {
			t.Fatalf("got %d", len(got))
		}
	})
	t.Run("a principal text of 2048 characters", func(t *testing.T) {
		text := strings.Repeat("a", kms.MaxTextLength)
		got := principals(t, policyOf(t, stmt(text, "kms:Sign")))
		if len(got) != 1 || got[0].Kind != handoff.PrincipalOther {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("a Sid and an Id of 2048 characters", func(t *testing.T) {
		text := strings.Repeat("a", kms.MaxTextLength)
		st := stmt(holder, "kms:Sign")
		st["Sid"] = text
		doc := jsonOf(t, map[string]any{"Version": "2012-10-17", "Id": text, "Statement": []any{st}})
		if got := principals(t, doc); len(got) != 1 {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("a policy of exactly MaxPolicyBytes", func(t *testing.T) {
		doc := policyOf(t, stmt(holder, "kms:Sign"))
		doc += strings.Repeat(" ", kms.MaxPolicyBytes-len(doc))
		if len(doc) != kms.MaxPolicyBytes {
			t.Fatalf("the text is %d bytes", len(doc))
		}
		if got := principals(t, doc); len(got) != 1 {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("a policy of MaxPolicyBytes+1", func(t *testing.T) {
		doc := policyOf(t, stmt(holder, "kms:Sign"))
		doc += strings.Repeat(" ", kms.MaxPolicyBytes+1-len(doc))
		wantPolicyFault(t, doc)
	})
	t.Run("a policy over the limit is refused unread", func(t *testing.T) {
		// Text that no parser could read: the refusal is for the length, and its words say so.
		doc := strings.Repeat("{", kms.MaxPolicyBytes+1)
		_, err := kms.SignPrincipals(doc)
		var r *kms.Refusal
		if !errors.As(err, &r) || r.Fault != kms.FaultPolicy || !strings.Contains(r.Detail, "longer than the limit") {
			t.Fatalf("error %v", err)
		}
		// The same bytes within the limit are refused for their form.
		_, err = kms.SignPrincipals(strings.Repeat("{", kms.MaxPolicyBytes))
		if !errors.As(err, &r) || strings.Contains(r.Detail, "longer than the limit") {
			t.Fatalf("error %v", err)
		}
	})
}

// strictjson allows 10000 levels in all, the top-level object counting as one. A policy with a deeper
// Condition is refused and never crashes the reader.
func TestPolicyDepth(t *testing.T) {
	nested := func(levels int) string {
		return `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":"*","Action":"kms:Sign","Condition":` +
			strings.Repeat("[", levels) + strings.Repeat("]", levels) + `}}`
	}
	// The top object and the statement are two levels, so 9998 more make 10000.
	if got := principals(t, nested(9998)); len(got) != 1 {
		t.Fatalf("a policy of 10000 levels gives %+v", got)
	}
	wantPolicyFault(t, nested(9999))
	wantPolicyFault(t, nested(10000))
	wantPolicyFault(t, nested(20000))
	wantPolicyFault(t, strings.Repeat("[", 30000))
}

func TestHostilePolicyBytes(t *testing.T) {
	for name, text := range map[string]string{
		"invalid UTF-8 in a name":  "{\"Version\":\"2012-10-17\",\"Statement\":{\"Sid\":\"\xff\",\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"kms:Sign\"}}",
		"a NUL byte":               "{\"Version\":\"2012-10-17\",\"Statement\":{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"kms:Sign\"}}\x00",
		"a NUL escape in a Sid":    `{"Version":"2012-10-17","Statement":{"Sid":"a\u0000b","Effect":"Allow","Principal":"*","Action":"kms:Sign"}}`,
		"a right-to-left override": "{\"Version\":\"2012-10-17\",\"Statement\":{\"Sid\":\"\xe2\x80\xae\",\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"kms:Sign\"}}",
		"a huge number":            `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":"*","Action":"kms:Sign","Condition":{"x":` + strings.Repeat("9", 5000) + `}}}`,
		"many members":             `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":"*","Action":"kms:Sign","Condition":{` + manyMembers(3000) + `}}}`,
		"an escape of every kind":  `{"Version":"2012-10-17","Statement":{"Sid":"\"\\\/\b\f\n\r\t` + "\xc3\xa9" + `","Effect":"Allow","Principal":"*","Action":"kms:Sign"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			// Whatever the result, it is a list or a refusal, and no text of the input is in an error.
			got, err := kms.SignPrincipals(text)
			if err != nil {
				var r *kms.Refusal
				if !errors.As(err, &r) || got != nil || !printable(err.Error()) {
					t.Fatalf("error %v (%T), list %+v", err, err, got)
				}
				return
			}
			for _, p := range got {
				if !printable(p.ARN) {
					t.Fatalf("principal text %q", p.ARN)
				}
			}
		})
	}
}

func manyMembers(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"k%d":%d`, i, i)
	}
	return b.String()
}

// No byte of a policy that is refused is in the error: the holder of the key writes the policy.
func TestARefusedPolicyDoesNotLeakItsText(t *testing.T) {
	const marker = "SECRET-MARKER-9f3a"
	for name, text := range map[string]string{
		"an unknown top-level member": `{"Version":"2012-10-17","` + marker + `":1,"Statement":[]}`,
		"an unknown statement member": `{"Version":"2012-10-17","Statement":[{"` + marker + `":1,"Effect":"Allow","Principal":"*","Action":"kms:Sign"}]}`,
		"an unknown principal member": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"` + marker + `","Action":"kms:Sign"}]}`,
		"a bad Effect":                `{"Version":"2012-10-17","Statement":[{"Effect":"` + marker + `","Principal":"*","Action":"kms:Sign"}]}`,
		"a bad Version":               `{"Version":"` + marker + `","Statement":[]}`,
		"a long Sid":                  `{"Version":"2012-10-17","Statement":[{"Sid":"` + marker + strings.Repeat("a", 3000) + `","Effect":"Allow","Principal":"*","Action":"kms:Sign"}]}`,
		"a long principal":            `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"` + marker + strings.Repeat("a", 3000) + `"},"Action":"kms:Sign"}]}`,
		"a repeated member":           `{"Version":"2012-10-17","` + marker + `":1,"` + marker + `":2,"Statement":[]}`,
		"a float":                     `{"Version":"2012-10-17","` + marker + `":1.5,"Statement":[]}`,
		"a Deny with a bad member":    `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","` + marker + `":1,"Action":"x"}]}`,
		"a list of the marker":        `{"Version":"2012-10-17","Statement":["` + marker + `"]}`,
		"a long action":               `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"` + marker + strings.Repeat("a", 300) + `"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := kms.SignPrincipals(text)
			if err == nil {
				t.Fatal("accepted")
			}
			if strings.Contains(err.Error(), marker) {
				t.Fatalf("the error holds a text of the policy: %v", err)
			}
		})
	}
}

func FuzzSignPrincipals(f *testing.F) {
	st := `{"Effect":"Allow","Principal":{"AWS":"` + holder + `"},"Action":["kms:Sign","kms:Get*"],"Resource":"*"}`
	for _, s := range []string{
		"", "{}", "[]", "null",
		`{"Version":"2012-10-17","Statement":[` + st + `]}`,
		`{"Version":"2012-10-17","Statement":` + st + `}`,
		`{"Version":"2008-10-17","Id":"x","Statement":[{"Effect":"Deny","NotPrincipal":"*","NotAction":"kms:*"}]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Condition":{"StringEquals":{"a":["b"]}}}]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"x","AWS":["a","` + holder + `"]},"Action":"kms:S?gn"}]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"` + "\xc3\xa9\xf0\x9f\x98\x80" + `"},"Action":"kms:Sign"}]}`,
		"{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"\xff\"},\"Action\":\"kms:Sign\"}]}",
		policyDeep(5), policyDeep(200),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, err := kms.SignPrincipals(s)
		if err != nil {
			var r *kms.Refusal
			if !errors.As(err, &r) || r.Fault != kms.FaultPolicy {
				t.Fatalf("error %v (%T) is not a policy refusal", err, err)
			}
			if got != nil {
				t.Fatalf("an error beside a list: %+v", got)
			}
			if !printable(err.Error()) || len(err.Error()) > 400 {
				t.Fatalf("the error is not short printable ASCII: %q", err.Error())
			}
			return
		}
		if len(s) > kms.MaxPolicyBytes {
			t.Fatalf("a policy of %d bytes is accepted", len(s))
		}
		if len(got) > kms.MaxPrincipals {
			t.Fatalf("%d principals", len(got))
		}
		for _, p := range got {
			switch p.Kind {
			case handoff.PrincipalRole, handoff.PrincipalUser, handoff.PrincipalRoot, handoff.PrincipalWildcard, handoff.PrincipalOther:
			default:
				t.Fatalf("kind %q", p.Kind)
			}
			if !printable(p.ARN) {
				t.Fatalf("principal text %q", p.ARN)
			}
			if p.Kind == handoff.PrincipalRole || p.Kind == handoff.PrincipalUser || p.Kind == handoff.PrincipalRoot {
				if strings.ContainsAny(p.ARN, "*? ") {
					t.Fatalf("a %s with a wildcard or a space: %q", p.Kind, p.ARN)
				}
			}
		}
		// Reading the same text again gives the same list.
		again, err := kms.SignPrincipals(s)
		if err != nil || !reflect.DeepEqual(again, got) {
			t.Fatalf("second read: %+v, %v", again, err)
		}
	})
}

func policyDeep(n int) string {
	return `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":"*","Action":"kms:Sign","Condition":` +
		strings.Repeat("[", n) + strings.Repeat("]", n) + `}}`
}
