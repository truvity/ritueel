package kms

import (
	"slices"
	"strings"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/jsonset"
	"ritueel.id/ritueel/internal/strictjson"
)

// signAction is the action that the single-principal rule is about, in the one case that the matcher
// compares: IAM compares action names without regard to case.
const signAction = "kms:sign"

// policyFault is the refusal of a key policy that this package cannot read. The words are fixed.
func policyFault(words string) error {
	return &Refusal{Fault: FaultPolicy, Detail: "the key policy " + words}
}

// SignPrincipals reads a key policy document and returns the principals of every statement that allows
// kms:Sign, in the order of the policy: statements in order, and in a statement the members AWS, Service,
// Federated and CanonicalUser of its Principal, then NotPrincipal. A principal that is listed twice is listed
// twice; counting the distinct ones is check 9's.
//
// The text is untrusted (the holder of the key writes the policy). Its length is checked before it is parsed,
// it is parsed by package strictjson into one object (no member twice, no null, no float), and then read
// under these rules; any text that does not meet them is a fault and is never read in part. The error is a
// *[Refusal] with the fault [FaultPolicy].
//
//   - The members of the document are Version ("2012-10-17" or "2008-10-17", required), Id (a string) and
//     Statement (required: one object, or a list of 1 to [MaxStatements] objects). Another member is a fault.
//   - A statement has only Sid, Effect, Principal, NotPrincipal, Action, NotAction, Resource, NotResource and
//     Condition. Effect is "Allow" or "Deny", exactly. Exactly one of Action and NotAction is there, each a
//     string or a list of 1 to [MaxActions] strings of at most [MaxPatternLen] bytes.
//   - A statement allows kms:Sign when its Effect is Allow and, with Action, a pattern matches kms:Sign, or,
//     with NotAction, no pattern matches it. A pattern is IAM's: "*" for any run, "?" for one character,
//     compared without regard to case. A Deny statement and a Condition are ignored: ignoring them can only
//     add principals, so it can only turn an acceptance into a refusal.
//   - The principals of such a statement: "*" is a wildcard. An object has the members AWS, Service, Federated
//     and CanonicalUser, each a string or a non-empty list of strings; an empty object, or a member that is not
//     one of the four, adds one principal of kind other with an empty ARN. NotPrincipal is one principal of kind
//     wildcard with the ARN text "NotPrincipal". A statement with neither Principal nor NotPrincipal is one
//     principal of kind other with an empty ARN. A Principal that is any other string, a list, a number or a
//     boolean is a fault.
//   - A string of an AWS member is a wildcard when it holds "*" or "?"; a root when it is twelve digits or
//     arn:aws*:iam::ACCOUNT:root; a role or a user when it is arn:aws*:iam::ACCOUNT:role/NAME or :user/NAME
//     with a name of IAM's characters; any other string is other. A string of another member (a service, a
//     federated name, a canonical user) is a wildcard when it holds "*" or "?", and is other otherwise: it is
//     never a role or a user.
//   - The ARN text of a returned principal is [jsonset.EscapeExact] of the string, which is one to one, so two
//     different principals never read as one in the count of distinct principals.
//   - More than [MaxPrincipals] principals, a text over [MaxTextLength] bytes, or a count over any other
//     bound is a fault. A policy in which no statement allows kms:Sign returns an empty list and no error;
//     check 9 refuses it.
func SignPrincipals(policy string) ([]handoff.Principal, error) {
	if len(policy) > MaxPolicyBytes {
		return nil, policyFault("is longer than the limit")
	}
	var doc any
	if err := strictjson.Unmarshal([]byte(policy), &doc, strictjson.Options{MaxBytes: MaxPolicyBytes}); err != nil {
		return nil, policyFault("is not one JSON object of the plain form (no member twice, no null, no number with a fraction)")
	}
	top, ok := doc.(map[string]any)
	if !ok {
		return nil, policyFault("is not one JSON object")
	}
	for name := range top {
		switch name {
		case "Version", "Id", "Statement":
		default:
			return nil, policyFault("has a member that this reader does not know")
		}
	}
	if v, ok := top["Version"].(string); !ok || (v != "2012-10-17" && v != "2008-10-17") {
		return nil, policyFault("has no Version of 2012-10-17 or 2008-10-17")
	}
	if id, present := top["Id"]; present {
		if s, ok := id.(string); !ok || len(s) > MaxTextLength {
			return nil, policyFault("has an Id that is not a short string")
		}
	}
	statements, err := statementList(top["Statement"])
	if err != nil {
		return nil, err
	}
	var out []handoff.Principal
	for _, st := range statements {
		ps, err := statementPrincipals(st)
		if err != nil {
			return nil, err
		}
		if len(out)+len(ps) > MaxPrincipals {
			return nil, policyFault("names more principals than the limit")
		}
		out = append(out, ps...)
	}
	return out, nil
}

// statementList returns the statements of the member Statement: one object, or a list of 1 to MaxStatements.
func statementList(v any) ([]map[string]any, error) {
	switch s := v.(type) {
	case map[string]any:
		return []map[string]any{s}, nil
	case []any:
		if len(s) == 0 || len(s) > MaxStatements {
			return nil, policyFault("has no statement, or more than the limit")
		}
		out := make([]map[string]any, 0, len(s))
		for _, e := range s {
			m, ok := e.(map[string]any)
			if !ok {
				return nil, policyFault("has a statement that is not an object")
			}
			out = append(out, m)
		}
		return out, nil
	}
	return nil, policyFault("has no Statement that is an object or a list of objects")
}

// statementPrincipals reads one statement and returns its principals when it allows kms:Sign, and none
// otherwise. Every statement is checked for its shape, Deny ones too.
func statementPrincipals(st map[string]any) ([]handoff.Principal, error) {
	for name := range st {
		switch name {
		case "Sid", "Effect", "Principal", "NotPrincipal", "Action", "NotAction", "Resource", "NotResource", "Condition":
		default:
			return nil, policyFault("has a statement member that this reader does not know")
		}
	}
	if sid, present := st["Sid"]; present {
		if s, ok := sid.(string); !ok || len(s) > MaxTextLength {
			return nil, policyFault("has a Sid that is not a short string")
		}
	}
	effect, _ := st["Effect"].(string)
	if effect != "Allow" && effect != "Deny" {
		return nil, policyFault("has a statement whose Effect is not Allow or Deny")
	}
	action, hasAction := st["Action"]
	notAction, hasNotAction := st["NotAction"]
	if hasAction == hasNotAction {
		return nil, policyFault("has a statement with both or neither of Action and NotAction")
	}
	var patterns []string
	var err error
	if hasAction {
		patterns, err = actionList(action)
	} else {
		patterns, err = actionList(notAction)
	}
	if err != nil {
		return nil, err
	}
	matches := slices.ContainsFunc(patterns, matchesSign)
	if effect != "Allow" || matches != hasAction {
		return nil, nil
	}
	return principalsOf(st)
}

// actionList reads Action or NotAction: a string, or a list of 1 to MaxActions strings.
func actionList(v any) ([]string, error) {
	switch a := v.(type) {
	case string:
		if len(a) > MaxPatternLen {
			return nil, policyFault("has an action pattern that is too long")
		}
		return []string{a}, nil
	case []any:
		if len(a) == 0 || len(a) > MaxActions {
			return nil, policyFault("has an empty list of actions, or more than the limit")
		}
		out := make([]string, 0, len(a))
		for _, e := range a {
			s, ok := e.(string)
			if !ok || len(s) > MaxPatternLen {
				return nil, policyFault("has an action that is not a short string")
			}
			out = append(out, s)
		}
		return out, nil
	}
	return nil, policyFault("has an action that is not a string or a list of strings")
}

// matchesSign reports whether the IAM action pattern matches kms:Sign: "*" is any run of characters, "?" is
// one, and letters are compared without regard to case. The match walks the pattern once with one point to go
// back to, so a pattern of many "*" cannot take more than the product of the two lengths.
func matchesSign(pattern string) bool {
	p, t := 0, 0
	star, mark := -1, 0
	for t < len(signAction) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || foldASCII(pattern[p]) == signAction[t]):
			p++
			t++
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, t
			p++
		case star >= 0:
			mark++
			p, t = star+1, mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// foldASCII lower-cases an ASCII letter and leaves every other byte as it is. Not unicode.ToLower: that
// would read the Kelvin sign as the letter k.
func foldASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// principalsOf lists the principals of a statement that allows kms:Sign.
func principalsOf(st map[string]any) ([]handoff.Principal, error) {
	principal, hasPrincipal := st["Principal"]
	_, hasNot := st["NotPrincipal"]
	var out []handoff.Principal
	if hasPrincipal {
		ps, err := principalValue(principal)
		if err != nil {
			return nil, err
		}
		out = append(out, ps...)
	}
	if hasNot {
		out = append(out, handoff.Principal{ARN: "NotPrincipal", Kind: handoff.PrincipalWildcard})
	}
	if !hasPrincipal && !hasNot {
		out = append(out, handoff.Principal{Kind: handoff.PrincipalOther})
	}
	return out, nil
}

// principalValue reads the member Principal: "*", or an object.
func principalValue(v any) ([]handoff.Principal, error) {
	switch p := v.(type) {
	case string:
		if p != "*" {
			return nil, policyFault("has a Principal that is a string other than *")
		}
		return []handoff.Principal{{ARN: "*", Kind: handoff.PrincipalWildcard}}, nil
	case map[string]any:
		var out []handoff.Principal
		known := 0
		for _, member := range []string{"AWS", "Service", "Federated", "CanonicalUser"} {
			val, present := p[member]
			if !present {
				continue
			}
			known++
			strs, err := principalStrings(val)
			if err != nil {
				return nil, err
			}
			for _, s := range strs {
				out = append(out, classify(s, member == "AWS"))
			}
		}
		if len(p) != known || known == 0 {
			out = append(out, handoff.Principal{Kind: handoff.PrincipalOther})
		}
		return out, nil
	}
	return nil, policyFault("has a Principal that is not * or an object")
}

// principalStrings reads the value of a member of a Principal object: a string, or a list of 1 to
// MaxPrincipals strings of at most MaxTextLength bytes.
func principalStrings(v any) ([]string, error) {
	switch s := v.(type) {
	case string:
		if len(s) > MaxTextLength {
			return nil, policyFault("names a principal that is too long")
		}
		return []string{s}, nil
	case []any:
		if len(s) == 0 || len(s) > MaxPrincipals {
			return nil, policyFault("has an empty list of principals, or more than the limit")
		}
		out := make([]string, 0, len(s))
		for _, e := range s {
			str, ok := e.(string)
			if !ok || len(str) > MaxTextLength {
				return nil, policyFault("names a principal that is not a short string")
			}
			out = append(out, str)
		}
		return out, nil
	}
	return nil, policyFault("names a principal that is not a string or a list of strings")
}

// classify gives the kind of one principal string. aws is true for a member AWS, whose strings may be IAM
// ARNs; for any other member a string is a wildcard or other.
func classify(s string, aws bool) handoff.Principal {
	p := handoff.Principal{ARN: jsonset.EscapeExact(s), Kind: handoff.PrincipalOther}
	switch {
	case strings.ContainsAny(s, "*?"):
		p.Kind = handoff.PrincipalWildcard
	case !aws:
	case digits(s, 12):
		p.Kind = handoff.PrincipalRoot
	default:
		if _, kind, ok := parseIAMARN(s); ok {
			p.Kind = handoff.PrincipalKind(kind)
		}
	}
	return p
}
