package wanted

import (
	"slices"
	"testing"
)

// The comparison of the delegation table with the schema of docs/reference/bundle.md leaves out the members of
// notOnThePageYet, because the page does not list them. This test keeps the exemption small and honest: it holds
// exactly the member card, which the table has and is not required, and it says what to do on the day the page
// lists the member.
func TestTheExemptionFromThePageHoldsOnlyTheCardMember(t *testing.T) {
	if !slices.Equal(notOnThePageYet, []string{"card"}) {
		t.Fatalf("notOnThePageYet is %v: only the member card is exempt until the page lists it", notOnThePageYet)
	}
	for _, name := range notOnThePageYet {
		i := slices.IndexFunc(delegationMembers, func(m member) bool { return m.name == name })
		if i < 0 {
			t.Errorf("the exempt member %s is not in the table of a delegation: delete the exemption", name)
			continue
		}
		if delegationMembers[i].required {
			t.Errorf("the exempt member %s is required: a required member must be on the page", name)
		}
	}
	// The page and the exemption must not both name the member: when the schema of a delegation file lists card,
	// delete notOnThePageYet and the slices.DeleteFunc that uses it in TestTheSchemasOnThePageAreTheTablesOfTheCode.
	blocks := pageSchemas(t)
	if len(blocks) != 2 {
		t.Fatalf("the page holds %d schema blocks, want 2", len(blocks))
	}
	for _, name := range notOnThePageYet {
		if _, listed := blocks[1].Properties[name]; listed {
			t.Errorf("the schema of a delegation file on the page lists %s: delete notOnThePageYet in drift_internal_test.go, and the DeleteFunc that uses it", name)
		}
	}
}
