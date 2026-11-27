package wanted

import (
	"slices"
	"testing"
)

// The schema of a delegation file on the page and the table of the code hold the same members, the member card
// of a person's delegation among them, with no exemption on either side.
func TestThePageListsTheCardMemberOfADelegationAsTheCodeDoes(t *testing.T) {
	blocks := pageSchemas(t)
	if len(blocks) != 2 {
		t.Fatalf("the page holds %d schema blocks, want 2", len(blocks))
	}
	delegation := blocks[1]
	if _, ok := delegation.Properties["card"]; !ok {
		t.Error("the schema of a delegation file on the page does not list card")
	}
	if !slices.Equal(keysOf(delegation.Properties), names(delegationMembers)) {
		t.Errorf("the page has the members %v, the code %v", keysOf(delegation.Properties), names(delegationMembers))
	}
	i := slices.IndexFunc(delegationMembers, func(m member) bool { return m.name == "card" })
	if i < 0 || delegationMembers[i].required || slices.Contains(delegation.Required, "card") {
		t.Errorf("card is in the table at %d, required %v, and required on the page %v", i, i >= 0 && delegationMembers[i].required, delegation.Required)
	}
}
