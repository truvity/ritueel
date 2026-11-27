package wanted

import (
	"fmt"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"ritueel.id/ritueel/internal/fsx"
)

// UserIDsPath is the path of the wanted file of the further user IDs of the key of a person.
const UserIDsPath = "want/openpgp.yaml"

// The limits of the user IDs file. The name is at most 64 characters and the address at most 254, so a whole
// user ID, "name <address>", is at most 323 bytes, under the 1024 bytes that a user ID may have.
const (
	// MaxUserIDs is the most entries of user_ids.
	MaxUserIDs = 16
	// MaxActiveUserIDs is the most entries of user_ids that do not retire a user ID.
	MaxActiveUserIDs = 8
)

var (
	userIDsMembers = []member{
		{name: "version", required: true},
		{name: "user_ids"},
	}
	userIDMembers = []member{
		{name: "name", required: true},
		{name: "address", required: true},
		{name: "retire"},
	}
)

// UserID is one entry of user_ids: a user ID to add, or with Retire a user ID to retire.
type UserID struct {
	// Name follows the form of person.name.
	Name string
	// Address is one bare address in printable ASCII with exactly one "@".
	Address string
	// Retire is true to retire the user ID, whose reason is "no longer valid". A line that is deleted retires
	// nothing (record 0005, rule 5).
	Retire bool
}

// UserIDs is the file want/openpgp.yaml as it was read. The person of ritueel.yaml is always the one primary
// user ID of the key and is not written here: an entry adds a further user ID, or retires one. Only
// [ParseUserIDs] and [LoadUserIDs] make a usable one: see [UserIDs.Valid].
type UserIDs struct {
	// File is the file as stored, with its bytes and digest.
	File File

	entries []UserID
	made    bool
}

// Valid reports whether u was made by [ParseUserIDs] or [LoadUserIDs]. It is false for a nil UserIDs and for the
// zero value.
func (u *UserIDs) Valid() bool { return u != nil && u.made }

// Entries returns a copy of the entries, in the order written.
func (u *UserIDs) Entries() []UserID {
	if u == nil {
		return nil
	}
	return slices.Clone(u.entries)
}

// LoadUserIDs reads want/openpgp.yaml through package fsx and parses it. A file that does not exist gives an
// error that wraps fs.ErrNotExist: the file is optional, and the caller decides what a missing one means.
func LoadUserIDs(fsys fsx.FS) (*UserIDs, error) {
	data, err := readFile(fsys, UserIDsPath)
	if err != nil {
		return nil, err
	}
	return ParseUserIDs(data)
}

// ParseUserIDs reads the bytes of want/openpgp.yaml: version 1 and user_ids, at most [MaxUserIDs] entries of
// name, address and the optional retire, of which at most [MaxActiveUserIDs] do not retire. No user ID is there
// twice, whatever the case of its name and address. What only the person's own user ID decides (that it is not written or retired
// here) is judged by [CheckPersonal], which knows ritueel.yaml.
func ParseUserIDs(data []byte) (*UserIDs, error) {
	d, err := read(UserIDsPath, data)
	if err != nil {
		return nil, err
	}
	top, err := d.mappingOf(d.root, "", userIDsMembers)
	if err != nil {
		return nil, err
	}
	if _, err := top.version(); err != nil {
		return nil, err
	}
	u := &UserIDs{File: d.file}
	if top.has("user_ids") {
		if u.entries, err = top.userIDs(); err != nil {
			return nil, err
		}
	}
	u.made = true
	return u, nil
}

// userIDs reads the member user_ids. The length is checked before the first entry is read.
func (m *mapping) userIDs() ([]UserID, error) {
	v := m.val["user_ids"]
	if v.Kind != yaml.SequenceNode {
		return nil, m.d.fail(v, "user_ids must be a list")
	}
	if len(v.Content) > MaxUserIDs {
		return nil, m.d.fail(v, fmt.Sprintf("user_ids must hold at most %d entries", MaxUserIDs))
	}
	out := make([]UserID, 0, len(v.Content))
	active := 0
	for i, e := range v.Content {
		at := fmt.Sprintf("user_ids[%d]", i+1)
		u, err := m.userID(e, at)
		if err != nil {
			return nil, err
		}
		if slices.ContainsFunc(out, func(p UserID) bool { return sameUserID(p, u) }) {
			return nil, m.d.fail(e, at+" is a user ID that an earlier entry has: write it once")
		}
		if !u.Retire {
			if active++; active > MaxActiveUserIDs {
				return nil, m.d.fail(e, fmt.Sprintf("user_ids holds more than %d user IDs that are not retired", MaxActiveUserIDs))
			}
		}
		out = append(out, u)
	}
	return out, nil
}

// userID reads one entry of user_ids; at names it in a message.
func (m *mapping) userID(e *yaml.Node, at string) (UserID, error) {
	um, err := m.d.mappingOf(e, at, userIDMembers)
	if err != nil {
		return UserID{}, err
	}
	var u UserID
	if u.Name, err = um.str("name"); err != nil {
		return UserID{}, err
	}
	if why := personNameProblem(u.Name); why != "" {
		return UserID{}, um.fail("name", at+".name "+why)
	}
	if u.Address, err = um.str("address"); err != nil {
		return UserID{}, err
	}
	if why := addressProblem(u.Address); why != "" {
		return UserID{}, um.fail("address", at+".address "+why)
	}
	if um.has("retire") {
		if u.Retire, err = um.boolean("retire"); err != nil {
			return UserID{}, err
		}
	}
	return u, nil
}

// sameUserID reports whether two entries are one user ID: the same name and the same address, each without
// regard to the case of its letters (both are ASCII).
func sameUserID(a, b UserID) bool {
	return strings.EqualFold(a.Name, b.Name) && strings.EqualFold(a.Address, b.Address)
}
