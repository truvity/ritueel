package history

import (
	"errors"
	"io/fs"

	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/fsx"
)

// unlistedFiles looks for what the records do not cover. For each trust set that a record lists
// it lists the whole set, and a file that no record lists is [codeUnlistedInSet], also a regular
// file with a name that a desktop system writes. For each ceremony folder with a record that was
// read it lists wanted/, and a file that the record does not list is [codeUnlistedInWanted]. A
// set that no record lists is not listed: it is reported as unlisted, or as an unfinished
// ceremony, and its files would only say it again.
func (ck *checker) unlistedFiles() error {
	for _, name := range ck.setNames {
		if ck.listed[name] == nil {
			continue
		}
		// trust/<set>/ takes two of the elements of a path.
		err := ck.listTree("trust/"+name, 1, files.MaxPathElements-2, tempInSet, func(path string, e fs.DirEntry) {
			switch {
			case ck.rd.isListed(path):
			case e.IsDir():
				ck.col.add(codeUnlistedInSet, path, "a folder deeper than the check looks into; no record lists it")
			default:
				ck.col.add(codeUnlistedInSet, path, "no record lists it ("+kindOf(e)+")")
			}
		})
		if err != nil {
			return err
		}
	}
	for _, folder := range ck.wantedDirs {
		dir := "history/" + folder + "/" + files.WantedDir
		err := ck.listTree(dir, 1, files.MaxPathElements, tempInWanted, func(path string, e fs.DirEntry) {
			if ck.rd.isListed(path) {
				return
			}
			detail := "its record does not list it (" + kindOf(e) + ")"
			if e.IsDir() {
				detail = "a folder deeper than the check looks into; its record does not list it"
			}
			ck.col.add(codeUnlistedInWanted, path, detail)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// tempRule says what a leftover temporary name is in the folder that is walked.
type tempRule struct {
	code   Code
	detail string
}

var (
	// tempInSet: a trust set is written whole and renamed into place (record 0006, rule 41), so a
	// finished set holds no temporary name.
	tempInSet = tempRule{codeTempInSet, "a leftover temporary name inside a trust set; a finished set holds none (record 0006, rule 41); no record lists it"}
	// tempInWanted: the folder of copies can hold what a stopped write left.
	tempInWanted = tempRule{UnexpectedFile, "a leftover temporary name; it is skipped (record 0006, rule 45)"}
)

// listTree lists dir and, level by level, the folders below it, and calls visit for each entry that
// is not a folder. A folder at the last level (level == last) is not entered and is given to
// visit instead. A name that is a leftover temporary name, or breaks the rule for names, is said
// by [checker.plainName] and not visited. The walk is bounded: each folder by fsx.MaxDirEntries,
// the depth by last, and the number of names looked at in all by [MaxWalkEntries].
func (ck *checker) listTree(dir string, level, last int, temp tempRule, visit func(path string, e fs.DirEntry)) error {
	if err := ck.ctx.Err(); err != nil {
		return err
	}
	ents, err := fsx.ReadDir(ck.fsys, dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range ents {
		if err := ck.count(1); err != nil {
			return err
		}
		name := e.Name()
		if !ck.plainNameIn(dir, name, temp.code, temp.detail) {
			continue
		}
		path := dir + "/" + name
		if e.IsDir() && level < last {
			if err := ck.listTree(path, level+1, last, temp, visit); err != nil {
				return err
			}
			continue
		}
		visit(path, e)
	}
	return nil
}
