// Package keydir holds the rules for the key directory: the folder where a key store keeps what it
// must not leave in the bundle (record 0005, roads not taken, "Key files inside the bundle"; the
// refusal of docs/reference/cli.md, `--key-dir`). The rules hold for every key store that keeps
// anything in a directory, and they live here so that no store has a copy of them.
//
// A key directory is accepted only when it exists and is a folder, is not the bundle folder or any
// folder inside it, and is not inside the work tree of any repository that encloses the bundle. A
// key directory that is a parent of the bundle, or beside it, is accepted unless one of these
// rules refuses it (a parent that is, or lies inside, a repository that encloses the bundle is
// refused): the stick keeps `keys/<bundle>/` beside `bundles/<name>/`.
//
// [Check] judges a pair of paths and reads no file. A store that opens the folder afterwards looks
// again, with [CheckStat], and compares what it opened with the folder that was checked.
//
// [Open] checks a pair of paths, opens the folder that was checked and returns a [Dir]. A Dir says whether
// the key directory was used before ([Dir.Used]: the folder [TestOnlyFolder], a removal authorisation, or a
// key file of the naming of earlier versions), and keeps ritueel's own files in it, the removal
// authorisations ([Dir.SaveRemoval], [Dir.ReadRemoval]). Keys are not its business: a key store keeps its keys
// in a folder of its own beside these files.
//
// The package has no reason codes and no knowledge of any store. A refusal is a [*Refusal] whose
// reason is in fixed words and holds no path; a store maps it to its own error and its own code.
package keydir
