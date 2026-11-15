// Package cards reads the whole folder of wanted card files of a bundle, want/cards, and finds what only
// the whole set shows. It is the one place that judges the set: [Inspect] gives the cards that passed their
// reader and the findings about the files, and [Check] is [Inspect] for apply (record 0005, rule 19: a
// wanted file that fails its check stops apply before anything is written).
//
// One file is judged by [wanted.ParseCard], and nothing else reads a card file. The set check is: two
// files that name one card (the same serial number, whatever the kinds) are a finding, because a serial
// identifies the card in every later check and is never reused for another role (record 0003, rule 5).
//
// The package reads no card. It lists want/cards once and reads each file there once, through package
// fsx, and reads no other path of the bundle. It starts no program and opens no device: its imports are
// the standard library and the packages that read a bundle, and a test holds that list.
//
// A fault of a file (its text, or its size over the limit of a read) is a finding, so that a later status
// can show the other cards. A fault of the check itself (the folder cannot be listed, a file cannot be
// read, more than [wanted.MaxCards] files, a canceled context) is an error and no report: a check that
// cannot run is not a pass. A zero [Report] is not usable and is never clean.
package cards
