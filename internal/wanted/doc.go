// Package wanted reads the wanted files of a bundle: ritueel.yaml, a delegation file, the small wanted
// root file and a card file (docs/reference/bundle.md, "The wanted files"). Each is one strict YAML file
// that a person writes on the workstation (record 0006, rule 5). The package reads untrusted bytes and
// returns either a value that was made by its own parser or an error, never a part of a value.
//
// A reader keeps the bytes of the file exactly as they were read and their SHA-256, so that a later
// ceremony can copy the file and list it by its digest (record 0005, rule 6). It never writes the bytes
// again, and a digest is of the bytes as stored.
//
// What strict means (proposed on the page, built as follows). A file is at most [MaxBytes]. It is UTF-8
// with LF line ends: no byte order mark, no carriage return, no tab, no control character, no format
// character (the bidirectional controls and the zero-width characters among them) and no U+2028 or
// U+2029, in a comment as well as in a value. It holds one document and its root is a mapping; at most
// one "---" line, before any content; no "...", no directive. It holds no anchor, no alias, no merge key,
// no tag, no null (written as null, ~ or nothing), no complex key and no key that is not a string, no key
// twice in one mapping, no more than [MaxDepth] levels and no more than [MaxNodes] nodes. An unknown member
// is an error that names it. A value has exactly the type of its member and is typed from what is written,
// and not from the Go field it would fill: a string is a string (so 2024 must be written "2024"), a
// boolean is true or false and nothing else (so yes and on are strings), an integer is plain decimal digits
// with no sign, no leading zero and at most nine digits, and no member is a float. The library that reads
// the text is go.yaml.in/yaml/v3. The package does not rely on its own strictness: it reads the document
// into a tree of nodes, refuses what is listed above by a scan of the lines and a walk of the tree, and
// fills its types from the nodes, so the library never types a value for it. The scan of the lines is
// needed for what the tree does not show: a directive, a document marker and an explicit key. The walk
// refuses a node that the library marks as tagged, and a node whose source text starts with "!": the library
// drops a bare "!" (the non-specific tag) without a mark, but it puts the start of a node that has a tag at the
// tag, so the text at the position of every node tells it. The text is not scanned for tags by hand.
//
// Every fault is an [*Error] with the path of the file, the line when there is one and a text of fixed
// words and numbers. A text that came from the file goes through [jsonset.Escape] and is cut at 40
// characters before it is put in a message, so a message is printable ASCII whatever the file held.
//
// A card file (want/cards/NAME.yaml, docs/reference/cards.md, "The card file") names one card: its serial, its
// kind, the applications that the bundle uses and the rows of other bundles that the card declares. It is read
// from the file alone: no card is read, and nothing here can reach one. Two serials are the same card when
// [SerialKey] gives one text for both, so a caller that judges a whole folder compares serials only through it.
//
// A [Settings], a [Delegation], a [Root] and a [Card] that was not made by its parser is not usable: each has
// Valid, which is false for a zero value and for one that a caller built by hand, and a package that
// takes one refuses a value that is not Valid.
//
// Nothing here follows a link. A file is read by the name it is given, through package fsx, which refuses
// a link in any element of the path, a file that is not a regular file and a file over 8 MiB. The only
// folders listed are want/roots, want/delegations and want/cards, each once, for the names in it.
package wanted
