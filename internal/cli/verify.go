package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	ucli "github.com/urfave/cli/v3"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/rootlist"
	"ritueel.id/ritueel/internal/strictjson"
)

// verifySpec is the word verify. Its second words are the host's side of each trust file; only
// root-list is built.
var verifySpec = spec{
	name:  "verify",
	usage: "check a trust file the way the host that holds it does",
	subs: []spec{{
		name:      "root-list",
		usage:     "check a signed root list, and a CA bundle, against the list the host holds or its initial pins",
		argsUsage: "FILE (--held FILE | --pin SHA256... [--min-sequence N]) [--ca-bundle FILE]",
		flags:     verifyRootListFlags,
		run:       runVerifyRootList,
	}},
}

// The names of the flags of verify root-list. "ca-bundle" is the proposed spelling of docs/reference/cli.md
// (the arguments of verify root-list are marked Proposed there) and is written in this one place.
const (
	flagHeld     = "held"
	flagPin      = "pin"
	flagCABundle = "ca-bundle"
	flagMinSeq   = "min-sequence"
)

func verifyRootListFlags() []ucli.Flag {
	return []ucli.Flag{
		&ucli.StringFlag{Name: flagHeld, Usage: "the list the host holds: its root-list.json is `FILE`"},
		&ucli.StringSliceFlag{Name: flagPin, Usage: "an initial pin: the `SHA256` of a root key's SubjectPublicKeyInfo, 64 lower-case hexadecimal digits; repeat for each root key"},
		&ucli.StringFlag{Name: flagMinSeq, Usage: "with --pin only: refuse a list whose sequence is lower than `N`, an integer of at least 1 (a host with a held list has its sequence)"},
		&ucli.StringFlag{Name: flagCABundle, Usage: "also check the CA bundle `FILE` against the list"},
	}
}

// runVerifyRootList runs the eleven checks of docs/reference/root-list.md on the root list FILE and
// the root-list.jws beside it, against the list the host holds or its initial pins, and then the CA
// bundle when one is named. It signs and writes nothing.
//
// What a user's file is: every file is read through a reader rooted at the file's folder (see
// readInput), so a link, a FIFO, a device and a folder are never read, and nothing longer than
// fsx.MaxReadSize is read at all. What is wrong with the list is a refusal (exit code 3); what
// stops the command from reading its input is a failure (exit code 1); a command line that does
// not say what the page asks is a usage error (exit code 2).
func runVerifyRootList(_ context.Context, c *Call) (*Result, error) {
	if len(c.Args) != 1 {
		return nil, UsageError{Msg: "verify root-list takes exactly one FILE, the root-list.json to check"}
	}
	file := c.Args[0]
	stem, ok := strings.CutSuffix(file, ".json")
	if !ok {
		// The page says "the signature is the .jws file beside it" and not how a file that does not
		// end in .json finds its signature; no name is guessed.
		return nil, UsageError{Msg: "FILE must be a root-list.json, a name that ends in .json: its signature is the .jws file beside it"}
	}
	sigFile := stem + ".jws"

	heldGiven, pinsGiven := c.FlagSet(flagHeld), len(c.FlagStrings(flagPin)) > 0
	switch {
	case heldGiven && pinsGiven:
		return nil, UsageError{Msg: "give the list the host holds (--held) or its initial pins (--pin), not both"}
	case !heldGiven && !pinsGiven:
		return nil, UsageError{Msg: "give the list the host holds (--held FILE) or its initial pins (--pin SHA256, once for each)"}
	}
	if heldGiven && c.FlagString(flagHeld) == "" {
		return nil, UsageError{Msg: "--held needs a file name"}
	}
	if c.FlagSet(flagCABundle) && c.FlagString(flagCABundle) == "" {
		return nil, UsageError{Msg: "--ca-bundle needs a file name"}
	}

	minSeq, err := minSequenceOf(c, heldGiven)
	if err != nil {
		return nil, err
	}

	var trust rootlist.Trust
	var held *rootlist.Held
	if heldGiven {
		data, err := readHostInput(c.FlagString(flagHeld))
		if err != nil {
			return nil, fmt.Errorf("cannot read the held list: %w", err)
		}
		if held, err = rootlist.ParseHeld(data); err != nil {
			return nil, fmt.Errorf("the held list cannot be used: %w", err)
		}
		trust = rootlist.HeldTrust(held)
	} else {
		var err error
		if trust, err = rootlist.PinTrust(c.FlagStrings(flagPin)); err != nil {
			return nil, UsageError{Msg: "--pin: " + err.Error()}
		}
		if minSeq > 0 {
			if trust, err = trust.WithMinSequence(minSeq); err != nil {
				return nil, UsageError{Msg: "--min-sequence: " + err.Error()}
			}
		}
	}

	cand, wrong, err := readCandidate(file, sigFile)
	if err != nil {
		return nil, err
	}
	// The CA bundle follows the rule of the candidate's files: missing or unreadable is exit code 1,
	// there and not acceptable (bundleWrong) is a refusal with ca-bundle-mismatch, given when the
	// list has been accepted and the bundle is judged. With two faults at once, a file that could
	// not be read ends the run first (here, before any check), whichever file it is; two files that
	// are there and wrong are judged in the order of the checks, the list's malformed first.
	var bundle []byte
	var bundleName, bundleWrong string
	if c.FlagSet(flagCABundle) {
		var rerr error
		bundleName = filepath.Base(c.FlagString(flagCABundle))
		if bundle, bundleWrong, rerr = readInput(c.FlagString(flagCABundle)); rerr != nil {
			return nil, fmt.Errorf("cannot read the CA bundle: %w", rerr)
		}
	}

	now := c.Env.Now()
	warnings := rootlist.CheckHeld(held, now)
	refuse := func(reason rootlist.Reason, msg string) error {
		return WithWarnings(Refusal{Reasons: []string{string(reason)}, Msg: msg}, warnings...)
	}

	if wrong != "" {
		// A file of the candidate is there and is not acceptable: no check can run on it, and the
		// code of such a file is malformed (the form rules of checks 1 and 5).
		return nil, refuse(rootlist.Malformed, fmt.Sprintf("refused: %s (%s)", rootlist.Malformed, wrong))
	}
	v := rootlist.Verify(cand, trust, now)
	if !v.Accepted {
		return nil, refuse(v.Reason, fmt.Sprintf("refused: %s (check %d: %s)", v.Reason, v.Check, v.Detail))
	}
	if c.FlagSet(flagCABundle) {
		if bundleWrong != "" {
			return nil, refuse(rootlist.CABundleMismatch, fmt.Sprintf("refused: %s (%s)", rootlist.CABundleMismatch, bundleWrong))
		}
		if bv := rootlist.VerifyCABundle(bundle, v.List); !bv.Accepted {
			return nil, refuse(bv.Reason, fmt.Sprintf("refused: %s (%s)", bv.Reason, bv.Detail))
		}
	}

	l := v.List
	keys := "root keys"
	if len(l.Roots) == 1 {
		keys = "root key"
	}
	checked := []CheckedFile{
		{Name: filepath.Base(file), SHA256: digest(cand.JSON)},
		{Name: filepath.Base(sigFile), SHA256: digest(cand.JWS)},
	}
	if c.FlagSet(flagCABundle) {
		// The bundle was judged and accepted: its digest is of the bytes that were judged.
		checked = append(checked, CheckedFile{Name: bundleName, SHA256: digest(bundle)})
	}
	var text strings.Builder
	fmt.Fprintf(&text, "accepted: sequence %d, %d %s, expires %s\n", l.Sequence, len(l.Roots), keys, l.ExpiresAt.Format(rootlist.TimeLayout))
	if v.Again {
		text.WriteString(textAgain + "\n")
	}
	for _, f := range checked {
		// The form that sha256sum -c reads: the digest, two spaces, the name. A name that needs
		// the escapes of that form (a backslash, a line feed) is refused by the reader of files.
		fmt.Fprintf(&text, "%s  %s\n", f.SHA256, f.Name)
	}
	return &Result{Warnings: warnings, Checked: checked, Again: v.Again, Text: text.String()}, nil
}

// textAgain is the line of the text output for the held list coming again, written after the line
// "accepted". It is the one place of the wording.
const textAgain = "again: the list the host holds, byte for byte; install nothing"

// digest is the SHA-256 of the bytes that were read and checked, in lower-case hexadecimal.
func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// minSequenceOf reads --min-sequence: a decimal integer of at least 1 and at most the largest
// integer of the JSON rules, written plainly (digits, no sign, no leading zero), and only with
// --pin. It is 0 when the flag was not given. Every fault is a usage error.
func minSequenceOf(c *Call, heldGiven bool) (int64, error) {
	if !c.FlagSet(flagMinSeq) {
		return 0, nil
	}
	if heldGiven {
		return 0, UsageError{Msg: "--min-sequence goes with --pin; a host that holds a list has its sequence"}
	}
	text := c.FlagString(flagMinSeq)
	plain := text != "" && text[0] != '0'
	for i := 0; i < len(text); i++ {
		if text[i] < '0' || text[i] > '9' {
			plain = false
		}
	}
	n, err := strconv.ParseInt(text, 10, 64)
	if !plain || err != nil || n < 1 || n > strictjson.MaxSafeInt {
		return 0, UsageError{Msg: fmt.Sprintf("--min-sequence must be an integer from 1 to %d, written in digits", int64(strictjson.MaxSafeInt))}
	}
	return n, nil
}

// readCandidate reads the two files of the candidate, FILE and the .jws beside it, with one rule:
// not there is failed, there and wrong is refused (docs/reference/root-list.md, the command).
//   - A file that is missing, or cannot be read (no permission, an I/O error, a folder that cannot
//     be opened), is an error: the command could not check, exit code 1. When one of the two is
//     like that, it is the error returned, whatever the other is.
//   - A file that is there and is not acceptable (a symbolic link, a FIFO, a device, a folder, a
//     file longer than the reader holds) gives wrong, the text that says which: the command
//     refuses with malformed, exit code 3. The bytes are not used then.
func readCandidate(file, sigFile string) (cand rootlist.Signed, wrong string, err error) {
	data, wrongJSON, err := readInput(file)
	if err != nil {
		return cand, "", fmt.Errorf("cannot read the root list: %w", err)
	}
	sig, wrongSig, err := readInput(sigFile)
	if err != nil {
		return cand, "", fmt.Errorf("cannot read the signature, the .jws beside the list: %w", err)
	}
	wrong = wrongJSON
	if wrong == "" {
		wrong = wrongSig
	}
	return rootlist.Signed{JSON: data, JWS: sig}, wrong, nil
}

// readHostInput reads the list the host holds, --held: every fault of reading, the file that is
// there and is not acceptable included, is an error and exit code 1.
func readHostInput(path string) ([]byte, error) {
	data, wrong, err := readInput(path)
	if err != nil {
		return nil, err
	}
	if wrong != "" {
		return nil, fmt.Errorf("%s: %s", path, wrong)
	}
	return data, nil
}

// readInput reads a file that the user named: the whole of it, as it is. It is the reader of
// package fsx, rooted at the folder that holds the file: the folder is opened once, the file is
// looked up in it by its name alone, and the reader refuses a symbolic link at the file, opens a
// FIFO or a device without waiting or touching it and then refuses it, reads only a regular file,
// and reads at most fsx.MaxReadSize bytes (never a part of a longer file). The name of the file
// must follow the rule of fsx for names (ASCII letters, digits, dot, hyphen and underscore, at
// most 255 bytes), and the folder, if it is a link, is refused as the last element of a root is.
//
// The result tells "there and wrong" from "missing or unreadable" by the kind of the error of the
// reader, never by its text: errors.Is with fsx.ErrLink, fsx.ErrNotRegular and fsx.ErrTooLarge,
// which fsx wraps for exactly these three faults of a file that it found, give wrong (the text
// says which, with the name of the file); every other error is err, among them fs.ErrNotExist and
// fs.ErrPermission, a name that breaks the rule of fsx, and a failure to open the folder (OpenFS,
// where a link is the folder and not the file).
func readInput(path string) (data []byte, wrong string, err error) {
	dir, name := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	root, err := fsx.OpenFS(dir)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = root.Close() }() // a read-only handle: its close says nothing the read did not
	data, err = fsx.ReadFile(root, name)
	switch {
	case err == nil:
		return data, "", nil
	case errors.Is(err, fsx.ErrLink):
		return nil, name + " is a symbolic link", nil
	case errors.Is(err, fsx.ErrNotRegular):
		return nil, name + " is not a regular file", nil
	case errors.Is(err, fsx.ErrTooLarge):
		return nil, fmt.Sprintf("%s is longer than %d bytes", name, fsx.MaxReadSize), nil
	}
	return nil, "", fmt.Errorf("%s: %w", path, err) // finish shows it as printable ASCII
}
