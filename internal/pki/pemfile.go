package pki

import (
	"bytes"
	"encoding/base64"
	"errors"
	"slices"
)

// ErrPEM is wrapped by every error of [ReadPEMFile] for a file that is not of the form of the rule:
// it is a fault of a file and not of a certificate request, so it is not an [ErrRequest], and
// [ParseRequestFile] turns it into the [ErrRequest] with the check [CheckMalformed] that it has always
// returned. A label that [ReadPEMFile] cannot write as a line is an [ErrParams] and not an ErrPEM.
var ErrPEM = errors.New("pki: PEM file refused")

// pemFault names the rule of the file that a refusal breaks. It is the coded cause that a caller turns
// into its own words: [readRequestFile] turns it into the sentence about "the request file".
type pemFault int

const (
	pemTooLong    pemFault = iota + 1 // the file is longer than MaxRequestSize
	pemNoBlock                        // the file does not start with a PEM block
	pemWrongLabel                     // the block has another label
	pemNoEOL                          // the first line is not followed by LF or CRLF
	pemNoFooter                       // there is no footer line
	pemAfter                          // something follows the footer
	pemHeaders                        // a header line stands between the markers
	pemLine                           // a line of base64 is empty or longer than 76 characters
	pemBase64                         // the lines are not the one standard base64 text of some bytes
)

// pemError is an [ErrPEM] that also holds the rule that it breaks.
type pemError struct {
	fault pemFault
	msg   string
}

func (e *pemError) Error() string { return ErrPEM.Error() + ": " + e.msg }
func (e *pemError) Unwrap() error { return ErrPEM }

// failPEM returns a refusal of a PEM file with the rule that it breaks. The text is fixed words and numbers.
func failPEM(fault pemFault, format string, args ...any) error {
	return &pemError{fault: fault, msg: sprintf(format, args...)}
}

// pemFaultOf returns the rule that an error from [ReadPEMFile] breaks, and false for any other error.
func pemFaultOf(err error) (pemFault, bool) {
	var pe *pemError
	if errors.As(err, &pe) {
		return pe.fault, true
	}
	return 0, false
}

// validPEMLabel tells whether label can stand in a marker line: one or more words of capital ASCII
// letters, separated by one space each (RFC 7468, section 2: the labels of the registered kinds).
func validPEMLabel(label string) bool {
	if label == "" || label[0] == ' ' || label[len(label)-1] == ' ' {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c >= 'A' && c <= 'Z':
		case c == ' ' && label[i-1] != ' ':
		default:
			return false
		}
	}
	return true
}

// ReadPEMFile reads a file that is one PEM block with the given label, and nothing else, and returns the
// DER inside it. It is the one reader of the strict rule that the hand-off contract gives a PEM file
// ("The request"), so that the certifier reads `<stem>.csr.pem` (the label CERTIFICATE REQUEST) and the
// requester reads `<stem>.cert.pem` (the label CERTIFICATE) by the same rule. The file is refused unless
// it is, from its first octet to its last, these lines, in this order and nothing else:
//
//   - the line -----BEGIN label-----, then one or more lines of base64, then the line
//     -----END label-----, then at most one line end;
//   - a line end is LF or CRLF, the same in the whole file;
//   - a line of base64 has 1 to 76 characters, so no line is empty, and the lines together are the
//     standard base64 text of the DER (RFC 4648, section 4, with its padding) and nothing else: no
//     space, no tab, no padding left out and no bits after the end of the data, so that one DER has one
//     text;
//   - the two marker lines are exactly that text: nothing before the first one, no space after either,
//     no header line (a line with a colon) between them, and no second block after the first;
//   - the file is at most [MaxRequestSize] octets, checked before it is decoded.
//
// It does not use the PEM reader of the standard library, which skips text before the block and blank
// lines, spaces and tabs inside it, and ignores what follows the footer. The DER is not read: that is
// for the caller. A file that breaks a rule is an error that wraps [ErrPEM]; a label that is not words
// of capital letters is an [ErrParams]. The file is copied at the top of the call. Nothing is returned
// with an error.
func ReadPEMFile(file []byte, label string) (der []byte, err error) {
	if !validPEMLabel(label) {
		return nil, fail(ErrParams, "the label of a PEM file is not words of capital ASCII letters")
	}
	if len(file) > MaxRequestSize {
		return nil, failPEM(pemTooLong, "the file is longer than %d octets", MaxRequestSize)
	}
	file, err = copyBytes(file) // read more than once: copied first
	if err != nil {
		return nil, err
	}
	begin := "-----BEGIN " + label + "-----"
	end := "-----END " + label + "-----"
	if !bytes.HasPrefix(file, []byte("-----BEGIN ")) {
		return nil, failPEM(pemNoBlock, "the file does not start with a PEM block")
	}
	if !bytes.HasPrefix(file, []byte(begin)) {
		return nil, failPEM(pemWrongLabel, "the PEM block of the file does not have the label %s", label)
	}
	body := file[len(begin):]
	var eol []byte
	switch {
	case bytes.HasPrefix(body, []byte("\r\n")):
		eol = []byte("\r\n")
	case bytes.HasPrefix(body, []byte("\n")):
		eol = []byte("\n")
	default:
		return nil, failPEM(pemNoEOL, "the first line of the file is not followed by a line end of LF or CRLF")
	}
	lines := bytes.Split(body[len(eol):], eol)
	last := slices.IndexFunc(lines, func(l []byte) bool { return string(l) == end })
	if last < 0 {
		return nil, failPEM(pemNoFooter, "the file is not a PEM block")
	}
	// After the footer: nothing, or one line end (an empty last part of the split).
	if after := lines[last+1:]; len(after) > 1 || (len(after) == 1 && len(after[0]) != 0) {
		return nil, failPEM(pemAfter, "the file has something after its PEM block")
	}
	var text []byte
	for _, line := range lines[:last] {
		switch {
		case bytes.IndexByte(line, ':') >= 0:
			return nil, failPEM(pemHeaders, "the PEM block of the file has headers")
		case len(line) == 0 || len(line) > maxPEMLine:
			return nil, failPEM(pemLine, "a line of the base64 text of the file is empty or longer than %d characters", maxPEMLine)
		}
		text = append(text, line...)
	}
	der, err = base64.StdEncoding.DecodeString(string(text))
	// The text is the one text that the standard alphabet and padding write for the DER: the decoder
	// ignores a carriage return and a line feed, and accepts bits after the data, so the text is
	// written again and compared.
	if err != nil || len(der) == 0 || base64.StdEncoding.EncodeToString(der) != string(text) {
		return nil, failPEM(pemBase64, "the base64 text of the file is not the standard base64 of some bytes")
	}
	return der, nil
}
