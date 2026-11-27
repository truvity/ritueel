package openpgpapp

import (
	"errors"
	"fmt"
	"time"

	"ritueel.id/ritueel/internal/smartcard/apdu"
)

// send sends one command and returns the data of the answer. It is the one function through which
// every command of the layer goes.
//
// First the command is looked up in the allowlist of the session: a command that no row matches is
// [ErrNotAllowed], and one that a read-only session may not send is [ErrReadOnly]; in both nothing is
// sent and the session stays alive. Then the command is sent in the short form, or in the extended
// form when it needs it and both the transport and the card take it, or as a chain of blocks of at
// most 255 bytes when its data is more than one command carries and the extended form is not
// available. An answer 61xx is followed with GET RESPONSE, with the count the card announced, until
// the answer ends in 9000; the data of all the answers is joined, up to [MaxResponse]. Every other
// status word is final: it comes back as a [*StatusError]. There is no retry of any kind, and a 6Cxx
// word is a status word like the others.
//
// Until select-application has succeeded, every other command is [ErrNotSelected]. Once an answer
// began with 61xx the card has run the command, so any ending but success (an error status to GET
// RESPONSE, the size cap, too many rounds) is a lost exchange whose cause names get-response, never a
// refusal of the command. A block of a chain that the card refuses is a lost exchange too, because the
// card then holds a partial chain.
//
// An error from the transport, a panic of the transport, an answer with no status word, or an answer
// longer than the form can carry ends the exchange in an unknown state: the session is dead, the call returns a [*LostError] that
// says whether the command changes the card, and every later call returns [ErrSessionDead] without
// touching the transport.
//
// The bytes of a command that holds a secret are overwritten as soon as the transport returns, and the
// buffers of every response that is not returned are overwritten, on every path. The data that send
// returns is a new slice that the caller owns. The command's own Data is the caller's, and is not
// changed.
func (s *Session) send(cmd apdu.Command) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.closed:
		return nil, ErrSessionClosed
	case s.dead:
		return nil, ErrSessionDead
	}
	spec, ok := lookup(s.table, cmd, false)
	if !ok {
		return nil, ErrNotAllowed
	}
	if s.readOnly && !spec.readOnly {
		return nil, fmt.Errorf("%w: %s", ErrReadOnly, spec.name)
	}
	if !s.selected && spec.name != nameSelectApplication {
		return nil, fmt.Errorf("%w: %s", ErrNotSelected, spec.name)
	}
	budget := s.budget
	if spec.mayWait {
		budget = s.waitBudget
	}
	st, out, err := s.run(spec, cmd, budget)
	if err != nil {
		return nil, err
	}
	if len(out) > MaxResponse {
		clear(out)
		return nil, s.lose(spec, ErrResponseTooLong)
	}
	continued := false
	for rounds := 0; ; {
		if st.IsSuccess() {
			if spec.name == nameSelectApplication {
				s.selected = true
			}
			return out, nil
		}
		count, more := st.MoreData()
		if !more {
			clear(out)
			if continued {
				// The card ran the command and announced its answer: this is not a refusal of it.
				return nil, s.loseOp(nameGetResponse, spec, &StatusError{Op: nameGetResponse, SW: uint16(st)})
			}
			if spec.name == nameSelectApplication {
				s.selected = false // what is selected on the card is no longer known
			}
			return nil, &StatusError{Op: spec.name, SW: uint16(st)}
		}
		continued = true
		if rounds++; rounds > maxContinuations {
			clear(out)
			return nil, s.lose(spec, ErrResponseTooLong)
		}
		getResponse := apdu.Command{CLA: 0x00, INS: 0xC0, Le: count}
		gr, ok := lookup(s.table, getResponse, true)
		if !ok {
			clear(out)
			return nil, ErrNotAllowed
		}
		var more2 []byte
		st, more2, err = s.one(gr, getResponse, false, s.budget)
		if err != nil {
			clear(out)
			return nil, s.lostFrom(spec, err)
		}
		out = append(out, more2...)
		clear(more2)
		if len(out) > MaxResponse {
			clear(out)
			return nil, s.lose(spec, ErrResponseTooLong)
		}
	}
}

// run sends the command, as a chain when its data needs one, and returns the status word and the data
// of the answer to its last block.
func (s *Session) run(spec *commandSpec, cmd apdu.Command, budget time.Duration) (apdu.Status, []byte, error) {
	extended := s.extended(cmd)
	switch {
	case len(cmd.Data) > apdu.MaxExtendedData:
		return 0, nil, apdu.ErrDataTooLong
	case len(cmd.Data) > apdu.MaxShortData && !extended:
		return s.chain(spec, cmd, budget)
	case !extended:
		cmd.Le = min(cmd.Le, apdu.MaxShortLe)
	}
	st, data, err := s.one(spec, cmd, extended, budget)
	return st, data, s.lostFrom(spec, err)
}

// extended reports whether a command goes in the extended form: it needs it (more than 255 data bytes,
// or more than 256 expected), and the transport and the card both take it, and it fits.
func (s *Session) extended(cmd apdu.Command) bool {
	if len(cmd.Data) <= apdu.MaxShortData && cmd.Le <= apdu.MaxShortLe {
		return false
	}
	return s.extData > 0 && s.t.ExtendedAPDU() && len(cmd.Data) <= s.extData && cmd.Le <= apdu.MaxExtendedLe
}

// chain sends the data in blocks of at most 255 bytes: the chaining bit of the class on every block but
// the last, each intermediate block answered by plain success, and the expected length on the last.
// An intermediate block that is answered in any other way, 61xx included, loses the session: the card
// holds a partial chain, and the [*LostError] has a [*StatusError] for its cause.
func (s *Session) chain(spec *commandSpec, cmd apdu.Command, budget time.Duration) (apdu.Status, []byte, error) {
	data := cmd.Data
	for off := 0; ; {
		n := min(chainBlock, len(data)-off)
		last := off+n == len(data)
		block := apdu.Command{CLA: cmd.CLA, INS: cmd.INS, P1: cmd.P1, P2: cmd.P2, Data: data[off : off+n]}
		b := s.budget
		if last {
			block.Le = min(cmd.Le, apdu.MaxShortLe)
			b = budget
		} else {
			block.CLA |= chainingBit
		}
		st, d, err := s.one(spec, block, false, b)
		if err != nil {
			return 0, nil, s.lostFrom(spec, err)
		}
		if last {
			return st, d, nil
		}
		clear(d)
		if !st.IsSuccess() {
			// Not plain success: a 61xx here is no invitation to fetch data. The card holds a partial
			// chain, so the exchange is lost, and its outcome is unknown for a command that changes the card.
			return 0, nil, s.lose(spec, &StatusError{Op: spec.name, SW: uint16(st)})
		}
		off += n
	}
}

// one sends one command APDU and returns the status word and a copy of the data of the answer. The raw
// answer is overwritten, and so is the encoded command when it held a secret. An error here is either
// a fault before anything was sent (the command could not be encoded) or a [lostCause]: the exchange
// failed after the command was handed to the transport.
func (s *Session) one(spec *commandSpec, cmd apdu.Command, extended bool, budget time.Duration) (apdu.Status, []byte, error) {
	enc, err := cmd.Encode(extended)
	if err != nil {
		return 0, nil, err
	}
	// The command is overwritten when this function ends, by a return or by a panic of the transport.
	// A panic also ends the exchange in an unknown state, so the session is dead before it goes on.
	returned := false
	defer func() {
		if spec.secret {
			clear(enc)
		}
		if !returned {
			s.dead, s.selected = true, false
		}
	}()
	raw, err := s.t.Transmit(enc, budget)
	returned = true
	if err != nil {
		clear(raw)
		return 0, nil, &lostCause{err: err}
	}
	// The largest answer that the form can carry: the data of the largest Le, and the status word.
	limit := apdu.MaxShortLe + 2
	if extended {
		limit = apdu.MaxExtendedLe + 2
	}
	if len(raw) > limit {
		clear(raw)
		return 0, nil, &lostCause{err: ErrResponseTooLong}
	}
	resp, err := apdu.ParseResponse(raw)
	if err != nil {
		clear(raw)
		return 0, nil, &lostCause{err: ErrMalformedResponse}
	}
	if resp.Status == apdu.StatusInstructionNotSupported || resp.Status == apdu.StatusClassNotSupported {
		// The answer of an application that does not know the command: the card may have another
		// application selected, so nothing else is sent until a new selection succeeds.
		s.selected = false
	}
	data := append([]byte(nil), resp.Data...)
	clear(raw)
	return resp.Status, data, nil
}

// lostCause marks an error of one exchange that leaves the state of the card unknown.
type lostCause struct{ err error }

func (e *lostCause) Error() string { return e.err.Error() }
func (e *lostCause) Unwrap() error { return e.err }

// lostFrom turns a [lostCause] into the error of a lost session; any other error (a fault before
// anything was sent) is returned as it is, and the session lives.
func (s *Session) lostFrom(spec *commandSpec, err error) error {
	var lc *lostCause
	if errors.As(err, &lc) {
		return s.lose(spec, lc.err)
	}
	return err
}

// lose ends the session: the exchange of the command failed for the cause, and the state of the card
// is unknown.
func (s *Session) lose(spec *commandSpec, cause error) error { return s.loseOp(spec.name, spec, cause) }

// loseOp is lose with the name of the operation that failed, which is not the command's own when the
// exchange failed in its continuation.
func (s *Session) loseOp(op string, spec *commandSpec, cause error) error {
	s.dead, s.selected = true, false
	e := &LostError{Op: op, OutcomeUnknown: spec.changes, cause: cause, secret: spec.secret}
	if !spec.secret {
		e.Err = cause
	}
	return e
}
