package openpgpapp

import (
	"sync"
	"time"
)

// The limits and defaults of a session.
const (
	// MaxResponse is the most bytes of one response that the layer collects, over any number of
	// GET RESPONSE commands. The largest objects of the card are a certificate of 2048 bytes and an
	// answer of a little over 3000 bytes in extended length; this is above both (OpenPGP smart card
	// application 3.4.1, sections 7.2.6 and 4.4.1; the vendor's pages on attestation and on the 5.2.3
	// enhancements).
	MaxResponse = 4096
	// MaxBudget is the longest budget that an option may name. It is the longest that a reader is
	// asked to wait for one exchange.
	MaxBudget = 90 * time.Second
	// DefaultBudget is the budget of an ordinary command when the options name none.
	DefaultBudget = 5 * time.Second
	// DefaultWaitBudget is the budget of a command that may wait for a person when the options
	// name none.
	DefaultWaitBudget = 30 * time.Second

	// maxContinuations is the most GET RESPONSE commands for one answer, apart from the size cap, so
	// that a card that announces more data and sends none ends the exchange.
	maxContinuations = 64
	// chainBlock is the most data bytes of one block of a chain (section 7.4).
	chainBlock = 255
	// chainingBit is the bit of the class byte that says that the command is not the last of a chain.
	chainingBit = 0x10
	// extendedOverhead is the largest header of an extended command: four bytes, three of Lc, two of Le.
	extendedOverhead = 9
)

// Options are the settings of a [Session]. The zero value is a session with the default budgets that
// may send every command of the allowlist.
type Options struct {
	// Budget is the time one ordinary exchange may take. Zero means [DefaultBudget].
	Budget time.Duration
	// WaitBudget is the time that a command may take when it can wait for a person to touch the
	// key, or take the card long. Zero means [DefaultWaitBudget].
	WaitBudget time.Duration
	// ReadOnly makes a session that sends only the commands that the allowlist marks as allowed in
	// a read-only session: no write, no PIN, no use of a key.
	ReadOnly bool
}

// Session owns a [Transport] and sends commands through it. It is the one holder of the state of an
// exchange with a card: whether the exchange is still known (not dead) and whether it may change the
// card at all (read-only). It is safe to call from several goroutines; calls run one at a time, as the
// card takes one command at a time.
type Session struct {
	mu         sync.Mutex
	t          Transport
	budget     time.Duration
	waitBudget time.Duration
	readOnly   bool
	table      []commandSpec
	// extData is the most data bytes of an extended command that the card takes, or 0 while the card
	// is not known to take extended lengths at all. A later piece sets it from the card's own
	// description of its limits (the extended length information and the historical bytes).
	extData int
	dead    bool
	closed  bool
	// selected is set when select-application has succeeded and cleared when the session dies or a
	// selection fails. While it is not set, send sends nothing else.
	selected bool
	// afterJudge is a hook that send calls between judging a command and encoding it; only tests set it.
	afterJudge func()
}

// The names of the two rows that send itself needs to know.
const (
	nameSelectApplication = "select-application"
	nameGetResponse       = "get-response"
)

// NewSession returns a session on the transport. It does not touch the transport: powering the card
// and selecting the application are for the piece that opens the card. The options are checked, and
// the transport must not be nil.
func NewSession(t Transport, o Options) (*Session, error) {
	if t == nil {
		return nil, ErrNoTransport
	}
	if o.Budget < 0 || o.Budget > MaxBudget || o.WaitBudget < 0 || o.WaitBudget > MaxBudget {
		return nil, ErrBadOptions
	}
	if o.Budget == 0 {
		o.Budget = DefaultBudget
	}
	if o.WaitBudget == 0 {
		o.WaitBudget = DefaultWaitBudget
	}
	return &Session{t: t, budget: o.Budget, waitBudget: o.WaitBudget, readOnly: o.ReadOnly, table: allowlist}, nil
}

// ReadOnly reports whether the session is read-only.
func (s *Session) ReadOnly() bool { return s.readOnly }

// Dead reports whether an exchange failed: after it every command is refused.
func (s *Session) Dead() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dead
}

// Close releases the transport. It is the one call that reaches the transport of a dead session,
// because the reader must be given back; a second Close does nothing and returns nil. Every command
// after it is [ErrSessionClosed].
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.t.Close()
}

// allowExtended tells the session that the card takes extended-length commands of up to maxCommand
// bytes in all (the largest command that the card's extended length information gives). Until it is
// called, nothing is sent in the extended form. A command is sent extended only when this and the
// transport both allow it.
func (s *Session) allowExtended(maxCommand int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.extData = max(0, maxCommand-extendedOverhead)
}

// powerOn powers the card through the transport. The power cycle ends the selection, so the session
// forgets it. A transport error ends the session.
func (s *Session) powerOn() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return nil, err
	}
	s.selected = false
	atr, err := s.t.PowerOn(s.budget)
	if err != nil {
		s.dead = true
		return nil, &LostError{Op: "power-on", Err: err, cause: err}
	}
	return atr, nil
}

// powerOff powers the card off through the transport, and the session forgets the selection.
func (s *Session) powerOff() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return err
	}
	s.selected = false
	if err := s.t.PowerOff(s.budget); err != nil {
		s.dead = true
		return &LostError{Op: "power-off", Err: err, cause: err}
	}
	return nil
}

// usable is the error that stops a call on a session that is closed or dead, or nil.
func (s *Session) usable() error {
	switch {
	case s.closed:
		return ErrSessionClosed
	case s.dead:
		return ErrSessionDead
	}
	return nil
}
