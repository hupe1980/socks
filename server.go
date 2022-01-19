package socks

import (
	"errors"
	"log"
	"net"

	"github.com/hupe1980/golog"
)

type Options struct {
	// Logger specifies an optional logger.
	// If nil, logging is done via the log package's standard logger.
	Logger golog.Logger

	Dialer Dialer

	Listener Listener

	// Ident specifies the optional ident function.
	// It must return an error when the ident is failed.
	Ident IdentFunc

	// AuthMethods specifies the list of supported authentication
	// methods.
	// If empty, SOCKS server supports AuthMethodNotRequired.
	AuthMethods []AuthMethod

	// Authenticate specifies the optional authentication
	// function. It must be non-nil when AuthMethods is not empty.
	// It must return an error when the authentication is failed.
	Authenticate AuthenticateFunc
}

type Server struct {
	*logger
	addr         string
	dialer       Dialer
	listener     Listener
	ident        IdentFunc
	authMethods  []AuthMethod
	authenticate AuthenticateFunc
}

func New(addr string, optFns ...func(*Options)) *Server {
	options := Options{
		Logger:      golog.NewGoLogger(golog.INFO, log.Default()),
		Dialer:      &net.Dialer{},
		Listener:    &net.ListenConfig{},
		AuthMethods: []AuthMethod{AuthMethodNotRequired},
	}

	for _, fn := range optFns {
		fn(&options)
	}

	return &Server{
		logger:       &logger{options.Logger},
		addr:         addr,
		dialer:       options.Dialer,
		listener:     options.Listener,
		ident:        options.Ident,
		authMethods:  options.AuthMethods,
		authenticate: options.Authenticate,
	}
}

func ListenAndServe(addr string) error {
	server := New(addr)
	return server.ListenAndServe()
}

func (s *Server) ListenAndServe() error {
	l, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}

	return s.Serve(l)
}

// Serve serves connections from a listener
func (s *Server) Serve(l net.Listener) error {
	defer func() {
		_ = l.Close()
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}

		go func() {
			if err := s.handleConnection(conn); err != nil {
				s.logErrorf("Connection error: %v", err)
			}
		}()
	}
}

func (s *Server) handleConnection(conn net.Conn) error {
	defer func() {
		_ = conn.Close()
	}()

	socksConn := NewConn(conn)

	version, err := socksConn.Peek(1)
	if err != nil {
		s.logErrorf("Failed to get version byte: %v", err)
		return err
	}

	switch Version(version[0]) {
	case Socks4Version:
		socks4Handler := &socks4Handler{
			logger: s.logger,
			dialer: s.dialer,
			conn:   socksConn,
		}

		return socks4Handler.handle()
	case Socks5Version:
		socks5Handler := &socks5Handler{
			logger:       s.logger,
			dialer:       s.dialer,
			conn:         socksConn,
			authMethods:  s.authMethods,
			authenticate: s.authenticate,
		}

		return socks5Handler.handle()
	default:
		return errors.New("unsupported socks version")
	}
}
