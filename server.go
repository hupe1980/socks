package socks

import (
	"bufio"
	"context"
	"errors"
	"log"
	"net"

	"github.com/hupe1980/golog"
)

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type Options struct {
	// Logger specifies an optional logger.
	// If nil, logging is done via the log package's standard logger.
	Logger golog.Logger

	Dialer Dialer
}

type Server struct {
	*logger
	addr   string
	dialer Dialer
}

func New(addr string, optFns ...func(*Options)) *Server {
	options := Options{
		Logger: golog.NewGoLogger(golog.INFO, log.Default()),
		Dialer: &net.Dialer{},
	}

	for _, fn := range optFns {
		fn(&options)
	}

	return &Server{
		logger: &logger{options.Logger},
		addr:   addr,
		dialer: options.Dialer,
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
			err := s.handleConnection(conn)
			s.logErrorf("Connection error: %v", err)
		}()
	}
}

func (s *Server) handleConnection(conn net.Conn) error {
	defer func() {
		_ = conn.Close()
	}()

	bufConn := bufio.NewReader(conn)

	version, err := bufConn.Peek(1)
	if err != nil {
		s.logErrorf("Failed to get version byte: %v", err)
		return err
	}

	socksConn := &socksConn{
		reader: bufConn,
		writer: conn,
	}

	switch Version(version[0]) {
	case Socks4Version:
		socks4Handler := &socks4Handler{
			logger:    s.logger,
			dialer:    s.dialer,
			socksConn: socksConn,
		}

		return socks4Handler.handle()
	case Socks5Version:
		socks5Handler := &socks5Handler{
			logger:    s.logger,
			dialer:    s.dialer,
			socksConn: socksConn,
		}

		return socks5Handler.handle()
	default:
		return errors.New("unsupported socks version")
	}
}
