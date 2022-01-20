package socks

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/hupe1980/golog"
)

type Socks4DialerOptions struct {
	UserID string

	// Logger specifies an optional logger.
	// If nil, logging is done via the log package's standard logger.
	Logger golog.Logger

	// ProxyDialer specifies the optional dialer for
	// establishing the transport connection.
	ProxyDialer Dialer
}

type Socks4Dialer struct {
	*logger
	cmd          Command
	proxyNetwork string // network between a proxy server and a client
	proxyAddress string // proxy server address
	proxyDialer  Dialer
	userID       string
}

// NewSocks4Dialer returns a new Socks4Dialer that dials through the provided
// proxy server's network and address.
func NewSocks4Dialer(network, address string, optFns ...func(*Socks4DialerOptions)) *Socks4Dialer {
	options := Socks4DialerOptions{
		Logger:      golog.NewGoLogger(golog.INFO, log.Default()),
		ProxyDialer: &net.Dialer{},
	}

	for _, fn := range optFns {
		fn(&options)
	}

	return &Socks4Dialer{
		logger:       &logger{options.Logger},
		cmd:          ConnectCommand,
		proxyNetwork: network,
		proxyAddress: address,
		proxyDialer:  options.ProxyDialer,
		userID:       options.UserID,
	}
}

func (d *Socks4Dialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *Socks4Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := d.proxyDialer.DialContext(ctx, d.proxyNetwork, d.proxyAddress)
	if err != nil {
		return nil, err
	}

	socksConn := NewConn(conn)

	if err := socksConn.Write(&Socks4Request{
		CMD:    ConnectCommand,
		Addr:   addr,
		UserID: d.userID,
	}); err != nil {
		return nil, err
	}

	resp := &Socks4Response{}
	if err := socksConn.Read(resp); err != nil {
		return nil, err
	}

	if resp.Status != Socks4StatusGranted {
		return nil, fmt.Errorf("socks error: %v", resp.Status)
	}

	return conn, nil
}

type Socks5DialerOptions struct {
	// Logger specifies an optional logger.
	// If nil, logging is done via the log package's standard logger.
	Logger golog.Logger

	// ProxyDialer specifies the optional dialer for
	// establishing the transport connection.
	ProxyDialer Dialer

	// AuthMethods specifies the list of request authentication
	// methods.
	// If empty, SOCKS client requests only AuthMethodNotRequired.
	AuthMethods []AuthMethod

	// Authenticate specifies the optional authentication
	// function. It must be non-nil when AuthMethods is not empty.
	// It must return an error when the authentication is failed.
	Authenticate AuthenticateFunc
}

type Socks5Dialer struct {
	*logger
	cmd          Command
	proxyNetwork string // network between a proxy server and a client
	proxyAddress string // proxy server address
	proxyDialer  Dialer
	authMethods  []AuthMethod
	authenticate AuthenticateFunc
}

// NewSocks5Dialer returns a new Socks5Dialer that dials through the provided
// proxy server's network and address.
func NewSocks5Dialer(network, address string, optFns ...func(*Socks5DialerOptions)) *Socks5Dialer {
	options := Socks5DialerOptions{
		Logger:      golog.NewGoLogger(golog.INFO, log.Default()),
		ProxyDialer: &net.Dialer{},
		AuthMethods: []AuthMethod{AuthMethodNotRequired},
	}

	for _, fn := range optFns {
		fn(&options)
	}

	return &Socks5Dialer{
		logger:       &logger{options.Logger},
		cmd:          ConnectCommand,
		proxyNetwork: network,
		proxyAddress: address,
		proxyDialer:  options.ProxyDialer,
		authMethods:  options.AuthMethods,
		authenticate: options.Authenticate,
	}
}

func (d *Socks5Dialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *Socks5Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := d.proxyDialer.DialContext(ctx, d.proxyNetwork, d.proxyAddress)
	if err != nil {
		return nil, err
	}

	socksConn := NewConn(conn)

	if err := socksConn.Write(&MethodSelectRequest{
		Methods: d.authMethods,
	}); err != nil {
		return nil, err
	}

	methodSelectResp := &MethodSelectResponse{}
	if err := socksConn.Read(methodSelectResp); err != nil {
		return nil, err
	}

	// If the selected METHOD is X'FF', none of the methods listed by the
	// client are acceptable, and the client MUST close the connection.
	if methodSelectResp.Method == AuthMethodNoAcceptableMethods {
		_ = conn.Close()
		return nil, errors.New("no authentication method accepted")
	}

	if d.authenticate != nil {
		if err := d.authenticate(ctx, socksConn, methodSelectResp.Method); err != nil {
			return nil, err
		}
	}

	if err := socksConn.Write(&Socks5Request{
		CMD:  ConnectCommand,
		Addr: addr,
	}); err != nil {
		return nil, err
	}

	resp := &Socks5Response{}
	if err := socksConn.Read(resp); err != nil {
		return nil, err
	}

	if resp.Status != Socks5StatusGranted {
		return nil, fmt.Errorf("socks error: %v", resp.Status)
	}

	return conn, nil
}
