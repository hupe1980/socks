package socks

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
)

type Socks4Dialer struct {
	cmd          Command
	proxyNetwork string // network between a proxy server and a client
	proxyAddress string // proxy server address

	// ProxyDial specifies the optional dial function for
	// establishing the transport connection.
	ProxyDial func(context.Context, string, string) (net.Conn, error)
}

// NewSocks4Dialer returns a new Socks4Dialer that dials through the provided
// proxy server's network and address.
func NewSocks4Dialer(network, address string) *Socks4Dialer {
	return &Socks4Dialer{
		cmd:          ConnectCommand,
		proxyNetwork: network,
		proxyAddress: address,
	}
}

func (d *Socks4Dialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *Socks4Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var (
		err  error
		conn net.Conn
	)

	if d.ProxyDial != nil {
		conn, err = d.ProxyDial(ctx, d.proxyNetwork, d.proxyAddress)
	} else {
		var dd net.Dialer
		conn, err = dd.DialContext(ctx, d.proxyNetwork, d.proxyAddress)
	}

	if err != nil {
		return nil, err
	}

	socksConn := &socksConn{
		reader: bufio.NewReader(conn),
		writer: conn,
	}

	if err := socksConn.write(&Socks4Request{
		Version: Socks4Version,
		CMD:     ConnectCommand,
		Addr:    addr,
	}); err != nil {
		return nil, err
	}

	resp := &Socks4Response{}
	if err := socksConn.read(resp); err != nil {
		return nil, err
	}

	if resp.Status != Socks4StatusGranted {
		return nil, fmt.Errorf("reply error: %v", resp.Status)
	}

	return conn, nil
}

type Socks5Dialer struct {
	cmd          Command
	proxyNetwork string // network between a proxy server and a client
	proxyAddress string // proxy server address

	// ProxyDial specifies the optional dial function for
	// establishing the transport connection.
	ProxyDial func(context.Context, string, string) (net.Conn, error)

	// AuthMethods specifies the list of request authentication
	// methods.
	// If empty, SOCKS client requests only AuthMethodNotRequired.
	AuthMethods []AuthMethod

	// Authenticate specifies the optional authentication
	// function. It must be non-nil when AuthMethods is not empty.
	// It must return an error when the authentication is failed.
	Authenticate func(context.Context, io.ReadWriter, AuthMethod) error
}

// NewSocks5Dialer returns a new Socks5Dialer that dials through the provided
// proxy server's network and address.
func NewSocks5Dialer(network, address string) *Socks5Dialer {
	return &Socks5Dialer{
		cmd:          ConnectCommand,
		proxyNetwork: network,
		proxyAddress: address,
		AuthMethods:  []AuthMethod{AuthMethodNotRequired},
	}
}

func (d *Socks5Dialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *Socks5Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var (
		err  error
		conn net.Conn
	)

	if d.ProxyDial != nil {
		conn, err = d.ProxyDial(ctx, d.proxyNetwork, d.proxyAddress)
	} else {
		var dd net.Dialer
		conn, err = dd.DialContext(ctx, d.proxyNetwork, d.proxyAddress)
	}

	if err != nil {
		return nil, err
	}

	socksConn := &socksConn{
		reader: bufio.NewReader(conn),
		writer: conn,
	}

	if err := socksConn.write(&MethodSelectRequest{
		Version: Socks5Version,
		Methods: d.AuthMethods,
	}); err != nil {
		return nil, err
	}

	methodSelectResp := &MethodSelectResponse{}
	if err := socksConn.read(methodSelectResp); err != nil {
		return nil, err
	}

	if methodSelectResp.Method == AuthMethodNoAcceptableMethods {
		return nil, errors.New("no acceptable authentication methods")
	}

	if err := socksConn.write(&Socks5Request{
		Version: Socks5Version,
		CMD:     ConnectCommand,
		Addr:    addr,
	}); err != nil {
		return nil, err
	}

	resp := &Socks5Response{}
	if err := socksConn.read(resp); err != nil {
		return nil, err
	}

	if resp.Status != Socks5StatusGranted {
		return nil, fmt.Errorf("reply error: %v", resp.Status)
	}

	return conn, nil
}
