package socks

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
)

type socks4Handler struct {
	*logger
	conn     *Conn
	dialer   Dialer
	listener Listener
	ident    IdentFunc
}

func (h *socks4Handler) handle() error {
	req := &Socks4Request{}
	if err := h.conn.Read(req); err != nil {
		return err
	}

	if h.ident != nil {
		if err := h.ident(context.Background(), h.conn, req); err != nil {
			return err
		}
	}

	switch req.CMD {
	case ConnectCommand:
		return h.handleConnect(req)
	case BindCommand:
		return h.handleBind(req)
	case AssociateCommand:
		fallthrough
	default:
		if err := h.conn.Write(&Socks4Response{
			Status: Socks4StatusRejected,
		}); err != nil {
			return err
		}
	}

	return nil
}

func (h *socks4Handler) handleConnect(req *Socks4Request) error {
	target, err := h.dialer.DialContext(context.Background(), "tcp", req.Addr)
	if err != nil {
		writeErr := h.conn.Write(&Socks4Response{
			Status: Socks4StatusRejected,
		})
		if writeErr != nil {
			return writeErr
		}

		return err
	}

	defer func() {
		_ = target.Close()
	}()

	if err := h.conn.Write(&Socks4Response{
		Status: Socks4StatusGranted,
		Addr:   "",
	}); err != nil {
		return err
	}

	return h.conn.Tunnel(target)
}

func (h *socks4Handler) handleBind(req *Socks4Request) error {
	listener, err := h.listener.Listen(context.Background(), "tcp", ":0") // use a free port
	if err != nil {
		writeErr := h.conn.Write(&Socks4Response{
			Status: Socks4StatusRejected,
		})
		if writeErr != nil {
			return writeErr
		}

		return err
	}

	if err = h.conn.Write(&Socks4Response{
		Status: Socks4StatusGranted,
		Addr:   listener.Addr().String(),
	}); err != nil {
		return err
	}

	conn, err := listener.Accept()
	if err != nil {
		writeErr := h.conn.Write(&Socks4Response{
			Status: Socks4StatusRejected,
			Addr:   conn.RemoteAddr().String(),
		})
		if writeErr != nil {
			return writeErr
		}

		return err
	}

	_ = listener.Close()

	// The SOCKS server checks the IP address of the originating host against
	// the value of DSTIP specified in the client's BIND request.
	if err := checkIPAddr(req.Addr, conn.RemoteAddr().String()); err != nil {
		_ = conn.Close()

		writeErr := h.conn.Write(&Socks4Response{
			Status: Socks4StatusRejected,
		})
		if writeErr != nil {
			return writeErr
		}

		return err
	}

	// The SOCKS server sends a second reply packet to the client when the
	// anticipated connection from the application server is established.
	if err := h.conn.Write(&Socks4Response{
		Status: Socks4StatusGranted,
		Addr:   "",
	}); err != nil {
		return err
	}

	return h.conn.Tunnel(conn)
}

type socks5Handler struct {
	*logger
	conn         *Conn
	dialer       Dialer
	listener     Listener
	authMethods  []AuthMethod
	authenticate AuthenticateFunc
}

func (h *socks5Handler) handle() error {
	methodSelectReq := &MethodSelectRequest{}
	if err := h.conn.Read(methodSelectReq); err != nil {
		return err
	}

	method := h.selectAuthMethod(methodSelectReq.Methods)

	if err := h.conn.Write(&MethodSelectResponse{
		Method: method,
	}); err != nil {
		return err
	}

	if method == AuthMethodNoAcceptableMethods {
		return errors.New("no supported authentication method")
	}

	if h.authenticate != nil {
		if err := h.authenticate(context.Background(), h.conn, method); err != nil {
			return err
		}
	}

	req := &Socks5Request{}
	if err := h.conn.Read(req); err != nil {
		return err
	}

	switch req.CMD {
	case ConnectCommand:
		return h.handleConnect(req)
	case BindCommand:
		return h.handleBind(req)
	case AssociateCommand:
		fallthrough
	default:
		if err := h.conn.Write(&Socks5Response{
			Status: Socks5StatusCMDNotSupported,
		}); err != nil {
			return err
		}
	}

	return nil
}

func (h *socks5Handler) selectAuthMethod(authMethods []AuthMethod) AuthMethod {
	for _, dm := range authMethods {
		for _, sm := range h.authMethods {
			if dm == sm {
				return dm
			}
		}
	}

	return AuthMethodNoAcceptableMethods
}

func (h *socks5Handler) handleConnect(req *Socks5Request) error {
	target, err := h.dialer.DialContext(context.Background(), "tcp", req.Addr)
	if err != nil {
		msg := err.Error()
		status := Socks5StatusHostUnreachable

		if strings.Contains(msg, "refused") {
			status = Socks5StatusConnectionRefused
		} else if strings.Contains(msg, "network is unreachable") {
			status = Socks5StatusNetworkUnreaachable
		}

		writeErr := h.conn.Write(&Socks5Response{
			Status: status,
		})
		if writeErr != nil {
			return writeErr
		}

		h.logErrorf("Connect to %v failed: %v", req.Addr, err)

		return err
	}

	defer func() {
		_ = target.Close()
	}()

	if err := h.conn.Write(&Socks5Response{
		Status: Socks5StatusGranted,
		// In the reply to a CONNECT, BND.PORT contains the port number that the
		// server assigned to connect to the target host, while BND.ADDR
		// contains the associated IP address.
		Addr: target.LocalAddr().String(),
	}); err != nil {
		return err
	}

	return h.conn.Tunnel(target)
}

func (h *socks5Handler) handleBind(req *Socks5Request) error {
	listener, err := h.listener.Listen(context.Background(), "tcp", ":0")
	if err != nil {
		writeErr := h.conn.Write(&Socks5Response{
			Status: Socks5StatusFailure,
		})
		if writeErr != nil {
			return writeErr
		}

		return err
	}

	if err = h.conn.Write(&Socks5Response{
		Status: Socks5StatusGranted,
		Addr:   listener.Addr().String(),
	}); err != nil {
		return err
	}

	conn, err := listener.Accept()
	if err != nil {
		writeErr := h.conn.Write(&Socks5Response{
			Status: Socks5StatusFailure,
		})
		if writeErr != nil {
			return writeErr
		}

		return err
	}

	_ = listener.Close()

	if err := checkIPAddr(req.Addr, conn.RemoteAddr().String()); err != nil {
		_ = conn.Close()

		writeErr := h.conn.Write(&Socks5Response{
			Status: Socks5StatusFailure,
		})
		if writeErr != nil {
			return writeErr
		}

		return err
	}

	if err := h.conn.Write(&Socks5Response{
		Status: Socks5StatusGranted,
		Addr:   conn.RemoteAddr().String(),
	}); err != nil {
		return err
	}

	return h.conn.Tunnel(conn)
}

func (h *socks5Handler) handleAssociate(req *Socks5Request) error {
	var lc net.ListenConfig

	udpConn, err := lc.ListenPacket(context.Background(), "udp", req.Addr)
	if err != nil {
		writeErr := h.conn.Write(&Socks5Response{
			Status: Socks5StatusFailure,
		})
		if writeErr != nil {
			return writeErr
		}

		return err
	}

	defer func() {
		_ = udpConn.Close()
	}()

	// TODO

	return nil
}

func checkIPAddr(expected, actual string) error {
	expectedIP, _, err := net.SplitHostPort(expected)
	if err != nil {
		return err
	}

	actualIP, _, err := net.SplitHostPort(actual)
	if err != nil {
		return err
	}

	if expectedIP != actualIP {
		return fmt.Errorf("ip mismatch. Expected %s. Got %s", expectedIP, actualIP)
	}

	return nil
}
