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
	conn   *Conn
	dialer Dialer
}

func (h *socks4Handler) handle() error {
	req := &Socks4Request{}
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
	var lc net.ListenConfig

	listener, err := lc.Listen(context.Background(), "tcp", ":0") // use a free port
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

	if err := checkAllowedBind(req.Addr, conn.RemoteAddr().String()); err != nil {
		_ = conn.Close()

		writeErr := h.conn.Write(&Socks4Response{
			Status: Socks4StatusRejected,
		})
		if writeErr != nil {
			return writeErr
		}

		return err
	}

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
		Version: Socks5Version,
		Method:  method,
	}); err != nil {
		return err
	}

	if method == AuthMethodNoAcceptableMethods {
		return errors.New("no supported authentication mechanism")
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
			Version: Socks5Version,
			Status:  Socks5StatusCMDNotSupported,
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
			Version: Socks5Version,
			Status:  status,
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
		Version: Socks5Version,
		Status:  Socks5StatusGranted,
	}); err != nil {
		return err
	}

	return h.conn.Tunnel(target)
}

func (h *socks5Handler) handleBind(req *Socks5Request) error {
	var lc net.ListenConfig

	listener, err := lc.Listen(context.Background(), "tcp", req.Addr)
	if err != nil {
		return err
	}

	if err = h.conn.Write(&Socks5Response{
		Version: Socks5Version,
		Status:  Socks5StatusGranted,
		Addr:    listener.Addr().String(),
	}); err != nil {
		return err
	}

	conn, err := listener.Accept()
	if err != nil {
		writeErr := h.conn.Write(&Socks5Response{
			Version: Socks5Version,
			Status:  Socks5StatusFailure,
		})
		if writeErr != nil {
			return writeErr
		}

		return err
	}

	_ = listener.Close()

	if err := checkAllowedBind(req.Addr, conn.RemoteAddr().String()); err != nil {
		_ = conn.Close()

		writeErr := h.conn.Write(&Socks5Response{
			Version: Socks5Version,
			Status:  Socks5StatusFailure,
		})
		if writeErr != nil {
			return writeErr
		}

		return err
	}

	if err := h.conn.Write(&Socks5Response{
		Version: Socks5Version,
		Status:  Socks5StatusGranted,
		Addr:    conn.RemoteAddr().String(),
	}); err != nil {
		return err
	}

	return h.conn.Tunnel(conn)
}

func checkAllowedBind(expected, actual string) error {
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
